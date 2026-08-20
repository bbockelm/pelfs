package overlay

import (
	"database/sql"
	"sync"
)

// stmtCache is a querier that compiles each SQL string once.
//
// Profiling the write path found the same defect the catalog reader had:
// database/sql re-prepares — re-PARSES — a statement on every Query call
// with arguments, so IsDirty alone cost 24 us, more than a whole Lookup,
// while being the most frequently called operation in the FUSE TTL path.
// The querier interface is exactly QueryRow/Query/Exec, so a caching
// implementation slips underneath every read path without touching a
// single call site.
//
// Transactions share the cache through txStmts (below), which is what
// makes an untar — whose every mutation runs inside one — benefit too.
type stmtCache struct {
	db *sql.DB

	mu sync.RWMutex
	m  map[string]*sql.Stmt
	// pending holds queries first seen INSIDE a transaction, which could
	// not be compiled there (see lookup). withTx drains it before the
	// next Begin, so a query is uncached at most once per session.
	pending map[string]struct{}
	// uncachable remembers queries db.Prepare refused, so a query that
	// cannot be compiled costs one failed attempt rather than one per
	// transaction forever.
	uncachable map[string]struct{}
	// closed is set by close and never cleared. It is the reason the maps
	// above may be nil, and every method below consults it FIRST.
	//
	// A closed cache still gets called. FS.Close drops the statements and
	// THEN closes the pool, so for the instant between those two the maps
	// are gone while db.Prepare still works — and a caller landing there
	// used to take prep's compile path and assign into a map close had
	// just nilled. That is "assignment to entry in nil map", and it is how
	// a background checkpoint's Rebase died when the session tore the
	// overlay down underneath it. Nothing about it is a data race: every
	// access here is already under mu, which is exactly why the race
	// detector never named it.
	//
	// Closed means one thing everywhere: compile nothing, remember
	// nothing, and let the caller fall back to the pool — which reports
	// "sql: database is closed" once the pool is gone. An error, never a
	// panic.
	closed bool
}

func newStmtCache(db *sql.DB) *stmtCache {
	return &stmtCache{
		db:         db,
		m:          make(map[string]*sql.Stmt),
		pending:    make(map[string]struct{}),
		uncachable: make(map[string]struct{}),
	}
}

// prep returns the compiled statement for query, compiling it on first
// use. A preparation failure returns nil and the caller falls back to the
// uncached path, so a cache problem can never turn into a query failure.
//
// It must not be called while a transaction is open: preparing needs a
// connection, the pool holds exactly one, and the transaction owns it —
// db.Prepare would block on a connection that only the caller can
// release. Transactional callers use lookup instead.
func (c *stmtCache) prep(query string) *sql.Stmt {
	c.mu.RLock()
	st, ok := c.m[query]
	closed := c.closed
	c.mu.RUnlock()
	if ok {
		return st
	}
	if closed {
		return nil
	}
	st, err := c.db.Prepare(query)
	if err != nil {
		c.mu.Lock()
		if !c.closed {
			c.uncachable[query] = struct{}{}
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Lock()
	if existing, raced := c.m[query]; raced {
		c.mu.Unlock()
		st.Close() //nolint:errcheck
		return existing
	}
	if c.closed {
		// close ran while this was compiling. The statement belongs to
		// nobody now — the cache will never be read again and the pool is
		// on its way out — so it is released here rather than handed to a
		// caller who would execute it against a closing connection.
		c.mu.Unlock()
		st.Close() //nolint:errcheck
		return nil
	}
	c.m[query] = st
	delete(c.pending, query)
	c.mu.Unlock()
	return st
}

// lookup returns an already-compiled statement, or nil without compiling
// one. A miss is recorded for warm to compile later, outside any
// transaction.
func (c *stmtCache) lookup(query string) *sql.Stmt {
	c.mu.RLock()
	st, ok := c.m[query]
	_, bad := c.uncachable[query]
	closed := c.closed
	c.mu.RUnlock()
	if ok || bad || closed {
		return st
	}
	c.mu.Lock()
	if !c.closed {
		c.pending[query] = struct{}{}
	}
	c.mu.Unlock()
	return nil
}

// warm compiles the queries lookup could not. The caller must hold no
// open transaction (see prep).
func (c *stmtCache) warm() {
	c.mu.RLock()
	n := len(c.pending)
	closed := c.closed
	c.mu.RUnlock()
	if n == 0 || closed {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	queries := make([]string, 0, len(c.pending))
	for q := range c.pending {
		queries = append(queries, q)
	}
	c.pending = make(map[string]struct{})
	c.mu.Unlock()
	for _, q := range queries {
		c.prep(q)
	}
}

func (c *stmtCache) QueryRow(query string, args ...any) *sql.Row {
	if st := c.prep(query); st != nil {
		return st.QueryRow(args...)
	}
	return c.db.QueryRow(query, args...)
}

func (c *stmtCache) Query(query string, args ...any) (*sql.Rows, error) {
	if st := c.prep(query); st != nil {
		return st.Query(args...)
	}
	return c.db.Query(query, args...)
}

func (c *stmtCache) Exec(query string, args ...any) (sql.Result, error) {
	if st := c.prep(query); st != nil {
		return st.Exec(args...)
	}
	return c.db.Exec(query, args...)
}

// close releases every compiled statement. Calls that arrive afterwards
// are answered uncached (see closed); it is idempotent.
func (c *stmtCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, st := range c.m {
		st.Close() //nolint:errcheck
	}
	c.m = nil
	c.pending = nil
	c.uncachable = nil
}

// txStmts is the querier withTx hands to write paths: the transaction,
// with the same compile-once treatment the read paths get.
//
// Every mutation the overlay performs runs inside a transaction, so
// before this existed the cache above covered only reads and an untar
// paid a full SQL parse per INSERT — Tx.Exec and Tx.QueryRow together
// were 37% of mount CPU, roughly two thirds of that in the parser.
//
// tx.Stmt is what makes it legal: database/sql looks the statement up by
// connection and reuses the driver handle when the transaction is on the
// same connection, which it always is here — the pool is opened with
// MaxOpenConns(1). Nothing about the transaction changes: same BEGIN,
// same COMMIT, same durability.
type txStmts struct {
	tx *sql.Tx
	c  *stmtCache
	// m memoizes this transaction's handles. tx.Stmt allocates a wrapper
	// per call and the transaction pins every one until commit, which a
	// loop over thousands of inodes (Rebase) would otherwise turn into
	// thousands of live wrappers. No lock: a transaction belongs to one
	// operation, and operations are serialized by FS.mu.
	m map[string]*sql.Stmt
}

func newTxStmts(tx *sql.Tx, c *stmtCache) *txStmts {
	return &txStmts{tx: tx, c: c}
}

// stmt returns the transaction's handle on the cached statement, or nil
// when the query is not compiled yet (its first execution this session
// runs uncached, and warm compiles it before the next transaction).
func (t *txStmts) stmt(query string) *sql.Stmt {
	if st, ok := t.m[query]; ok {
		return st
	}
	pooled := t.c.lookup(query)
	if pooled == nil {
		return nil
	}
	st := t.tx.Stmt(pooled)
	if t.m == nil {
		t.m = make(map[string]*sql.Stmt, 8)
	}
	t.m[query] = st
	return st
}

func (t *txStmts) QueryRow(query string, args ...any) *sql.Row {
	if st := t.stmt(query); st != nil {
		return st.QueryRow(args...)
	}
	return t.tx.QueryRow(query, args...)
}

// Query is deliberately NOT cached. A cached statement is one driver
// handle with one compiled sqlite3_stmt behind it, and Query hands the
// caller a cursor it keeps open: two overlapping reads of the same query
// would step on each other's cursor, where today each gets its own
// statement. QueryRow is safe because Scan closes before returning, and
// no write path streams rows inside its transaction anyway.
func (t *txStmts) Query(query string, args ...any) (*sql.Rows, error) {
	return t.tx.Query(query, args...)
}

func (t *txStmts) Exec(query string, args ...any) (sql.Result, error) {
	if st := t.stmt(query); st != nil {
		return st.Exec(args...)
	}
	return t.tx.Exec(query, args...)
}
