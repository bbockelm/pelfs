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
// Only non-transactional reads use this. Statements belong to a
// connection, and a *sql.Tx holds its own; write paths keep passing the
// raw transaction, where the commit dominates anyway.
type stmtCache struct {
	db *sql.DB

	mu sync.RWMutex
	m  map[string]*sql.Stmt
}

func newStmtCache(db *sql.DB) *stmtCache {
	return &stmtCache{db: db, m: make(map[string]*sql.Stmt)}
}

// prep returns the compiled statement for query, compiling it on first
// use. A preparation failure returns nil and the caller falls back to the
// uncached path, so a cache problem can never turn into a query failure.
func (c *stmtCache) prep(query string) *sql.Stmt {
	c.mu.RLock()
	st, ok := c.m[query]
	c.mu.RUnlock()
	if ok {
		return st
	}
	st, err := c.db.Prepare(query)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	if existing, raced := c.m[query]; raced {
		c.mu.Unlock()
		st.Close() //nolint:errcheck
		return existing
	}
	c.m[query] = st
	c.mu.Unlock()
	return st
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

func (c *stmtCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.m {
		st.Close() //nolint:errcheck
	}
	c.m = nil
}
