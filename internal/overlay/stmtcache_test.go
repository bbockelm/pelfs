package overlay

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// openCacheDB is a bare SQLite database for the statement cache to sit
// over. The cache needs nothing of the overlay's schema — every test here
// is about its lifecycle, not about what it queries.
func openCacheDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

// A query that arrives after close must fail, or succeed uncached, but
// never panic — and the window this pins is the one FS.Close opens.
//
// Close drops the statements and THEN closes the pool, so for the instant
// between those two the cache is empty while db.Prepare still works. A
// caller landing there took prep's compile path and assigned into a map
// close had just nilled: "panic: assignment to entry in nil map", which
// is how a background checkpoint's Rebase died when the session tore the
// overlay down underneath it.
//
// Deliberately sequential: the panic needs no race to reproduce, only the
// order below, which is exactly what the concurrent case degenerated to.
func TestStmtCacheSurvivesQueriesThatArriveAfterClose(t *testing.T) {
	db := openCacheDB(t)
	c := newStmtCache(db)

	// Warm one query so the closed cache is exercised on both sides of
	// its hit/miss split: a query it used to know, and one it never did.
	warm, err := c.Query("SELECT 1")
	if err != nil {
		t.Fatalf("query before close: %v", err)
	}
	// Closed, not leaked: the pool holds one connection, and a cursor
	// left open would block every db.Prepare below on it.
	warm.Close() //nolint:errcheck
	c.close()

	// The pool is still open — that is the whole window.
	for _, q := range []string{"SELECT 1", "SELECT 2"} {
		rows, err := c.Query(q)
		if err != nil {
			t.Fatalf("query %q after close: %v", q, err)
		}
		rows.Close() //nolint:errcheck
		if err := c.QueryRow(q).Scan(new(int)); err != nil {
			t.Fatalf("query row %q after close: %v", q, err)
		}
	}
	if _, err := c.Exec("SELECT 1"); err != nil {
		t.Fatalf("exec after close: %v", err)
	}

	// Nothing may be cached again: a statement compiled after close would
	// outlive the pool it was compiled on.
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.m != nil || c.pending != nil || c.uncachable != nil {
		t.Errorf("close was undone by a later query: m=%v pending=%v uncachable=%v",
			c.m, c.pending, c.uncachable)
	}
}

// The same window, reached the way production reached it: two goroutines
// with no ordering between them.
//
// Worth saying what this is NOT. The race detector cannot see this defect
// and never could — every access to the cache's maps is under its own
// mutex, so there is no data race to report, only a call that happens
// after close. The -race lane ran this code for months and stayed silent;
// the panic above is the only evidence it ever produced.
func TestStmtCacheCloseConcurrentWithQueries(t *testing.T) {
	// Several rounds because the window is narrow: close has to land
	// between one caller's db.Prepare and its assignment into the map.
	for round := 0; round < 20; round++ {
		db := openCacheDB(t)
		c := newStmtCache(db)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				rows, err := c.Query("SELECT " + string(rune('1'+i)))
				if err == nil {
					rows.Close() //nolint:errcheck
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c.close()
		}()
		close(start)
		wg.Wait()
	}
}

// Close is not exempt from the serialization every other operation on the
// overlay runs under. It takes the same lock they do, so it cannot pull
// the statement cache and the connection pool out from under a query
// already in flight — which is what a teardown racing a background
// checkpoint's Rebase did.
//
// The FS here is only the two fields Close touches; building a real one
// would need a base generation and prove nothing more.
func TestCloseWaitsForTheOperationInFlight(t *testing.T) {
	db := openCacheDB(t)
	fs := &FS{db: db, q: newStmtCache(db)}

	// Stand in for an operation: every one of them holds this lock from
	// entry to return.
	fs.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- fs.Close() }()

	select {
	case err := <-done:
		t.Fatalf("Close finished while an operation held the overlay lock (err=%v); "+
			"the operation's next query would find the statement cache gone", err)
	case <-time.After(100 * time.Millisecond):
		// Blocked, as it must be. Four orders of magnitude above the
		// microseconds an unsynchronized Close took.
	}

	fs.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("Close: %v", err)
	}
}
