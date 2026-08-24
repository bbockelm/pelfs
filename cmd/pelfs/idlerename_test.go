package main

import (
	"testing"
	"time"
)

// A session whose only change is a RENAME must idle-seal like any other.
//
// It did not. The trigger read staged bytes and dirty inodes, and a rename
// moves neither — so `staged == 0 && nodes == 0` decided there was nothing
// to publish, and the change sat in the overlay until the interval tick or
// the seal at exit found it (both of which have always tested DirtyEdges).
// A user who renamed a file and closed the tab got no seal at all from
// this path.
//
// The second half of the same fact is that a rename must also RESET the
// quiet window: it is a write, and sealing while somebody is still moving
// files around is the thing the window exists to prevent.
func TestIdleSealFiresForARenameThatMovedNoBytes(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	// Nothing staged and nothing dirty — the state right after a
	// checkpoint, which is where a rename actually lands.
	f.mu.Lock()
	f.staged, f.nodes, f.edges = 0, 0, 0
	f.mu.Unlock()

	ch := f.attach()
	f.step()
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap + time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed a session with nothing in it (%d seals)", f.sealCount())
	}

	f.rename()
	// The rename is a write, so the window restarts from here: a seal
	// before it is up would publish under somebody's hands.
	f.step()
	f.clk.advance(idleQuietWindowCap - time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("a rename did not restart the quiet window: sealed %v after it (%d seals)",
			idleQuietWindowCap-time.Second, f.sealCount())
	}
	f.clk.advance(time.Second)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("a rename-only session did not idle-seal after the %v window (%d seals); "+
			"the trigger counts bytes and inodes, and a rename moves neither",
			idleQuietWindowCap, f.sealCount())
	}
}
