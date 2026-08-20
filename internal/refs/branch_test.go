package refs

// The branch half of the ref store: several names over one volume, and
// what that does to the two pieces of local state this package keeps — the
// volume key pin, which must stay volume-wide, and the per-branch record
// of the last generation accepted, which must stay per-branch.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE ROLLBACK CHECK IS PER-BRANCH, AND IT HAS TO BE.
//
// checkMonotonic refuses a head older than the newest generation this
// client already accepted ON THAT BRANCH. The record is keyed by branch
// name (lastPath) and this pins that, because the failure if it were not
// is silent in the dangerous direction on a volume with siblings: two
// branches advance independently, so dev at generation 2 beside main at
// generation 9 is the ordinary state of a maintenance line — and a
// volume-wide record would read every fetch of dev as a stale read and
// refuse to mount it, while a fetch of main after dev would quietly reset
// the bar that protects main.
func TestTheRollbackCheckIsKeptPerBranch(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	state := t.TempDir()
	s, err := New(inner, state, nil)
	if err != nil {
		t.Fatal(err)
	}

	// main walks to generation 3.
	var prev []byte
	for n := uint64(0); n <= 3; n++ {
		raw := gen(t, n, prev, priv, nil)
		etag := ""
		if n > 0 {
			f, err := s.Fetch(ctx, "main")
			if err != nil {
				t.Fatal(err)
			}
			etag = f.ETag
		}
		if err := s.Flip(ctx, "main", raw, etag); err != nil {
			t.Fatalf("flip main gen %d: %v", n, err)
		}
		if _, err := s.Fetch(ctx, "main"); err != nil {
			t.Fatalf("fetch main gen %d: %v", n, err)
		}
		prev = raw
	}

	// dev is a branch that has only ever reached generation 1 — younger
	// than main by every measure, and perfectly legitimate.
	devGen0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "dev", devGen0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "dev"); err != nil {
		t.Fatalf("a branch at generation 0 beside a branch at generation 3 was refused as a rollback: %v", err)
	}
	devGen1 := gen(t, 1, devGen0, priv, nil)
	f, err := s.Fetch(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flip(ctx, "dev", devGen1, f.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "dev"); err != nil {
		t.Fatalf("dev's own second generation was refused: %v", err)
	}

	// And main's bar was not lowered by any of it: a genuinely stale read
	// of main is still refused.
	if err := s.Flip(ctx, "main", gen(t, 1, nil, priv, nil), ""); err == nil {
		// Flip refuses an existing ref with an empty etag; write it behind
		// the store's back to simulate an origin serving a superseded copy.
		t.Fatal("flip over an existing ref with no etag succeeded")
	}
	f, err = s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flip(ctx, "main", gen(t, 1, nil, priv, nil), f.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrRollback) {
		t.Fatalf("main served generation 1 after this client accepted 3 and it was not refused: %v", err)
	}

	// The state on disk says the same thing: one record per branch.
	for _, b := range []string{"main", "dev"} {
		if _, err := os.Stat(filepath.Join(state, "refs", b+".sb")); err != nil {
			t.Errorf("no per-branch record for %s: %v", b, err)
		}
	}
}

// The pin is the VOLUME's, not the branch's. A per-branch pin would hand
// an attacker a fresh trust-on-first-use for every branch name they can
// invent, which is why pinPath ignores the branch — and why a branch
// created from a verified head is trusted the moment it appears, with no
// second TOFU warning and no second file.
func TestThePinIsVolumeWideAcrossBranches(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	_, evilPriv := genKey(t)
	state := t.TempDir()
	s, err := New(inner, state, nil)
	if err != nil {
		t.Fatal(err)
	}

	g0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", g0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); err != nil { // pins on first use
		t.Fatal(err)
	}

	// A branch created the way `pelfs branch` creates one — the verified
	// head's own bytes under a second name — verifies immediately.
	if err := s.Flip(ctx, "dev", g0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "dev"); err != nil {
		t.Fatalf("a branch created from the pinned head does not verify: %v", err)
	}

	// A branch signed by ANOTHER key does not get its own first-use pin.
	// This is the attack the volume-wide pin exists to refuse: invent a
	// name, sign it yourself, and be trusted under it.
	if err := s.Flip(ctx, "evil", gen(t, 0, nil, evilPriv, nil), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "evil"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a branch signed by an unknown key was accepted under a new name: %v", err)
	}

	// One pin file, named for the volume rather than for any branch.
	entries, err := os.ReadDir(filepath.Join(state, "refs"))
	if err != nil {
		t.Fatal(err)
	}
	pins := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pub" {
			pins++
			if e.Name() != "volume.pub" {
				t.Errorf("per-branch key pin %s; the pin is volume-level by design", e.Name())
			}
		}
	}
	if pins != 1 {
		t.Errorf("%d key pins on disk, want exactly one for the volume", pins)
	}
}

// DELETING A BRANCH FORGETS IT LOCALLY, and that is what makes the name
// reusable.
//
// The per-branch record is the rollback check's whole memory. Once the ref
// is gone the statement "this client has accepted generation N on dev" is
// about nothing — and leaving it behind sets a trap, because re-creating
// dev at an OLDER generation is the ordinary result of branching from a
// tag, and the client that deleted it would be the one client that could
// not then read it.
func TestDeletingABranchLetsTheNameBeReusedFromThePast(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	state := t.TempDir()
	s, err := New(inner, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	g0 := gen(t, 0, nil, priv, nil)
	g1 := gen(t, 1, g0, priv, nil)
	g2 := gen(t, 2, g1, priv, nil)

	if err := s.Flip(ctx, "main", g0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	// dev reaches generation 2 and this client watches it get there.
	if err := s.Flip(ctx, "dev", g2, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.lastPath("dev")); err != nil {
		t.Fatalf("fetching dev recorded nothing: %v", err)
	}

	if err := s.DeleteBranch(ctx, "dev"); err != nil {
		t.Fatalf("DeleteBranch: %v", err)
	}
	if _, err := os.Stat(s.lastPath("dev")); !os.IsNotExist(err) {
		t.Fatal("deleting a branch left this client's record of it behind; re-creating the name from an " +
			"older generation would then be refused as a stale read")
	}
	// The volume pin is NOT forgotten: a deleted branch says nothing about
	// the volume's identity, and dropping the pin would mean the next fetch
	// silently trusted whatever it was served.
	if pinned, err := s.readPin(); err != nil || pinned == nil {
		t.Fatalf("deleting a branch dropped the volume key pin (%v)", err)
	}

	// The name is free, and free from the PAST: dev comes back at
	// generation 1, below where it was.
	if err := s.Flip(ctx, "dev", g1, ""); err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "dev")
	if err != nil {
		t.Fatalf("a re-created branch at an older generation was refused: %v", err)
	}
	if f.Superblock.Generation != 1 {
		t.Fatalf("re-created dev is at generation %d, want 1", f.Superblock.Generation)
	}
}

// Deleting a branch that is not there is a typo, not a no-op: the store's
// Delete treats a missing key as success, so absence has to be established
// before the removal rather than inferred from it.
func TestDeleteBranchNamesAnAbsentBranch(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBranch(ctx, "never-existed"); !errors.Is(err, ErrNoSuchBranch) {
		t.Fatalf("deleting an absent branch reported %v, want ErrNoSuchBranch", err)
	}
	// And the name rules apply here too, so a caller cannot delete "..".
	if err := s.DeleteBranch(ctx, ".."); err == nil {
		t.Fatal("DeleteBranch accepted a name that is not a ref")
	}
}

// ListBranches is what the sweep's root set and the last-branch refusal
// both count, so it has to apply the same two exclusions every ref listing
// applies: a ".tmp" name is a partial write and a directory is not a ref.
// Counting either would let `pelfs branch --rm` delete a volume's last real
// branch while believing there was another.
func TestListBranchesSkipsWhatNoReaderCanFetch(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// An empty prefix has no refs directory at all, and that is an empty
	// listing rather than a failure.
	names, err := s.ListBranches(ctx)
	if err != nil || len(names) != 0 {
		t.Fatalf("ListBranches on an empty prefix: %v, %v", names, err)
	}

	g0 := gen(t, 0, nil, priv, nil)
	for _, b := range []string{"main", "dev"} {
		if err := s.Flip(ctx, b, g0, ""); err != nil {
			t.Fatal(err)
		}
	}
	// A partial write, as an interrupted upload leaves one.
	if err := s.inner.Put(ctx, RefDirKey+"/half.tmp", strings.NewReader(string(g0))); err != nil {
		t.Fatal(err)
	}
	names, err = s.ListBranches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "dev" || names[1] != "main" {
		t.Fatalf("ListBranches returned %v, want [dev main] — sorted, and without the .tmp partial", names)
	}
}
