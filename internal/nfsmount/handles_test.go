package nfsmount

import (
	"testing"

	"github.com/go-git/go-billy/v5/memfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

func newTestHandles(limit int) *handles {
	return newHandles(nfshelper.NewNullAuthHandler(memfs.New()), limit)
}

func TestHandlesRoundTrip(t *testing.T) {
	tbl := newTestHandles(16)
	f := memfs.New()
	p := []string{"a", "b", "c.txt"}
	h := tbl.ToHandle(f, p)

	gotFS, gotPath, err := tbl.FromHandle(h)
	if err != nil {
		t.Fatalf("FromHandle: %v", err)
	}
	if gotFS != f {
		t.Fatalf("FromHandle returned a different filesystem")
	}
	if len(gotPath) != len(p) {
		t.Fatalf("path %v, want %v", gotPath, p)
	}
	for i := range p {
		if gotPath[i] != p[i] {
			t.Fatalf("path %v, want %v", gotPath, p)
		}
	}
	// The returned slice must be the caller's to append to: go-nfs's CREATE
	// handler does exactly that to name the new child.
	gotPath[0] = "mutated"
	_, again, _ := tbl.FromHandle(h)
	if again[0] != "a" {
		t.Fatalf("FromHandle handed out its own slice: %v", again)
	}
}

func TestHandlesStableForSamePath(t *testing.T) {
	tbl := newTestHandles(16)
	f := memfs.New()
	first := tbl.ToHandle(f, []string{"a", "b"})
	second := tbl.ToHandle(f, []string{"a", "b"})
	if string(first) != string(second) {
		t.Fatalf("the same path minted two handles: %x vs %x", first, second)
	}
}

func TestHandlesRejectsForeignAndMalformed(t *testing.T) {
	tbl := newTestHandles(16)
	other := newTestHandles(16)
	f := memfs.New()

	// A handle from a different server instance must be stale, not a
	// silent alias for whatever now holds that counter.
	other.ToHandle(f, []string{"elsewhere"})
	foreign := other.ToHandle(f, []string{"elsewhere", "deep"})
	if _, _, err := tbl.FromHandle(foreign); err == nil {
		t.Fatal("a handle from another server resolved")
	}
	if _, _, err := tbl.FromHandle([]byte{1, 2, 3}); err == nil {
		t.Fatal("a malformed handle resolved")
	}
	if _, _, err := tbl.FromHandle(nil); err == nil {
		t.Fatal("an empty handle resolved")
	}
}

func TestHandlesInvalidate(t *testing.T) {
	tbl := newTestHandles(16)
	f := memfs.New()
	h := tbl.ToHandle(f, []string{"gone.txt"})
	if err := tbl.InvalidateHandle(f, h); err != nil {
		t.Fatalf("InvalidateHandle: %v", err)
	}
	if _, _, err := tbl.FromHandle(h); err == nil {
		t.Fatal("an invalidated handle still resolved")
	}
	// A later handle for the same path is a fresh, working one.
	if _, _, err := tbl.FromHandle(tbl.ToHandle(f, []string{"gone.txt"})); err != nil {
		t.Fatalf("re-minted handle: %v", err)
	}
}

// Ancestors of a handle in active use must not be evicted underneath it:
// a client holding a directory handle would start getting ESTALE for a
// tree it never stopped using.
func TestHandlesKeepAncestorsResident(t *testing.T) {
	const limit = 8
	tbl := newTestHandles(limit)
	f := memfs.New()

	dir := tbl.ToHandle(f, []string{"keep"})
	leaf := tbl.ToHandle(f, []string{"keep", "leaf"})

	// Churn well past the limit through unrelated paths, touching the leaf
	// (and thereby its ancestry) between each.
	for i := 0; i < limit*4; i++ {
		tbl.ToHandle(f, []string{"churn", string(rune('a' + i%26)), string(rune('0' + i%10))})
		if _, _, err := tbl.FromHandle(leaf); err != nil {
			t.Fatalf("leaf went stale at %d: %v", i, err)
		}
	}
	if _, _, err := tbl.FromHandle(dir); err != nil {
		t.Fatalf("the ancestor of an in-use handle was evicted: %v", err)
	}
}

func TestHandlesBoundedByLimit(t *testing.T) {
	const limit = 4
	tbl := newTestHandles(limit)
	f := memfs.New()
	for i := 0; i < 100; i++ {
		tbl.ToHandle(f, []string{"f", string(rune('a' + i%26)), string(rune('0' + i/26))})
	}
	tbl.mu.Lock()
	n, ids, paths := tbl.order.Len(), len(tbl.byID), len(tbl.byPath)
	tbl.mu.Unlock()
	if n > limit || ids > limit || paths > limit {
		t.Fatalf("table grew past the limit: order=%d byID=%d byPath=%d limit=%d", n, ids, paths, limit)
	}
}

func TestHandlesVerifierRoundTrip(t *testing.T) {
	tbl := newTestHandles(16)
	f := memfs.New()
	if err := f.MkdirAll("/d", 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		fh, err := f.Create("/d/" + name)
		if err != nil {
			t.Fatal(err)
		}
		fh.Close() //nolint:errcheck
	}
	contents, err := f.ReadDir("/d")
	if err != nil {
		t.Fatal(err)
	}
	v := tbl.VerifierFor("/d", contents)
	got := tbl.DataForVerifier("/d", v)
	if len(got) != len(contents) {
		t.Fatalf("verifier returned %d entries, want %d", len(got), len(contents))
	}
	if tbl.DataForVerifier("/d", v+1) != nil {
		t.Fatal("an unknown verifier returned data")
	}
}
