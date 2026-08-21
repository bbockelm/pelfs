package nfsmount

import (
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	nfs "github.com/willscott/go-nfs"
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

// A verifier retains a whole directory listing, so the cache has to be
// bounded by the entries it holds and not only by how many listings it
// holds — otherwise a handful of large directories pin an unbounded
// amount for the life of the mount.
func TestVerifiersBoundedByEntries(t *testing.T) {
	tbl := newTestHandles(1 << 20)
	big := make([]fs.FileInfo, 8192)
	for i := range big {
		big[i] = dummyInfo(fmt.Sprintf("f%06d", i))
	}
	for i := 0; i < 200; i++ {
		tbl.VerifierFor(fmt.Sprintf("/d%d", i), big)
	}
	tbl.mu.Lock()
	entries, listings := tbl.verifyEntries, len(tbl.verifiers)
	tbl.mu.Unlock()
	// 200 listings of 8192 is 1.6M entries; the budget must have capped it.
	if entries > verifyEntryLimit+len(big) {
		t.Fatalf("verifier cache holds %d entries, budget %d", entries, verifyEntryLimit)
	}
	if listings > verifyLimit {
		t.Fatalf("verifier cache holds %d listings, limit %d", listings, verifyLimit)
	}
	// The most recent listing must survive: the caller is about to serve it.
	if entries < len(big) {
		t.Fatalf("the listing just cached was evicted (%d entries held)", entries)
	}
}

// A directory larger than the whole budget must still be listable.
func TestVerifierLargerThanBudgetSurvives(t *testing.T) {
	tbl := newTestHandles(16)
	huge := make([]fs.FileInfo, verifyEntryLimit*2)
	for i := range huge {
		huge[i] = dummyInfo("f")
	}
	v := tbl.VerifierFor("/huge", huge)
	if got := tbl.DataForVerifier("/huge", v); len(got) != len(huge) {
		t.Fatalf("oversized listing returned %d entries, want %d", len(got), len(huge))
	}
}

// READDIR cookies in go-nfs are POSITIONAL: an entry's cookie is its index
// in the listing the server read, plus two for "." and "..". On its own
// that is the classic skip-under-mutation bug — unlink an entry between
// two pages and every later entry shifts down one, so the client resumes
// past entries it was never shown, `rm -rf` finishes early, and the rmdir
// behind it reports the directory non-empty.
//
// What makes it safe here is that the positions index a SNAPSHOT rather
// than the live directory: the verifier names a listing, this table
// retains it, and go-nfs serves every continuation from the retained one
// (getDirListingWithVerifier consults DataForVerifier before it re-reads).
// Two properties carry that, and both are asserted below.
//
// The scheme is contingent on this type satisfying the interface go-nfs
// type-asserts for. If it ever stops, nothing fails to build and no test
// fails — go-nfs silently falls back to re-reading the directory for every
// page, and the positional cookies above become the skipping bug for real.
// Hence the assertion.
var _ nfs.CachingHandler = (*handles)(nil)

// A retained listing must not move when the directory does. This is the
// property that stops an unlink between two pages from shifting the
// entries the client has not been shown yet.
func TestVerifierPinsTheListingAgainstMutation(t *testing.T) {
	tbl := newTestHandles(16)
	first := []fs.FileInfo{dummyInfo("a"), dummyInfo("b"), dummyInfo("c"), dummyInfo("d")}
	v := tbl.VerifierFor("/d", first)

	// The directory loses an entry mid-scan, as an `rm -rf` makes it do
	// thousands of times.
	after := []fs.FileInfo{dummyInfo("a"), dummyInfo("c"), dummyInfo("d")}
	tbl.VerifierFor("/d", after)

	got := tbl.DataForVerifier("/d", v)
	if len(got) != len(first) {
		t.Fatalf("the pinned listing changed under the scan: %d entries, want %d", len(got), len(first))
	}
	for i := range first {
		if got[i].Name() != first[i].Name() {
			t.Fatalf("entry %d of the pinned listing is %q, want %q", i, got[i].Name(), first[i].Name())
		}
	}
}

// And when the pin is NOT available — evicted, or a client resuming
// against a server that has forgotten it — the verifier the server
// recomputes must DIFFER, so go-nfs answers NFS3ERR_BAD_COOKIE and the
// client restarts the scan (RFC 1813 3.3.16). A verifier that did not
// track content would leave the client resuming into a list that had
// moved, which is the same skip by another route.
func TestVerifierChangesWhenTheDirectoryChanges(t *testing.T) {
	tbl := newTestHandles(16)
	before := []fs.FileInfo{dummyInfo("a"), dummyInfo("b"), dummyInfo("c")}
	v := tbl.VerifierFor("/d", before)

	for _, c := range []struct {
		what     string
		contents []fs.FileInfo
	}{
		{"an entry removed", []fs.FileInfo{dummyInfo("a"), dummyInfo("c")}},
		{"an entry added", []fs.FileInfo{dummyInfo("a"), dummyInfo("b"), dummyInfo("c"), dummyInfo("d")}},
		{"an entry renamed", []fs.FileInfo{dummyInfo("a"), dummyInfo("b"), dummyInfo("z")}},
	} {
		if got := tbl.VerifierFor("/d", c.contents); got == v {
			t.Errorf("%s: verifier is unchanged (%d), so a resuming client would never restart", c.what, got)
		}
	}
	// The same directory, unchanged, must keep its verifier: a client
	// resuming a scan of a quiet directory must not be forced to restart.
	if got := tbl.VerifierFor("/d", before); got != v {
		t.Errorf("an unchanged directory changed verifier: %d, want %d", got, v)
	}
	// Different directories with identical entries are distinguishable,
	// which is what keeps one scan's pin from serving another's.
	if got := tbl.VerifierFor("/other", before); got == v {
		t.Error("two directories with the same entries share a verifier")
	}
}

type dummyInfo string

func (d dummyInfo) Name() string       { return string(d) }
func (d dummyInfo) Size() int64        { return 0 }
func (d dummyInfo) Mode() fs.FileMode  { return 0644 }
func (d dummyInfo) ModTime() time.Time { return time.Time{} }
func (d dummyInfo) IsDir() bool        { return false }
func (d dummyInfo) Sys() any           { return nil }
