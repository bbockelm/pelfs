package webapi_test

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/webapi"
)

// One directory per navigation, in the shape the component takes: a flat list
// of full paths, folders marked lazy, files carrying a size.
func TestListingShape(t *testing.T) {
	f := newFix(t)
	d0 := f.dir(rootIno, "dir-0")
	f.dir(d0, "dir-1")
	f.text(d0, "file-0.txt", "hello")
	f.text(rootIno, "top.txt", "top")

	for _, tc := range []struct {
		name string
		dir  string
		want []webapi.Entry
	}{
		{
			name: "the root, which is what GET /files with no id means",
			dir:  "/",
			want: []webapi.Entry{
				{ID: "/dir-0", Type: webapi.TypeFolder, Lazy: true},
				{ID: "/top.txt", Type: webapi.TypeFile, Size: 3},
			},
		},
		{
			name: "one directory, reached by its percent-encoded id",
			dir:  "/dir-0",
			want: []webapi.Entry{
				{ID: "/dir-0/dir-1", Type: webapi.TypeFolder, Lazy: true},
				{ID: "/dir-0/file-0.txt", Type: webapi.TypeFile, Size: 5},
			},
		},
		{
			name: "an empty directory is [] and not null",
			dir:  "/dir-0/dir-1",
			want: []webapi.Entry{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := f.list(tc.dir).entries()
			if len(got) != len(tc.want) {
				t.Fatalf("%s listed %d entries, want %d: %+v", tc.dir, len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				g := got[i]
				if g.ID != w.ID || g.Type != w.Type || g.Size != w.Size || g.Lazy != w.Lazy {
					t.Errorf("entry %d = %+v, want id=%s type=%s size=%d lazy=%v",
						i, g, w.ID, w.Type, w.Size, w.Lazy)
				}
				// Every entry carries a parseable date, because the
				// component feeds it to new Date().
				if g.Date == "" {
					t.Errorf("entry %d (%s) carries no date", i, g.ID)
				}
			}
		})
	}
}

// A FOLDER MUST BE MARKED LAZY or the tree never loads: the store emits
// `request-data` only for a folder marked lazy, and a folder sent without it
// is one the component believes it already has (empty). This is the single
// field whose absence would make the whole file manager look like an empty
// volume, so it gets its own test.
func TestEveryFolderIsMarkedLazy(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "a")
	f.dir(rootIno, "b")
	f.text(rootIno, "c.txt", "x")
	for _, e := range f.list("/").entries() {
		if e.Type == webapi.TypeFolder && !e.Lazy {
			t.Errorf("%s is a folder and is not lazy; the component will never ask for its contents", e.ID)
		}
		if e.Type == webapi.TypeFile && e.Lazy {
			t.Errorf("%s is a file and is marked lazy", e.ID)
		}
	}
}

// The id is a full path percent-encoded into ONE segment, and PathValue is
// the only correct way to read it back — r.URL.Path has already collapsed the
// %2F. The last row is the case a handler that decoded twice would get wrong:
// a filename that CONTAINS the three characters "%2F".
func TestPercentEncodedIDs(t *testing.T) {
	f := newFix(t)
	d0 := f.dir(rootIno, "dir-0")
	d1 := f.dir(d0, "dir-1")
	f.text(d1, "deep.txt", "deep")
	// A name with a literal percent-escape in it. It is not a separator and
	// must not become one.
	weird := f.dir(rootIno, "a%2Fb")
	f.text(weird, "inside.txt", "inside")
	f.text(rootIno, "lit%2Fname.txt", "literal")

	for _, tc := range []struct {
		dir  string
		want string
	}{
		{"/dir-0", "/dir-0/dir-1"},
		{"/dir-0/dir-1", "/dir-0/dir-1/deep.txt"},
		{"/a%2Fb", "/a%2Fb/inside.txt"},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			got := f.list(tc.dir).ids()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("listing %s gave %v, want [%s]", tc.dir, got, tc.want)
			}
		})
	}

	// And the literal name survives a round trip through a listing: the id
	// the component gets back is what it must send to rename it.
	var found string
	for _, e := range f.list("/").entries() {
		if strings.Contains(e.ID, "%2F") && e.Type == webapi.TypeFile {
			found = e.ID
		}
	}
	if found != "/lit%2Fname.txt" {
		t.Fatalf("the root listing reported the literal-%%2F file as %q, want %q", found, "/lit%2Fname.txt")
	}
	// Renaming it proves the id round-trips: escape it as the component
	// would, and the handler must see the name it always had.
	r := f.do(http.MethodPut, "/api/v1/files/"+id(found),
		jsonBody(t, map[string]string{"operation": "rename", "name": "plain.txt"}))
	if got := r.result().ID; got != "/plain.txt" {
		t.Fatalf("renaming %s produced id %q, want /plain.txt (body %s)", found, got, r.Body)
	}
	if f.exists("/lit%2Fname.txt") {
		t.Error("the original name is still there, so the rename hit some other path")
	}
}

// The cap, and the true count beside it. A capped listing is deterministic
// (the first N in name order) so that "narrow the path" is actionable, and it
// reports the numbers a UI needs to say what it is showing.
func TestListingCapAndTrueCount(t *testing.T) {
	const total = 25
	f := newFixCap(t, 10)
	d := f.dir(rootIno, "big")
	for i := 0; i < total; i++ {
		f.text(d, fmt.Sprintf("f%02d.txt", i), "x")
	}

	r := f.list("/big")
	ents := r.entries()
	if len(ents) != 10 {
		t.Fatalf("a capped listing returned %d entries, want 10", len(ents))
	}
	// Deterministic: the first ten in name order.
	for i, e := range ents {
		want := fmt.Sprintf("/big/f%02d.txt", i)
		if e.ID != want {
			t.Fatalf("capped entry %d is %s, want %s (the cap must take the first N in name order)", i, e.ID, want)
		}
	}
	for _, tc := range []struct{ header, want string }{
		{webapi.HeaderReturned, "10"},
		{webapi.HeaderTotal, strconv.Itoa(total)},
		{webapi.HeaderCap, "10"},
		{webapi.HeaderTruncated, "true"},
		{webapi.HeaderHidden, "0"},
	} {
		if got := r.Hdr.Get(tc.header); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}

	// And the same truth as JSON, with the sentence to show for it, because
	// the listing has to be a bare array and the provider hands the parsed
	// body to the store without the headers.
	in := f.get("/api/v1/info/" + id("/big")).info()
	if in.Entries != total || in.Returned != 10 || in.Cap != 10 || !in.Truncated {
		t.Fatalf("info = %+v, want 25 entries, 10 returned, cap 10, truncated", in)
	}
	if in.Mode != "read-write" {
		t.Errorf("info mode = %q, want read-write", in.Mode)
	}
	// The notice has to say BOTH things: how much is shown, and that the
	// search box is therefore searching only that much.
	for _, must := range []string{"10 of 25", "Search matches only what is loaded", "WebDAV"} {
		if !strings.Contains(in.Notice, must) {
			t.Errorf("the partial-search notice does not mention %q:\n%s", must, in.Notice)
		}
	}
	if in.Notice != webapi.PartialSearchNotice(10, total) {
		t.Errorf("the notice is not PartialSearchNotice's own words, so two surfaces can disagree:\n%s", in.Notice)
	}

	// An uncapped directory says nothing, because there is nothing to warn
	// about.
	small := f.get("/api/v1/info/" + id("/")).info()
	if small.Truncated || small.Notice != "" {
		t.Errorf("an uncapped listing carried a truncation notice: %+v", small)
	}
	if got := f.list("/").Hdr.Get(webapi.HeaderTruncated); got != "false" {
		t.Errorf("%s = %q for an uncapped listing, want false", webapi.HeaderTruncated, got)
	}
}

// The sentence itself, because it is the one piece of prose this package owes
// a user and a paraphrase of it would be a different claim.
func TestPartialSearchNoticeWording(t *testing.T) {
	got := webapi.PartialSearchNotice(5000, 412006)
	want := "Showing 5,000 of 412,006 entries in this folder. " +
		"Search matches only what is loaded, so it is searching these 5,000 rows and not the whole folder — " +
		"narrow the path, or use the WebDAV endpoint to see all of it."
	if got != want {
		t.Errorf("the partial-search sentence changed.\ngot:  %s\nwant: %s", got, want)
	}
}

// A directory listing must not lie about symlinks, and it must not lie by
// omission either: the policy is internal/vfsdav's, exactly, and what is
// hidden is counted and reported.
func TestSymlinkPolicyAndHiddenCounts(t *testing.T) {
	f := newFix(t)
	d := f.dir(rootIno, "links")
	f.text(d, "real.txt", "twelve bytes")
	f.dir(d, "realdir")
	f.symlink(d, "to-file", "real.txt")   // followed, presented as a file
	f.symlink(d, "to-dir", "realdir")     // hidden and counted
	f.symlink(d, "broken", "nowhere.txt") // hidden and counted
	f.fifo(d, "pipe")                     // hidden and counted

	before := f.api.Counts()
	r := f.list("/links")
	after := f.api.Counts()
	ents := r.entries()
	got := map[string]webapi.Entry{}
	for _, e := range ents {
		got[e.ID] = e
	}
	if len(ents) != 3 {
		t.Fatalf("the listing has %d entries, want 3 (real.txt, realdir, to-file): %+v", len(ents), ents)
	}
	link, okk := got["/links/to-file"]
	if !okk {
		t.Fatal("a symlink to a regular file was not listed; it must be followed and shown as that file")
	}
	if link.Type != webapi.TypeFile {
		t.Errorf("the followed link is type %q, want %q", link.Type, webapi.TypeFile)
	}
	if link.Size != int64(len("twelve bytes")) {
		t.Errorf("the followed link reports size %d, want the TARGET's %d", link.Size, len("twelve bytes"))
	}
	for _, gone := range []string{"/links/to-dir", "/links/broken", "/links/pipe"} {
		if _, there := got[gone]; there {
			t.Errorf("%s is in the listing; it must be hidden", gone)
		}
	}
	if h := r.Hdr.Get(webapi.HeaderHidden); h != "3" {
		t.Errorf("%s = %q, want 3", webapi.HeaderHidden, h)
	}

	in := f.get("/api/v1/info/" + id("/links")).info()
	want := webapi.Counts{DanglingSymlinks: 1, DirectorySymlinks: 1, SpecialFiles: 1}
	if in.Hidden != want {
		t.Errorf("hidden counts = %+v, want %+v", in.Hidden, want)
	}
	for _, must := range []string{"3 entries are not shown", "symbolic link to a directory", "broken symbolic link", "special file"} {
		if !strings.Contains(in.HiddenNotice, must) {
			t.Errorf("the hidden-entry notice does not mention %q:\n%s", must, in.HiddenNotice)
		}
	}
	// And the cumulative counter moved by the same amounts, so a status line
	// can report either surface's hiding with one number. It counts
	// OCCURRENCES rather than distinct entries — the same deliberate choice
	// internal/vfsdav makes, because remembering every path ever listed is a
	// leak on a volume of millions — so this is a delta and not a total.
	moved := webapi.Counts{
		DanglingSymlinks:  after.DanglingSymlinks - before.DanglingSymlinks,
		DirectorySymlinks: after.DirectorySymlinks - before.DirectorySymlinks,
		SpecialFiles:      after.SpecialFiles - before.SpecialFiles,
	}
	if moved != want {
		t.Errorf("API.Counts() moved by %+v for one listing, want %+v", moved, want)
	}
}

// THE TWO-REQUESTS-PER-NAVIGATION GUARD. The store fires `request-data` twice
// for one navigation, so two identical listings arrive together; on a
// 100k-entry directory that is two full readdirs of the largest thing in the
// volume. One readdir must answer both.
func TestConcurrentIdenticalListingsCostOneReadDir(t *testing.T) {
	f := newFix(t)
	d := f.dir(rootIno, "dir-0")
	for i := 0; i < 50; i++ {
		f.text(d, fmt.Sprintf("f%02d.txt", i), "x")
	}
	// A distinct directory, to prove the guard is keyed by path and does not
	// serialize the whole surface.
	f.dir(rootIno, "other")

	// Park the first ReadDir until every caller has arrived, so "they
	// collapsed" is a fact rather than a race the scheduler decides. Without
	// this the eight goroutines can run to completion one after another --
	// each finishing before the next begins -- and singleflight has nothing
	// to merge. That passed on a busy laptop and failed on an idle runner.
	var joins atomic.Int64
	webapi.SetFlightJoined(func() { joins.Add(1) })
	t.Cleanup(func() { webapi.SetFlightJoined(nil) })

	gate := make(chan struct{})
	held := map[string]chan struct{}{"/dir-0": gate}
	f.cnt.hold.Store(&held)

	before := f.cnt.readDirs.Load()
	const n = 8
	var wg sync.WaitGroup
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bodies[i] = f.list("/dir-0").want(http.StatusOK)
		}(i)
	}
	// Hold the leader inside ReadDir until every follower has JOINED the
	// guard -- not merely started. Waiting on "the leader arrived" was not
	// enough: the followers had not reached flight.do yet, so they each took
	// their own readdir and the assertion failed on an idle runner.
	for joins.Load() < n-1 {
		runtime.Gosched()
	}
	f.cnt.hold.Store(nil)
	close(gate)
	wg.Wait()
	reads := f.cnt.readDirs.Load() - before
	if reads < 1 {
		t.Fatalf("%d concurrent listings made %d readdirs", n, reads)
	}
	if reads > 1 {
		t.Fatalf("%d concurrent listings of the same directory made %d readdirs, want 1: the "+
			"in-flight guard is not collapsing them, and one navigation costs two full listings", n, reads)
	}
	for i := 1; i < n; i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("two concurrent listings of the same directory disagreed:\n%s\n%s", bodies[0], bodies[i])
		}
	}

	// The guard is NOT a cache: the refresh button exists to re-list a
	// directory the store already has, and it has to work.
	before = f.cnt.readDirs.Load()
	f.list("/dir-0").want(http.StatusOK)
	f.list("/dir-0").want(http.StatusOK)
	if got := f.cnt.readDirs.Load() - before; got != 2 {
		t.Fatalf("two SEQUENTIAL listings made %d readdirs, want 2: a cache here would break the "+
			"refresh gesture, which is the only way to re-list a loaded folder", got)
	}
}

// What a read refuses, and with which status. The permission rows are the
// point: a path this session may not read is a 403 and not an empty listing.
func TestListingRefusals(t *testing.T) {
	f := newFix(t)
	// A directory somebody else owns, with nothing granted to anybody else.
	f.mkdir(rootIno, "private", 0o700, f.they, f.thgr)
	f.text(rootIno, "plain.txt", "x")

	for _, tc := range []struct {
		name   string
		target string
		status int
	}{
		{"a directory the session may not read", "/api/v1/files/" + id("/private"), http.StatusForbidden},
		{"a path that is not there", "/api/v1/files/" + id("/nope"), http.StatusNotFound},
		{"a file, which is not a listing", "/api/v1/files/" + id("/plain.txt"), http.StatusBadRequest},
		{"info for a path that is not there", "/api/v1/info/" + id("/nope"), http.StatusNotFound},
		{"info for a directory the session may not read", "/api/v1/info/" + id("/private"), http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.get(tc.target)
			r.want(tc.status)
			if msg := r.errorOf(); msg == "" {
				t.Error("a refusal with no message")
			}
		})
	}
}

// A read is a read: a read-only session lists and reads exactly as a
// read-write one does, and only mutations are refused (mutate_test.go).
func TestReadOnlySessionCanStillList(t *testing.T) {
	f := newFix(t)
	f.text(rootIno, "there.txt", "x")
	ro := f.readOnly()
	if got := ro.list("/").ids(); len(got) != 1 || got[0] != "/there.txt" {
		t.Fatalf("a read-only session listed %v", got)
	}
	if in := ro.get("/api/v1/info/" + id("/")).info(); in.Mode != "read-only" {
		t.Errorf("info mode = %q on a read-only session, want read-only", in.Mode)
	}
}

// The volume is not open for the first moments of `pelfs browse`. That window
// is a 503, not an empty volume: an empty listing is a statement about the
// volume and there is none to make yet.
func TestNotReadyIs503(t *testing.T) {
	api, err := webapi.New(webapi.Config{Volume: webapi.Static(nil)})
	if err != nil {
		t.Fatalf("webapi.New: %v", err)
	}
	mux := http.NewServeMux()
	for _, rt := range api.Routes() {
		mux.Handle(rt.Pattern, rt.Handler)
	}
	f := &fix{t: t, mux: mux}
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodGet, "/api/v1/files", ""},
		{http.MethodGet, "/api/v1/files/" + id("/x"), ""},
		{http.MethodGet, "/api/v1/info/" + id("/x"), ""},
		{http.MethodPost, "/api/v1/files/" + id("/"), `{"name":"x","type":"folder"}`},
		{http.MethodDelete, "/api/v1/files", `{"ids":["/x"]}`},
	} {
		r := f.do(tc.method, tc.target, tc.body)
		r.want(http.StatusServiceUnavailable)
		if !strings.Contains(r.errorOf(), "still opening") {
			t.Errorf("%s %s said %q, want a sentence about the volume still opening",
				tc.method, tc.target, r.errorOf())
		}
	}
}
