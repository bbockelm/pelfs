package webapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/webapi"
)

// POST /api/v1/files/{parent}: mkdir and touch, and everything each of them
// refuses.
func TestNewFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		parent  string
		body    string
		status  int
		wantID  string
		wantMsg string
	}{
		{
			name: "a folder", parent: "/dir-0",
			body:   `{"name":"new-folder","type":"folder"}`,
			status: http.StatusOK, wantID: "/dir-0/new-folder",
		},
		{
			name: "a file", parent: "/dir-0",
			body:   `{"name":"touched.txt","type":"file"}`,
			status: http.StatusOK, wantID: "/dir-0/touched.txt",
		},
		{
			name:   "no type at all is a file, which is the contract's zero value",
			parent: "/dir-0", body: `{"name":"implicit.txt"}`,
			status: http.StatusOK, wantID: "/dir-0/implicit.txt",
		},
		{
			name: "a name that already exists", parent: "/dir-0",
			body:   `{"name":"taken.txt","type":"file"}`,
			status: http.StatusConflict, wantMsg: "already exists",
		},
		{
			name: "a name with a path separator in it", parent: "/dir-0",
			body:   `{"name":"a/b","type":"folder"}`,
			status: http.StatusBadRequest, wantMsg: "one component",
		},
		{
			name: "a name that is a traversal", parent: "/dir-0",
			body:   `{"name":"..","type":"folder"}`,
			status: http.StatusBadRequest, wantMsg: "is not a name",
		},
		{
			name: "an empty name", parent: "/dir-0",
			body:   `{"name":"","type":"folder"}`,
			status: http.StatusBadRequest, wantMsg: "empty name",
		},
		{
			name: "a type nobody has", parent: "/dir-0",
			body:   `{"name":"x","type":"socket"}`,
			status: http.StatusBadRequest, wantMsg: "neither",
		},
		{
			name: "a parent that is not there", parent: "/nope",
			body:   `{"name":"x","type":"folder"}`,
			status: http.StatusNotFound, wantMsg: "no such file",
		},
		{
			name: "a parent that is a file", parent: "/dir-0/taken.txt",
			body:   `{"name":"x","type":"folder"}`,
			status: http.StatusBadRequest, wantMsg: "not a directory",
		},
		{
			name: "a parent this session may not write", parent: "/theirs",
			body:   `{"name":"x","type":"folder"}`,
			status: http.StatusForbidden, wantMsg: "permission denied",
		},
		{
			name: "a body that is not JSON", parent: "/dir-0",
			body: `not json`, status: http.StatusBadRequest,
		},
		{
			name: "a body with a field we do not implement", parent: "/dir-0",
			body: `{"name":"x","type":"file","chmod":"0777"}`, status: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFix(t)
			d0 := f.dir(rootIno, "dir-0")
			f.text(d0, "taken.txt", "already here")
			f.mkdir(rootIno, "theirs", 0o755, f.they, f.thgr)

			r := f.do(http.MethodPost, "/api/v1/files/"+id(tc.parent), tc.body)
			r.want(tc.status)
			if tc.wantMsg != "" && !strings.Contains(r.errorOf(), tc.wantMsg) {
				t.Errorf("the refusal says %q, want it to mention %q", r.errorOf(), tc.wantMsg)
			}
			if tc.status != http.StatusOK {
				return
			}
			if got := r.result().ID; got != tc.wantID {
				t.Fatalf("result id %q, want %q", got, tc.wantID)
			}
			if !f.exists(tc.wantID) {
				t.Errorf("%s was reported created and is not in the volume", tc.wantID)
			}
		})
	}
}

// PUT /api/v1/files/{id}: one rename, in place.
func TestRename(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		body    string
		status  int
		wantID  string
		wantMsg string
	}{
		{
			name: "a file", id: "/dir-0/file-0.txt",
			body:   `{"operation":"rename","name":"renamed.txt"}`,
			status: http.StatusOK, wantID: "/dir-0/renamed.txt",
		},
		{
			name: "a directory", id: "/dir-0",
			body:   `{"operation":"rename","name":"dir-x"}`,
			status: http.StatusOK, wantID: "/dir-x",
		},
		{
			name: "renaming to the same name is a no-op, not an error", id: "/dir-0/file-0.txt",
			body:   `{"operation":"rename","name":"file-0.txt"}`,
			status: http.StatusOK, wantID: "/dir-0/file-0.txt",
		},
		{
			name: "a name that would move it", id: "/dir-0/file-0.txt",
			body:   `{"operation":"rename","name":"../escaped.txt"}`,
			status: http.StatusBadRequest, wantMsg: "one component",
		},
		{
			name: "an operation that belongs on the batch route", id: "/dir-0/file-0.txt",
			body:   `{"operation":"move","name":"x"}`,
			status: http.StatusBadRequest, wantMsg: "/api/v1/files",
		},
		{
			name: "the volume root", id: "/",
			body:   `{"operation":"rename","name":"x"}`,
			status: http.StatusBadRequest, wantMsg: "root",
		},
		{
			name: "a path that is not there", id: "/nope.txt",
			body:   `{"operation":"rename","name":"x.txt"}`,
			status: http.StatusNotFound,
		},
		{
			name: "a file in a directory this session may not write", id: "/theirs/f.txt",
			body:   `{"operation":"rename","name":"x.txt"}`,
			status: http.StatusForbidden, wantMsg: "permission denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFix(t)
			d0 := f.dir(rootIno, "dir-0")
			f.text(d0, "file-0.txt", "body")
			theirs := f.mkdir(rootIno, "theirs", 0o755, f.they, f.thgr)
			f.file(theirs, "f.txt", 0o644, f.they, f.thgr, []byte("theirs"))

			r := f.do(http.MethodPut, "/api/v1/files/"+id(tc.id), tc.body)
			r.want(tc.status)
			if tc.wantMsg != "" && !strings.Contains(r.errorOf(), tc.wantMsg) {
				t.Errorf("the refusal says %q, want it to mention %q", r.errorOf(), tc.wantMsg)
			}
			if tc.status != http.StatusOK {
				// A refused rename must not have half-happened.
				if !f.exists(tc.id) && tc.id != "/nope.txt" {
					t.Errorf("%s is gone after a refused rename", tc.id)
				}
				return
			}
			if got := r.result().ID; got != tc.wantID {
				t.Fatalf("result id %q, want %q", got, tc.wantID)
			}
			if !f.exists(tc.wantID) {
				t.Errorf("%s is not in the volume after the rename", tc.wantID)
			}
		})
	}
}

// A BATCH RETURNS ONE RESULT PER ID, and a batch where some ids fail is
// reported as exactly that: the successes stand, the failures say why, and the
// status is 200 because a 4xx would tell the client nothing happened when in
// fact half of it did.
func TestBatchMoveReportsEveryIDSeparately(t *testing.T) {
	f := newFix(t)
	src := f.dir(rootIno, "src")
	f.dir(rootIno, "dst")
	f.text(src, "a.txt", "A")
	f.text(src, "b.txt", "B")
	f.text(src, "c.txt", "C")
	// One id that cannot move: it lives in a directory this session may not
	// write, which is the EACCES the design's own example is about.
	theirs := f.mkdir(rootIno, "theirs", 0o555, f.they, f.thgr)
	f.file(theirs, "d.txt", 0o644, f.they, f.thgr, []byte("D"))

	body := jsonBody(t, map[string]any{
		"operation": "move",
		"ids":       []string{"/src/a.txt", "/src/b.txt", "/theirs/d.txt", "/src/missing.txt", "/src/c.txt"},
		"target":    "/dst",
	})
	got := f.do(http.MethodPut, "/api/v1/files", body).batch()

	if len(got.Result) != 5 {
		t.Fatalf("a 5-id batch returned %d results; there must be one per id: %+v", len(got.Result), got.Result)
	}
	if got.Failed != 2 {
		t.Errorf("failed = %d, want 2: %+v", got.Failed, got.Result)
	}
	want := []struct {
		from string
		ok   bool
		id   string
	}{
		{"/src/a.txt", true, "/dst/a.txt"},
		{"/src/b.txt", true, "/dst/b.txt"},
		{"/theirs/d.txt", false, ""},
		{"/src/missing.txt", false, ""},
		{"/src/c.txt", true, "/dst/c.txt"},
	}
	for i, w := range want {
		g := got.Result[i]
		if g.From != w.from {
			t.Errorf("result %d is for %q, want %q — results must come back in the request's order", i, g.From, w.from)
		}
		if g.OK != w.ok || g.ID != w.id {
			t.Errorf("result %d = %+v, want ok=%v id=%q", i, g, w.ok, w.id)
		}
		if !g.OK && g.Error == "" {
			t.Errorf("result %d failed with no reason", i)
		}
	}
	// The successes really happened, and the failures really did not.
	for _, p := range []string{"/dst/a.txt", "/dst/b.txt", "/dst/c.txt"} {
		if !f.exists(p) {
			t.Errorf("%s was reported moved and is not there", p)
		}
	}
	if !f.exists("/theirs/d.txt") {
		t.Error("the file that could not move is gone")
	}
	if f.exists("/dst/d.txt") {
		t.Error("a file that was reported as failed arrived at the target anyway")
	}
	// AND THE FIFTH ID STILL RAN. A batch that stopped at the first failure
	// would be the same lie in a different shape.
	if !f.exists("/dst/c.txt") {
		t.Error("the id after the failing one was never attempted")
	}
}

// Copy is the same route with the same per-id shape, and it copies a tree.
func TestBatchCopy(t *testing.T) {
	f := newFix(t)
	src := f.dir(rootIno, "src")
	f.dir(rootIno, "dst")
	f.text(src, "a.txt", "AAA")
	sub := f.dir(src, "sub")
	f.text(sub, "deep.txt", "deep")
	f.symlink(sub, "link", "deep.txt")

	body := jsonBody(t, map[string]any{
		"operation": "copy",
		"ids":       []string{"/src/a.txt", "/src/sub"},
		"target":    "/dst",
	})
	got := f.do(http.MethodPut, "/api/v1/files", body).batch()
	if got.Failed != 0 {
		t.Fatalf("a copy of two ids failed %d of them: %+v", got.Failed, got.Result)
	}
	if f.read("/dst/a.txt") != "AAA" {
		t.Errorf("the copied file has the wrong body: %q", f.read("/dst/a.txt"))
	}
	if f.read("/dst/sub/deep.txt") != "deep" {
		t.Errorf("the copied tree's file has the wrong body: %q", f.read("/dst/sub/deep.txt"))
	}
	// The original is untouched: that is the whole difference from a move.
	if f.read("/src/a.txt") != "AAA" {
		t.Error("a copy changed the source")
	}
	// A symlink to a file was presented to the UI as that file, so a copy of
	// it copies the bytes rather than a link the listing never showed.
	if f.read("/dst/sub/link") != "deep" {
		t.Errorf("the copied link does not hold the target's bytes: %q", f.read("/dst/sub/link"))
	}
	// No temp file survives a completed copy.
	if left := f.parts("/dst"); len(left) != 0 {
		t.Errorf("a finished copy left %v behind", left)
	}
}

// A copy INTO its own subtree would walk the tree it is growing. It is
// refused per id, and the refusal names the problem.
func TestBatchRefusesCopyIntoItself(t *testing.T) {
	f := newFix(t)
	src := f.dir(rootIno, "src")
	f.dir(src, "inner")
	f.text(src, "a.txt", "A")

	for _, op := range []string{"copy", "move"} {
		t.Run(op, func(t *testing.T) {
			body := jsonBody(t, map[string]any{
				"operation": op, "ids": []string{"/src"}, "target": "/src/inner",
			})
			got := f.do(http.MethodPut, "/api/v1/files", body).batch()
			if got.Failed != 1 {
				t.Fatalf("%s of a directory into itself was not refused: %+v", op, got.Result)
			}
			if !strings.Contains(got.Result[0].Error, "inside") {
				t.Errorf("the refusal says %q, want it to say the target is inside the source", got.Result[0].Error)
			}
		})
	}
}

// What fails the WHOLE batch, because nothing was attempted.
func TestBatchRequestLevelRefusals(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "dst")
	f.text(rootIno, "a.txt", "A")

	for _, tc := range []struct {
		name   string
		body   string
		status int
		msg    string
	}{
		{"an operation nobody implements", `{"operation":"chmod","ids":["/a.txt"],"target":"/dst"}`,
			http.StatusBadRequest, "not \"move\" or \"copy\""},
		{"no ids", `{"operation":"move","ids":[],"target":"/dst"}`,
			http.StatusBadRequest, "no ids"},
		{"a target that is not there", `{"operation":"move","ids":["/a.txt"],"target":"/nope"}`,
			http.StatusNotFound, "no such file"},
		{"a target that is a file", `{"operation":"move","ids":["/a.txt"],"target":"/a.txt"}`,
			http.StatusBadRequest, "not a directory"},
		{"a body that is not JSON", `nope`, http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.do(http.MethodPut, "/api/v1/files", tc.body)
			r.want(tc.status)
			if tc.msg != "" && !strings.Contains(r.errorOf(), tc.msg) {
				t.Errorf("the refusal says %q, want it to mention %q", r.errorOf(), tc.msg)
			}
			if f.exists("/dst/a.txt") {
				t.Fatal("a request-level refusal moved something anyway")
			}
		})
	}
}

// DELETE takes its ids IN THE BODY and answers per id, recursing into
// directories the way every file manager's delete does.
func TestDelete(t *testing.T) {
	f := newFix(t)
	d := f.dir(rootIno, "tree")
	sub := f.dir(d, "sub")
	f.text(sub, "deep.txt", "deep")
	f.text(d, "shallow.txt", "shallow")
	f.text(rootIno, "lone.txt", "lone")
	theirs := f.mkdir(rootIno, "theirs", 0o555, f.they, f.thgr)
	f.file(theirs, "stuck.txt", 0o644, f.they, f.thgr, []byte("stuck"))

	body := jsonBody(t, map[string]any{
		"ids": []string{"/lone.txt", "/tree", "/theirs/stuck.txt", "/gone.txt", "/"},
	})
	got := f.do(http.MethodDelete, "/api/v1/files", body).batch()
	if len(got.Result) != 5 {
		t.Fatalf("a 5-id delete returned %d results: %+v", len(got.Result), got.Result)
	}
	if got.Failed != 3 {
		t.Errorf("failed = %d, want 3 (the unwritable one, the missing one, the root): %+v", got.Failed, got.Result)
	}
	for _, gone := range []string{"/lone.txt", "/tree", "/tree/sub/deep.txt"} {
		if f.exists(gone) {
			t.Errorf("%s survived the delete", gone)
		}
	}
	if !f.exists("/theirs/stuck.txt") {
		t.Error("a file this session may not delete was deleted")
	}
	// The root is refused by name, because "delete everything" is not a
	// gesture this surface offers.
	rootResult := got.Result[4]
	if rootResult.OK || !strings.Contains(rootResult.Error, "root") {
		t.Errorf("deleting / gave %+v, want a refusal naming the root", rootResult)
	}
}

// A read-only session refuses every mutation, and says which kind of refusal
// it is: "restart with --rw" is a different action from "chmod that file".
func TestReadOnlySessionRefusesEveryMutation(t *testing.T) {
	rw := newFix(t)
	rw.dir(rootIno, "dir-0")
	rw.text(rootIno, "a.txt", "A")
	f := rw.readOnly()

	for _, tc := range []struct{ name, method, target, body string }{
		{"create", http.MethodPost, "/api/v1/files/" + id("/dir-0"), `{"name":"x","type":"folder"}`},
		{"rename", http.MethodPut, "/api/v1/files/" + id("/a.txt"), `{"operation":"rename","name":"b.txt"}`},
		{"move", http.MethodPut, "/api/v1/files", `{"operation":"move","ids":["/a.txt"],"target":"/dir-0"}`},
		{"delete", http.MethodDelete, "/api/v1/files", `{"ids":["/a.txt"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.do(tc.method, tc.target, tc.body)
			r.want(http.StatusForbidden)
			if !strings.Contains(r.errorOf(), "--rw") {
				t.Errorf("a read-only refusal says %q, want it to name the flag that fixes it", r.errorOf())
			}
		})
	}
	if !f.exists("/a.txt") {
		t.Error("a read-only session changed something")
	}
	if f.exists("/b.txt") {
		t.Error("a read-only session renamed something")
	}
	// And an upload on the read-only session is refused before a byte is read.
	body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"x.bin", "x"}})
	up := f.upload("/dir-0", body, ct)
	up.want(http.StatusForbidden)
	if len(f.parts("/dir-0")) != 0 {
		t.Error("a refused upload left a temp file behind")
	}
}
