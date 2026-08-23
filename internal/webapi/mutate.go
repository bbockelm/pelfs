package webapi

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/go-git/go-billy/v5"
)

// Result is one object a mutation produced or acted on.
//
// The response id is AUTHORITATIVE: the component renames its optimistic row
// to match whatever comes back (the recording's create-folder step notes it),
// so a handler that adjusted a name — deduplicated it, stripped something —
// must say so here and the UI will follow.
type Result struct {
	// ID is the object's path after the operation, or "" if it failed.
	ID string `json:"id"`
	// Type is "folder" or "file", where the operation knows it.
	Type string `json:"type,omitempty"`
}

// BatchResult is ONE id's outcome in a batch. There is one of these per id in
// the request, always, in the request's order.
//
// This is the honest shape and it is not negotiable (docs/design-webui.md,
// "semantic restraint"): there is no atomic N-way rename in internal/overlay,
// in WebDAV or in POSIX, so a batch move is N sequential renames — and a
// surface that reported "moved" for a batch whose fourth rename hit EACCES
// would be lying in the one place a user cannot check.
type BatchResult struct {
	// ID is the object's path after the operation, or "" on failure.
	ID string `json:"id"`
	// From is the id the request named, so a client can pair results with
	// requests without relying on order alone.
	From string `json:"from"`
	// OK is whether this one id succeeded.
	OK bool `json:"ok"`
	// Error is why it did not, for a person to read.
	Error string `json:"error,omitempty"`
}

// BatchResponse is what a batch route answers.
//
// THE STATUS IS 200 EVEN WHEN SOME IDS FAILED, and the count is how the
// client learns better. The alternative — a 4xx for a partial failure —
// would tell a client that nothing happened, when in fact three of five
// files moved, and it would make an optimistic UI roll back rows that are
// really gone. A request that is malformed in itself (bad JSON, unknown
// operation, an unusable target) is a 4xx with no results at all, because
// then nothing WAS attempted.
type BatchResponse struct {
	Result []BatchResult `json:"result"`
	// Failed is how many entries of Result have OK false. Zero means every
	// id succeeded, and it is the field a client should branch on rather
	// than the status.
	Failed int `json:"failed"`
}

func (b *BatchResponse) add(r BatchResult) {
	if !r.OK {
		b.Failed++
	}
	b.Result = append(b.Result, r)
}

// okResult and failed build one id's outcome.
func okResult(from, id string) BatchResult { return BatchResult{ID: id, From: from, OK: true} }
func failed(from string, err error) BatchResult {
	return BatchResult{From: from, Error: errText(err)}
}

// mutable resolves the volume and refuses a read-only session before any work
// is attempted, so that "you cannot write here at all" is one answer and not
// N identical per-id ones.
func (a *API) mutable() (billy.Filesystem, error) {
	bfs, err := a.volume()
	if err != nil {
		return nil, err
	}
	if !writable(bfs) {
		return nil, ErrReadOnly
	}
	return bfs, nil
}

// ---------------------------------------------------------------------------
// POST /api/v1/files/{id} — create
// ---------------------------------------------------------------------------

// newFileRequest is the component's NewFile body: {"name":"x","type":"folder"}.
type newFileRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// NewFile answers POST /api/v1/files/{id}, where {id} is the PARENT
// directory: mkdir for type "folder", an empty file for type "file".
//
// Both halves of the contract's create verb, and nothing else. The name is
// one component (validName), so this route cannot create a path — the two
// batch routes are where a client says where something goes.
func (a *API) NewFile(w http.ResponseWriter, r *http.Request) {
	parent, err := idOf(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req newFileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if err := validName(req.Name); err != nil {
		writeErr(w, err)
		return
	}
	kind := req.Type
	if kind == "" {
		// The contract's own default. A body with no type is a file, which
		// is what the reference server's NewFile{Name, Type} zero value
		// means.
		kind = TypeFile
	}
	if kind != TypeFile && kind != TypeFolder {
		writeErr(w, fmt.Errorf("%w: type %q is neither %q nor %q", ErrBadRequest, req.Type, TypeFile, TypeFolder))
		return
	}
	bfs, err := a.mutable()
	if err != nil {
		writeErr(w, err)
		return
	}
	// The parent must exist and be a directory. MkdirAll below would
	// otherwise create the whole chain, answering 200 for a create in a
	// directory the client had no reason to believe existed.
	pfi, err := bfs.Stat(parent)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !pfi.IsDir() {
		writeErr(w, fmt.Errorf("%w: %s is not a directory", ErrBadRequest, parent))
		return
	}
	full := path.Join(parent, req.Name)
	if _, err := lstat(bfs, full); err == nil {
		writeErr(w, &fs.PathError{Op: "create", Path: full, Err: fs.ErrExist})
		return
	} else if !os.IsNotExist(err) {
		writeErr(w, err)
		return
	}
	if kind == TypeFolder {
		if err := bfs.MkdirAll(full, 0o755); err != nil {
			writeErr(w, err)
			return
		}
	} else {
		// O_EXCL, so two clients racing the same name produce one file and
		// one 409 rather than one file and one silent truncation.
		f, err := bfs.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			writeErr(w, err)
			return
		}
		if err := f.Close(); err != nil {
			writeErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]Result{"result": {ID: full, Type: kind}})
}

// ---------------------------------------------------------------------------
// PUT /api/v1/files/{id} — rename
// ---------------------------------------------------------------------------

// renameRequest is {"operation":"rename","name":"renamed.txt"}.
type renameRequest struct {
	Operation string `json:"operation"`
	Name      string `json:"name"`
}

// Rename answers PUT /api/v1/files/{id}: one billyFS.Rename, in place.
//
// The new name is a COMPONENT, and the object stays in its own directory. A
// rename that moved something is the batch route's job, and keeping them
// apart is what makes this one a single filesystem call with a single answer.
func (a *API) Rename(w http.ResponseWriter, r *http.Request) {
	id, err := idOf(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req renameRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.Operation != "" && req.Operation != "rename" {
		writeErr(w, fmt.Errorf("%w: this route performs %q; %q belongs on PUT %s/files",
			ErrBadRequest, "rename", req.Operation, a.prefix))
		return
	}
	if err := validName(req.Name); err != nil {
		writeErr(w, err)
		return
	}
	if id == "/" {
		writeErr(w, fmt.Errorf("%w: the volume root has no name to change", ErrBadRequest))
		return
	}
	bfs, err := a.mutable()
	if err != nil {
		writeErr(w, err)
		return
	}
	to := path.Join(path.Dir(id), req.Name)
	if to == id {
		// Not an error and not work: the component sends this when a user
		// opens the rename box and presses Enter.
		writeJSON(w, http.StatusOK, map[string]Result{"result": {ID: id}})
		return
	}
	if err := bfs.Rename(id, to); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]Result{"result": {ID: to}})
}

// ---------------------------------------------------------------------------
// PUT /api/v1/files — batch move or copy
// ---------------------------------------------------------------------------

// batchRequest is {"operation":"move"|"copy","ids":[...],"target":"/dir"}.
type batchRequest struct {
	Operation string   `json:"operation"`
	IDs       []string `json:"ids"`
	Target    string   `json:"target"`
	// Name is in the contract's FileUpdate shape and is meaningless for a
	// batch; it is accepted and ignored so that a client which sends the
	// full struct is not answered with a 400 over a field it did not use.
	Name string `json:"name,omitempty"`
}

// Batch answers PUT /api/v1/files: N moves or N copies, N results.
func (a *API) Batch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	switch req.Operation {
	case "move", "copy":
	default:
		writeErr(w, fmt.Errorf("%w: operation %q is not %q or %q", ErrBadRequest, req.Operation, "move", "copy"))
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, fmt.Errorf("%w: no ids", ErrBadRequest))
		return
	}
	target, err := cleanPath(req.Target)
	if err != nil {
		writeErr(w, err)
		return
	}
	bfs, err := a.mutable()
	if err != nil {
		writeErr(w, err)
		return
	}
	// The target is checked ONCE, and a bad target fails the whole request
	// rather than N times identically: nothing was attempted, so there are
	// no per-id outcomes to report.
	tfi, err := bfs.Stat(target)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !tfi.IsDir() {
		writeErr(w, fmt.Errorf("%w: the target %s is not a directory", ErrBadRequest, target))
		return
	}

	var out BatchResponse
	for _, raw := range req.IDs {
		from, err := cleanPath(raw)
		if err != nil {
			out.add(failed(raw, err))
			continue
		}
		to := path.Join(target, path.Base(from))
		switch {
		case from == "/":
			out.add(failed(raw, fmt.Errorf("%w: the volume root cannot be moved or copied", ErrBadRequest)))
			continue
		case to == from:
			out.add(failed(raw, fmt.Errorf("%w: %s is already in %s", ErrBadRequest, path.Base(from), target)))
			continue
		case within(from, target):
			// Both operations need this. A move of a directory into itself
			// is EINVAL below anyway, but a COPY would walk the tree it is
			// growing and never finish, and "the server ran out of disk"
			// is not the error the user should get for it.
			out.add(failed(raw, fmt.Errorf("%w: %s is inside %s", ErrBadRequest, target, from)))
			continue
		}
		if req.Operation == "move" {
			if err := bfs.Rename(from, to); err != nil {
				out.add(failed(raw, err))
				continue
			}
			out.add(okResult(raw, to))
			continue
		}
		if err := copyTree(bfs, from, to); err != nil {
			out.add(failed(raw, err))
			continue
		}
		out.add(okResult(raw, to))
	}
	writeJSON(w, http.StatusOK, out)
}

// within reports whether inner is dir itself or somewhere below it.
func within(dir, inner string) bool {
	if dir == inner {
		return true
	}
	if dir == "/" {
		return true
	}
	return strings.HasPrefix(inner, dir+"/")
}

// copyTree copies one object, recursing for a directory.
//
// There is no billy copy, so this is composed of the calls there are — which
// is exactly the constraint the design puts on this surface: an operation
// that internal/vfsbilly cannot express is an operation this API does not
// have.
//
// Symlinks follow what the LISTING said about them: a link to a file was
// presented as that file, so copying it copies the bytes; a link to a
// directory and a dangling link were never shown, so a recursive copy skips
// them rather than inventing a representation for them mid-copy. Special
// files are skipped for the same reason.
func copyTree(bfs billy.Filesystem, from, to string) error {
	fi, err := bfs.Stat(from) // Stat, not Lstat: follows a terminal link.
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return copyFile(bfs, from, to, fi.Mode().Perm())
	}
	if _, err := lstat(bfs, to); err == nil {
		return &fs.PathError{Op: "copy", Path: to, Err: fs.ErrExist}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := bfs.MkdirAll(to, fi.Mode().Perm()); err != nil {
		return err
	}
	ents, err := bfs.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		switch e.Name() {
		case ".", "..":
			continue
		}
		src, dst := path.Join(from, e.Name()), path.Join(to, e.Name())
		m := e.Mode()
		switch {
		case m&os.ModeSymlink != 0:
			resolved, t, err := follow(bfs, src)
			if err != nil || t.IsDir() {
				// Hidden in the listing, skipped here: the two surfaces
				// agree about what is there.
				continue
			}
			// The bytes come from the TARGET. Opening the link itself
			// answers ESTALE on the first read, which is the same reason
			// internal/vfsdav opens the resolved path.
			if err := copyFile(bfs, resolved, dst, t.Mode().Perm()); err != nil {
				return err
			}
		case m.IsDir():
			if err := copyTree(bfs, src, dst); err != nil {
				return err
			}
		case m.IsRegular():
			if err := copyFile(bfs, src, dst, m.Perm()); err != nil {
				return err
			}
		}
	}
	return nil
}

// copyFile copies bytes THROUGH the .pelfs-part convention, for the same
// reason an upload does: a copy of a 68 MB file that dies halfway must not
// leave a truncated file under the final name for the next checkpoint to
// publish. The buffer is the upload's, so a copy of any size costs the same
// 32 KiB.
func copyFile(bfs billy.Filesystem, from, to string, perm os.FileMode) error {
	src, err := bfs.OpenFile(from, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck

	part, cleanup, err := createPart(bfs, to, perm)
	if err != nil {
		return err
	}
	buf := make([]byte, uploadBufSize)
	if _, err := io.CopyBuffer(part.dst, src, buf); err != nil {
		cleanup()
		return err
	}
	if err := part.dst.Close(); err != nil {
		cleanup()
		return err
	}
	if err := bfs.Rename(part.name, to); err != nil {
		cleanup()
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/files — batch delete
// ---------------------------------------------------------------------------

// deleteRequest is {"ids":[...]}. The ids are IN THE BODY and not in the
// path, which is the one surprise in the recorded contract.
type deleteRequest struct {
	IDs []string `json:"ids"`
}

// Delete answers DELETE /api/v1/files: N deletes, N results.
func (a *API) Delete(w http.ResponseWriter, r *http.Request) {
	var req deleteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, fmt.Errorf("%w: no ids", ErrBadRequest))
		return
	}
	bfs, err := a.mutable()
	if err != nil {
		writeErr(w, err)
		return
	}
	var out BatchResponse
	for _, raw := range req.IDs {
		id, err := cleanPath(raw)
		if err != nil {
			out.add(failed(raw, err))
			continue
		}
		if id == "/" {
			out.add(failed(raw, fmt.Errorf("%w: the volume root cannot be deleted", ErrBadRequest)))
			continue
		}
		if err := removeAll(bfs, id); err != nil {
			out.add(failed(raw, err))
			continue
		}
		out.add(okResult(raw, id))
	}
	writeJSON(w, http.StatusOK, out)
}

// removeAll unlinks a name, recursing into a directory.
//
// billy.Remove unlinks one name and refuses a non-empty directory, so the
// recursion is here — depth-first, and a SYMLINK is removed as itself.
// Following one would delete the target and leave the link, which is the one
// mistake a recursive delete cannot take back. This is internal/vfsdav's
// RemoveAll, for the same reasons.
func removeAll(bfs billy.Filesystem, p string) error {
	fi, err := lstat(bfs, p)
	if err != nil {
		return err
	}
	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		ents, err := bfs.ReadDir(p)
		if err != nil {
			return err
		}
		for _, e := range ents {
			switch e.Name() {
			case ".", "..":
				continue
			}
			if err := removeAll(bfs, path.Join(p, e.Name())); err != nil {
				return err
			}
		}
	}
	return bfs.Remove(p)
}

// lstat is Lstat where the filesystem has one, and Stat where it does not.
// The difference matters exactly where a symlink is the OBJECT of the
// operation rather than a step on the way to one.
func lstat(bfs billy.Filesystem, p string) (os.FileInfo, error) {
	type lstatter interface {
		Lstat(string) (os.FileInfo, error)
	}
	if l, okk := bfs.(lstatter); okk {
		return l.Lstat(p)
	}
	return bfs.Stat(p)
}
