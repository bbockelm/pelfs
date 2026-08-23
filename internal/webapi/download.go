package webapi

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"

	"github.com/bbockelm/pelfs/internal/browsesession"
)

// Source is the file surface behind GET /d/<ticket>, and it is the piece M1
// left as a nil seam (browseServer.downloadSource returned nil, so every
// redemption 404'd).
//
// It is deliberately tiny, because the interesting properties are elsewhere:
// the ticket is minted by an authenticated call, burned on first use, and
// expires in 30 seconds (internal/browsesession), and the download route
// accepts NO session credential because an <a href> cannot carry a header
// and an ambient-credential GET is the hole DNS rebinding exploits. What is
// left for this type to get right is exactly two things — that the bytes come
// from the volume through the same permission model as every other surface,
// and that the ticket's path is the only statement about what to serve.
func (a *API) Source() browsesession.Source { return &source{a: a} }

type source struct{ a *API }

var _ browsesession.Source = (*source)(nil)

// Open serves one file's bytes.
//
// The permission model is internal/fsperm through internal/vfsbilly and
// nothing else: an EACCES/EPERM from the layer below becomes
// browsesession.ErrForbidden, which the handler renders as 403. There is no
// second check here, and there must not be one — a surface with its own
// permission opinion is a surface that can disagree with FUSE, NFS and
// WebDAV about the same file.
//
// Three refusals worth naming:
//
//   - A DIRECTORY is fs.ErrNotExist, hence 404. There is no file at that
//     path to download, "you may not" would be false (the user may well be
//     allowed to list it), and a zip-on-the-fly is an operation
//     internal/vfsbilly cannot express.
//   - A SPECIAL FILE (fifo, socket, device) is fs.ErrNotExist for the same
//     reason it is hidden from every listing: there is nothing here a client
//     could receive, and a read of a fifo would hang the request forever.
//   - A SYMLINK is FOLLOWED to a regular file, matching what the listing
//     said about it, and refused where the listing hid it (a link to a
//     directory, a dangling link).
//
// Nothing in here reads the request, because Open is not given one: by the
// time it runs, the ticket's path is the whole of what the request said.
func (s *source) Open(_ context.Context, p string) (*browsesession.Content, error) {
	name, err := cleanPath(p)
	if err != nil {
		return nil, err
	}
	bfs, err := s.a.volume()
	if err != nil {
		return nil, err
	}
	// The chain is resolved to the path it ENDS at, and the handle is opened
	// on that path rather than on the name the user clicked. Opening the link
	// inode itself answers ESTALE on the first read — the same trap
	// internal/vfsdav documents — so "Stat says it is a regular file" is not
	// enough on its own.
	resolved, fi, err := follow(bfs, name)
	if err != nil {
		return nil, forbidden(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "download", Path: name, Err: fs.ErrNotExist}
	}
	f, err := bfs.OpenFile(resolved, os.O_RDONLY, 0)
	if err != nil {
		return nil, forbidden(err)
	}
	return &browsesession.Content{
		// The name the user clicked, not the target's: a download of
		// `lib.so -> lib.so.1` saves as lib.so.
		Name:    path.Base(name),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		// A billy.File is an io.ReadSeeker, so the handler's
		// http.ServeContent path gives Range and If-Modified-Since for
		// free. That retires docs/design-guiclients.md's concern about
		// go-billy's helper/iofs file having no Seek: this path never
		// touches iofs.
		Body: f,
	}, nil
}

// forbidden translates the layer below's refusal into the one the download
// handler distinguishes. "you cannot" and "there is nothing" are different
// answers and a user acts differently on each, which is why
// browsesession.ErrForbidden exists at all.
func forbidden(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return browsesession.ErrForbidden
	}
	return err
}
