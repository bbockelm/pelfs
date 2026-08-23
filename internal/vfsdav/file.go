package vfsdav

import (
	"encoding/xml"
	"io"
	"io/fs"
	"os"
	"sync"
	"syscall"

	"github.com/go-git/go-billy/v5"
	"golang.org/x/net/webdav"
)

// webdav.File is http.File plus io.Writer, which is why Seek is MANDATORY
// and why Range requests work with no code here: handleGetHeadPost calls
// http.ServeContent (webdav.go), ServeContent parses Range and seeks, and
// billy's file already has Seek (internal/vfsbilly/file.go). This retires
// docs/design-guiclients.md's concern that go-billy's helper/iofs file does
// not implement io.Seeker — that path is not on this one. It is verified
// rather than assumed: TestRangeRequestsAreServedByteExact asks the handler
// for four ranges and compares bytes.
//
// davFile is one open handle on a non-directory. It holds no buffered
// state, because the layer below commits every Write before returning.
type davFile struct {
	fs   *FS
	name string
	h    billy.File
	// mayWrite is false for a read open and for the O_RDWR that PROPPATCH
	// makes (propsOnly). x/net never writes bytes through either.
	mayWrite bool
}

var (
	_ webdav.File            = (*davFile)(nil)
	_ webdav.DeadPropsHolder = (*davFile)(nil)
)

func (f *davFile) Read(p []byte) (int, error)                { return f.h.Read(p) }
func (f *davFile) Seek(off int64, whence int) (int64, error) { return f.h.Seek(off, whence) }
func (f *davFile) Close() error                              { return f.h.Close() }

func (f *davFile) Write(p []byte) (int, error) {
	if !f.mayWrite {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: syscall.EBADF}
	}
	return f.h.Write(p)
}

// Stat asks the layer below every time rather than caching what the open
// saw. handlePut stats AFTER io.Copy to build the ETag, and a cached
// FileInfo would answer with the length the file had before the body
// arrived — an ETag for a version that never existed.
func (f *davFile) Stat() (fs.FileInfo, error) { return f.fs.fs.Stat(f.name) }

func (f *davFile) Readdir(int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{Op: "readdir", Path: f.name, Err: syscall.ENOTDIR}
}

func (f *davFile) DeadProps() (map[xml.Name]webdav.Property, error) {
	return f.fs.props.get(f.name), nil
}

func (f *davFile) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	return f.fs.props.patch(f.name, patches, f.fs.writable)
}

// davDir is one open handle on a collection. There is no billy handle
// behind it: billy puts Readdir on the FILESYSTEM rather than on the file,
// so this holds a path and calls FS.readDir — which is also where the
// symlink and special-file policy lives (see the package comment).
type davDir struct {
	fs *FS
	// name is the path the client asked for; dir is where a terminal
	// symlink resolved to, and is what is actually listed.
	name string
	dir  string

	mu   sync.Mutex
	ents []fs.FileInfo
	pos  int
	read bool
}

var (
	_ webdav.File            = (*davDir)(nil)
	_ webdav.DeadPropsHolder = (*davDir)(nil)
)

func (d *davDir) Close() error { return nil }

func (d *davDir) Read([]byte) (int, error) {
	return 0, &os.PathError{Op: "read", Path: d.name, Err: syscall.EISDIR}
}

func (d *davDir) Write([]byte) (int, error) {
	return 0, &os.PathError{Op: "write", Path: d.name, Err: syscall.EISDIR}
}

// Seek on a directory: rewinding is the only meaningful form, and it is
// what os.File allows too. Nothing in x/net asks for anything else — a GET
// on a collection is answered 405 before ServeContent is reached.
func (d *davDir) Seek(off int64, whence int) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if off == 0 && whence == io.SeekStart {
		d.pos, d.read = 0, false
		return 0, nil
	}
	return 0, &os.PathError{Op: "seek", Path: d.name, Err: syscall.EISDIR}
}

func (d *davDir) Stat() (fs.FileInfo, error) { return d.fs.fs.Stat(d.name) }

// Readdir follows os.File's contract, which x/net depends on in two
// different ways: walkFS calls Readdir(0) and copyFiles calls Readdir(-1),
// both of which must return EVERYTHING, while a count > 0 pages and reports
// io.EOF at the end.
func (d *davDir) Readdir(count int) ([]fs.FileInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.read {
		ents, err := d.fs.readDir(d.dir)
		if err != nil {
			return nil, err
		}
		d.ents, d.read = ents, true
	}
	if d.pos >= len(d.ents) {
		if count > 0 {
			return nil, io.EOF
		}
		return nil, nil
	}
	old := d.pos
	if count > 0 {
		d.pos = min(d.pos+count, len(d.ents))
	} else {
		d.pos = len(d.ents)
	}
	return d.ents[old:d.pos], nil
}

func (d *davDir) DeadProps() (map[xml.Name]webdav.Property, error) {
	return d.fs.props.get(d.name), nil
}

func (d *davDir) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	return d.fs.props.patch(d.name, patches, d.fs.writable)
}
