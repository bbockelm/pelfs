package webapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
)

// UploadResult is one file an upload landed.
type UploadResult struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
	Type string `json:"type"`
}

// UploadField is the multipart field name the component sends the bytes in,
// and NameField is the optional override of the filename. Both are the
// contract's, read off the recorded upload and SVAR's reference handler.
const (
	UploadField = "file"
	NameField   = "name"
)

// maxFieldBytes bounds a non-file part. The only one this route uses is the
// name override, so anything large in a text field is a client bug or an
// attempt to spend our memory on a route that deliberately has no body cap.
const maxFieldBytes = 4 << 10

// Upload answers POST /api/v1/upload?id=<parent>: ONE whole-file multipart
// POST, which is all the component can send.
//
// # r.MultipartReader(), never r.ParseMultipartForm()
//
// This is the single most important implementation note in the design
// (docs/design-webui.md, "Upload: whole-file for now"), so it is stated at
// the code rather than only in the doc: ParseMultipartForm(n) buffers n bytes
// in memory and SPILLS THE REST TO A TEMP FILE, which for a 68 MB SIF means
// writing the payload to disk twice — once into the operating system's temp
// directory, once into the overlay — and doubles the peak footprint of the
// one operation this route exists for. MultipartReader streams each part
// straight into billyFS.OpenFile through a 32 KiB buffer, so the memory cost
// of a 68 MB upload and of a 68 byte upload are the same. TestStreamsRather
// ThanBuffers and TestNoParseMultipartFormAnywhere pin both halves.
//
// # The ceiling this route has, stated because a physicist will hit it
//
// The provider does one multipart POST via fetch [W4], so:
//
//   - NO RESUME. A dropped connection at 90% of a 68,497,408-byte SIF (this
//     repo's own reference size) starts over. SFTP's `reput` survives exactly
//     this; the browser does not, and U15 (tus + uppy) is the deferred work
//     item that fixes it.
//   - NO PROGRESS. fetch gives no upload progress events, so "did my 68 MB
//     file get anywhere" has no answer until the request finishes. What the
//     UI can show afterwards is the durability state, which is the part that
//     matters more.
//   - The PRACTICAL CEILING is therefore a function of link reliability
//     rather than of size: on loopback or a wired LAN a multi-gigabyte upload
//     is fine, and on a flaky link the largest file that reliably completes
//     is the largest one that fits in the gaps between drops. For the 68 MB
//     reference SIF on a link that drops every few minutes, that is a coin
//     toss, and the honest advice until U15 lands is the WebDAV endpoint,
//     where a real client's own resume works.
//
// # A partial upload must never appear under its final name
//
// Bytes land in <name>.pelfs-part and the final Rename happens only after the
// whole body has been read; an abandoned or failed upload unlinks it. That is
// a durability requirement and not a nicety: the bytes are in the overlay the
// moment they are written, and the next checkpoint would publish a truncated
// file under the name the user believes is theirs.
func (a *API) Upload(w http.ResponseWriter, r *http.Request) {
	dir, err := cleanPath(r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	bfs, err := a.mutable()
	if err != nil {
		writeErr(w, err)
		return
	}
	fi, err := bfs.Stat(dir)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !fi.IsDir() {
		writeErr(w, fmt.Errorf("%w: the upload target %s is not a directory", ErrBadRequest, dir))
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, fmt.Errorf("%w: this route takes multipart/form-data (%v)", ErrBadRequest, err))
		return
	}

	// The idle deadline. It is extended on every chunk that arrives (see
	// extendOnProgress), so a slow upload never dies of slowness and a
	// stalled one does not hold a connection and a .pelfs-part forever.
	// A ResponseWriter with no deadline support — httptest's recorder — says
	// so and is not an error: the deadline is a property of a real
	// connection.
	rc := http.NewResponseController(w)
	extend := func() {
		_ = rc.SetReadDeadline(time.Now().Add(a.uploadIdle))
	}
	extend()

	// staged holds every part file written so far. Nothing is renamed to its
	// final name until the whole body has been read, and anything still
	// staged when this handler returns by any path other than success is
	// removed.
	var staged []*stagedFile
	done := false
	defer func() {
		if done {
			return
		}
		for _, s := range staged {
			s.discard()
		}
	}()

	var override string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truncated or malformed body. The deferred cleanup above is
			// what makes this leave nothing behind.
			writeErr(w, fmt.Errorf("%w: reading the upload: %v", ErrBadRequest, err))
			return
		}
		name := part.FileName()
		if name == "" {
			// A plain form field. The only one in the contract is the
			// filename override.
			field := part.FormName()
			val, rerr := readField(part)
			_ = part.Close()
			if rerr != nil {
				writeErr(w, rerr)
				return
			}
			if field == NameField {
				override = val
			}
			continue
		}
		s, uerr := a.streamPart(bfs, dir, part, extend)
		_ = part.Close()
		if uerr != nil {
			writeErr(w, uerr)
			return
		}
		staged = append(staged, s)
	}
	if len(staged) == 0 {
		writeErr(w, fmt.Errorf("%w: no %q part in the upload", ErrBadRequest, UploadField))
		return
	}

	// The override applies to the first file, which is the only one it can
	// mean anything for: the field is singular in the contract and a browser
	// sends one file per request in the default flow.
	if override != "" {
		if err := validName(base(override)); err != nil {
			writeErr(w, err)
			return
		}
		staged[0].final = path.Join(dir, base(override))
	}

	var results []UploadResult
	for _, s := range staged {
		if err := s.commit(); err != nil {
			// Whatever committed already stays committed: those files are
			// whole and renaming them back would be a second operation that
			// can also fail. The client is told which one broke.
			writeErr(w, err)
			return
		}
		results = append(results, UploadResult{ID: s.final, Size: s.size, Type: TypeFile})
	}
	done = true

	// One file is the recorded shape ({"result":{...}}); several is the same
	// field as an array, because a client that sent N parts needs N answers
	// and inventing a separate route for it would be a second protocol.
	if len(results) == 1 {
		writeJSON(w, http.StatusOK, map[string]UploadResult{"result": results[0]})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]UploadResult{"result": results})
}

// streamPart copies one file part into the volume, through .pelfs-part.
func (a *API) streamPart(bfs billy.Filesystem, dir string, part *multipart.Part, extend func()) (*stagedFile, error) {
	name := base(part.FileName())
	if err := validName(name); err != nil {
		return nil, err
	}
	final := path.Join(dir, name)
	p, cleanup, err := createPart(bfs, final, 0o644)
	if err != nil {
		return nil, err
	}
	// ONE fixed buffer for the whole file. io.CopyBuffer uses it because
	// neither a multipart.Part nor internal/vfsbilly's file implements
	// WriteTo or ReadFrom, so nothing behind this call allocates per the
	// body's size.
	buf := make([]byte, uploadBufSize)
	n, err := io.CopyBuffer(p.dst, &progressReader{r: part, extend: extend}, buf)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("%w: the upload of %s did not finish: %v", ErrBadRequest, name, err)
	}
	if err := p.dst.Close(); err != nil {
		cleanup()
		return nil, err
	}
	return &stagedFile{bfs: bfs, part: p.name, final: final, size: n}, nil
}

// stagedFile is one uploaded file's bytes, written and not yet named.
type stagedFile struct {
	bfs   billy.Filesystem
	part  string
	final string
	size  int64
}

// commit is the rename that makes the file appear. It is the last thing that
// happens, deliberately.
func (s *stagedFile) commit() error {
	if err := s.bfs.Rename(s.part, s.final); err != nil {
		s.discard()
		return err
	}
	s.part = ""
	return nil
}

// discard unlinks an abandoned part file. A failure to unlink is not
// reported: the upload has already failed, the client is being told about
// that, and a leftover *.pelfs-part is visible as exactly what it is on both
// surfaces.
func (s *stagedFile) discard() {
	if s.part == "" {
		return
	}
	_ = s.bfs.Remove(s.part)
	s.part = ""
}

// partFile is an open .pelfs-part handle and the name it has.
type partFile struct {
	name string
	dst  billy.File
}

// createPart opens the temp file for final, with O_EXCL so that two uploads
// of the same name cannot write into one another's bytes. The collision
// answer is a random infix rather than a 409: two people dropping the same
// filename into one folder is ordinary, and the loser of the race gets the
// ordinary answer (the second rename wins) rather than an error about a
// temporary file they never asked for.
func createPart(bfs billy.Filesystem, final string, perm os.FileMode) (*partFile, func(), error) {
	name := final + PartSuffix
	f, err := bfs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if os.IsExist(err) {
		var buf [4]byte
		if _, rerr := rand.Read(buf[:]); rerr != nil {
			return nil, nil, rerr
		}
		name = final + "." + hex.EncodeToString(buf[:]) + PartSuffix
		f, err = bfs.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	}
	if err != nil {
		return nil, nil, err
	}
	p := &partFile{name: name, dst: f}
	cleanup := func() {
		_ = f.Close()
		_ = bfs.Remove(name)
	}
	return p, cleanup, nil
}

// progressReader extends the idle deadline while bytes are arriving, at most
// once a second: the deadline has to be pushed forward often enough that a
// slow transfer survives, and rarely enough that a 68 MB upload does not
// reset a timer two thousand times.
type progressReader struct {
	r      io.Reader
	extend func()
	last   time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.extend != nil {
		if now := time.Now(); now.Sub(p.last) > time.Second {
			p.last = now
			p.extend()
		}
	}
	return n, err
}

// readField reads one small form field, refusing a large one rather than
// growing to fit it.
func readField(part *multipart.Part) (string, error) {
	b, err := io.ReadAll(io.LimitReader(part, maxFieldBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: reading the %q field: %v", ErrBadRequest, part.FormName(), err)
	}
	if len(b) > maxFieldBytes {
		return "", fmt.Errorf("%w: the %q field is larger than %d bytes", ErrBadRequest, part.FormName(), maxFieldBytes)
	}
	return string(b), nil
}

// base reduces a client-supplied filename to one component. A browser sends
// a bare basename, but a crafted request can send anything, and a filename
// carrying "../" would write outside the directory the id named — the one
// place this route could be talked into touching a path the client did not
// ask for. Backslashes are separators too, because a Windows client's
// "C:\\Users\\x\\f.dat" is one component to path.Base and three to a person.
func base(name string) string {
	return path.Base(strings.ReplaceAll(name, `\`, "/"))
}
