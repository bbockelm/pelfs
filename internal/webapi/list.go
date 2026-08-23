package webapi

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-billy/v5"
)

// Entry is one row of a listing, in the shape the component takes: a FLAT
// list of full paths, not a nested tree (docs/design-webui.md, Verification
// 3). `id` is the whole path and `type` is "folder" or "file".
type Entry struct {
	// ID is the full volume path, UNESCAPED. The component escapes it
	// itself when it puts it back in a URL, which is why a name containing
	// "%2F" survives the round trip.
	ID string `json:"id"`
	// Type is "folder" or "file". There is no third value: everything a
	// volume holds that is neither is hidden and counted (see Counts).
	Type string `json:"type"`
	// Size is bytes, for a file. Omitted for a folder, whose "size" would
	// be a property of the directory object and not of what is in it.
	Size int64 `json:"size,omitempty"`
	// Date is the modification time, RFC 3339. The component feeds it to
	// `new Date(...)`.
	Date string `json:"date,omitempty"`
	// Lazy marks a folder whose contents have not been sent. IT IS WHAT
	// MAKES THE TREE LOAD AT ALL: the store emits `request-data` only for a
	// folder marked lazy, so a folder sent without it is a folder the
	// component believes it already has (empty).
	Lazy bool `json:"lazy,omitempty"`
}

const (
	// TypeFolder and TypeFile are the component's own two words.
	TypeFolder = "folder"
	TypeFile   = "file"
)

// Listing response headers. They carry the truth a bare JSON array cannot:
// the component's provider hands `loadFiles` the parsed body and nothing
// else, so the array must BE the array — the numbers travel beside it, and
// GET /api/v1/info/{id} serves the same numbers to a caller that cannot read
// headers.
const (
	HeaderReturned  = "X-Pelfs-Listing-Returned"
	HeaderTotal     = "X-Pelfs-Listing-Total"
	HeaderCap       = "X-Pelfs-Listing-Cap"
	HeaderTruncated = "X-Pelfs-Listing-Truncated"
	HeaderHidden    = "X-Pelfs-Listing-Hidden"
)

// listing is one directory as this surface may present it.
type listing struct {
	// id is the directory's own path.
	id string
	// entries is what is being returned: at most cap of them, in name
	// order.
	entries []Entry
	// total is how many entries the directory has that this surface CAN
	// represent — the number the cap is measured against, and the number
	// the UI must show beside it.
	total int
	// hidden is what was left out because no client could render it.
	hidden Counts
}

func (l *listing) truncated() bool { return l.total > len(l.entries) }

// maxSymlinkHops bounds a chain, as internal/vfsdav and the layer below do.
const maxSymlinkHops = 8

// build lists one directory.
//
// The symlink policy is internal/vfsdav's, deliberately identical so that
// the two surfaces do not disagree about what a volume contains:
//
//   - a link to a REGULAR FILE is FOLLOWED and presented under the link's
//     own name, so `lib.so -> lib.so.1` is the file it names rather than an
//     empty one;
//   - a link to a DIRECTORY is hidden and counted, because path resolution
//     below is component-by-component and does not traverse a symlinked
//     directory, so listing it as a folder would promise a navigation that
//     then fails;
//   - a DANGLING link is hidden and counted;
//   - fifos, sockets and device nodes are hidden and counted, having no
//     representation a file manager could render.
//
// Hiding without counting would be the one unacceptable option: the tree
// would simply look smaller than it is.
func (a *API) build(bfs billy.Filesystem, dir string) (*listing, error) {
	// Stat first, so that "this is a file, not a directory" is a distinct
	// answer from an empty listing. ReadDir on a file answers ENOTDIR from
	// the layer below, which would become a 500.
	fi, err := bfs.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, &fs.PathError{Op: "list", Path: dir, Err: fs.ErrInvalid}
	}
	ents, err := bfs.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	l := &listing{id: dir}
	for _, e := range ents {
		switch e.Name() {
		case ".", "..":
			continue
		}
		full := path.Join(dir, e.Name())
		m := e.Mode()
		switch {
		case m&os.ModeSymlink != 0:
			_, target, err := follow(bfs, full)
			if err != nil {
				l.hidden.DanglingSymlinks++
				continue
			}
			if target.IsDir() {
				l.hidden.DirectorySymlinks++
				continue
			}
			// The TARGET's size and time under the LINK's name: the bytes a
			// download will serve are the target's, and the name the user
			// clicked is the link's.
			l.keep(a.cap, Entry{
				ID: full, Type: TypeFile,
				Size: target.Size(), Date: stamp(target.ModTime()),
			})
		case m.IsDir():
			l.keep(a.cap, Entry{ID: full, Type: TypeFolder, Date: stamp(e.ModTime()), Lazy: true})
		case m.IsRegular():
			l.keep(a.cap, Entry{ID: full, Type: TypeFile, Size: e.Size(), Date: stamp(e.ModTime())})
		default:
			l.hidden.SpecialFiles++
		}
	}
	a.hidden.add(l.hidden)
	return l, nil
}

// keep counts an entry and appends it while there is room. The cap takes the
// FIRST cap entries in name order (which is the order the layer below
// returns), so a capped listing is deterministic and re-listing the same
// directory shows the same rows — a cap that returned an arbitrary subset
// would make "narrow the path" impossible to act on.
func (l *listing) keep(limit int, e Entry) {
	l.total++
	if len(l.entries) < limit {
		l.entries = append(l.entries, e)
	}
}

// follow resolves a terminal symlink chain and returns BOTH the path it ends
// at and that path's attributes. Only the last component is followed, for the
// reason build's comment gives.
//
// The path is returned, and not only the FileInfo, because a caller that
// wants the BYTES has to open the target and not the link: an open of the
// link inode answers ESTALE on the first read, which is how a copy of a
// symlink fails if it reaches for the name the user clicked.
func follow(bfs billy.Filesystem, p string) (string, os.FileInfo, error) {
	type lstatter interface {
		Lstat(string) (os.FileInfo, error)
	}
	type readlinker interface {
		Readlink(string) (string, error)
	}
	lst, hasLstat := bfs.(lstatter)
	rl, hasReadlink := bfs.(readlinker)
	if !hasLstat || !hasReadlink {
		// A filesystem with no symlink half cannot have handed us one.
		fi, err := bfs.Stat(p)
		return p, fi, err
	}
	for hop := 0; ; hop++ {
		fi, err := lst.Lstat(p)
		if err != nil {
			return p, nil, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return p, fi, nil
		}
		if hop == maxSymlinkHops {
			return p, nil, &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
		}
		t, err := rl.Readlink(p)
		if err != nil {
			return p, nil, err
		}
		if strings.HasPrefix(t, "/") {
			// Rooted at the VOLUME, not the host: there is no host path a
			// link in a pelfs volume can name.
			p = path.Clean(t)
		} else {
			p = path.Clean(path.Join(path.Dir(p), t))
		}
	}
}

// stamp renders a modification time for the component. UTC and RFC 3339,
// which `new Date(...)` parses unambiguously; a local-time string without an
// offset would be read as the BROWSER's local time and be wrong by the
// difference.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ListRoot answers GET /api/v1/files: THE ROOT DIRECTORY, not the tree.
//
// The un-pathed form is what the component fetches at boot, and SVAR's own
// reference server answers it with the whole tree. That is the shape a pelfs
// volume cannot have — 62,500 files is proven in this repo's CI and the
// format's constraint is at millions — so here it means "the root directory",
// exactly as GET /api/v1/files/%2F would. docs/design-webui.md says this
// route is dropped in favour of the {path} form only; the recording says the
// component fetches it at boot regardless, so it is kept and narrowed.
func (a *API) ListRoot(w http.ResponseWriter, r *http.Request) {
	a.list(w, r, "/")
}

// List answers GET /api/v1/files/{id}: one directory, capped.
func (a *API) List(w http.ResponseWriter, r *http.Request) {
	id, err := idOf(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	a.list(w, r, id)
}

func (a *API) list(w http.ResponseWriter, _ *http.Request, dir string) {
	l, err := a.listing(dir)
	if err != nil {
		writeErr(w, err)
		return
	}
	h := w.Header()
	h.Set(HeaderReturned, strconv.Itoa(len(l.entries)))
	h.Set(HeaderTotal, strconv.Itoa(l.total))
	h.Set(HeaderCap, strconv.Itoa(a.cap))
	h.Set(HeaderTruncated, strconv.FormatBool(l.truncated()))
	h.Set(HeaderHidden, strconv.FormatInt(l.hidden.Total(), 10))
	// A bare ARRAY, never an object: the provider hands the parsed body
	// straight to the store. And never JSON null for an empty directory,
	// which the store would iterate over.
	//
	// The empty-slice fix lands on a LOCAL, because the listing is shared by
	// pointer with whoever else was waiting on the same in-flight call and
	// writing to it here would be a data race between two responses.
	ents := l.entries
	if ents == nil {
		ents = []Entry{}
	}
	writeJSON(w, http.StatusOK, ents)
}

// listing is build behind the single-flight, which is fact 2 of the package
// comment: one navigation makes the store emit `request-data` twice, so two
// identical listings arrive concurrently and one readdir answers both. It is
// NOT a cache — there is no TTL and nothing is retained — because the
// breadcrumb refresh button exists precisely to re-list a directory, and a
// cache would break the one gesture whose entire purpose is a fresh answer.
func (a *API) listing(dir string) (*listing, error) {
	bfs, err := a.volume()
	if err != nil {
		return nil, err
	}
	return a.inflight.do(dir, func() (*listing, error) { return a.build(bfs, dir) })
}

// InfoResponse is GET /api/v1/info/{id}: everything the listing could not
// say, because the listing has to be a bare array.
//
// This is where the cap becomes visible to a user. The component's search box
// filters LOADED DATA ONLY and issues no request, so a capped listing is a
// partial search — and the UI must say so rather than implying the whole
// volume was looked at. Notice is the sentence to show, rendered here so
// that every surface shows the same words.
type InfoResponse struct {
	// ID is the directory this describes.
	ID string `json:"id"`
	// Entries is the true number of entries in it that this surface can
	// represent.
	Entries int `json:"entries"`
	// Returned is how many a listing of it would carry.
	Returned int `json:"returned"`
	// Cap is the listing cap in force.
	Cap int `json:"cap"`
	// Truncated is Entries > Returned.
	Truncated bool `json:"truncated"`
	// Hidden is what no client could render, broken down.
	Hidden Counts `json:"hidden"`
	// Notice is the sentence to show the user when Truncated, and "" when
	// it is not. See PartialSearchNotice.
	Notice string `json:"notice,omitempty"`
	// HiddenNotice is the sentence for entries this surface cannot
	// represent, and "" when there are none.
	HiddenNotice string `json:"hidden_notice,omitempty"`
	// Mode is "read-only" or "read-write", so a UI can grey out what it
	// must not offer instead of offering it and collecting a 403.
	Mode string `json:"mode"`
}

// Info answers GET /api/v1/info/{id}.
func (a *API) Info(w http.ResponseWriter, r *http.Request) {
	id, err := idOf(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	bfs, err := a.volume()
	if err != nil {
		writeErr(w, err)
		return
	}
	l, err := a.listing(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	mode := "read-only"
	if writable(bfs) {
		mode = "read-write"
	}
	resp := InfoResponse{
		ID: l.id, Entries: l.total, Returned: len(l.entries), Cap: a.cap,
		Truncated: l.truncated(), Hidden: l.hidden, Mode: mode,
	}
	if resp.Truncated {
		resp.Notice = PartialSearchNotice(resp.Returned, resp.Entries)
	}
	if l.hidden.Any() {
		resp.HiddenNotice = HiddenNotice(l.hidden)
	}
	writeJSON(w, http.StatusOK, resp)
}

// PartialSearchNotice is THE sentence a capped listing owes the user, and it
// lives here so that there is exactly one wording of it.
//
// Two facts have to be in it, because a user who knows only one of them will
// draw a false conclusion from the other. The first is the cap itself
// (docs/design-webui.md: "showing 5,000 of 412,006 — narrow the path or use
// the WebDAV endpoint"). The second is the consequence the design doc's own
// sentence does not state: the component's search is client-side over loaded
// data, so in a capped folder the search box is searching the 5,000 rows and
// not the folder. Without that clause a user who searches and finds nothing
// concludes the file is not there.
func PartialSearchNotice(returned, total int) string {
	return fmt.Sprintf("Showing %s of %s entries in this folder. "+
		"Search matches only what is loaded, so it is searching these %s rows and not the whole folder — "+
		"narrow the path, or use the WebDAV endpoint to see all of it.",
		comma(returned), comma(total), comma(returned))
}

// HiddenNotice is the sentence for entries this surface cannot represent.
func HiddenNotice(c Counts) string {
	var parts []string
	add := func(n int64, one, many string) {
		switch {
		case n == 1:
			parts = append(parts, "1 "+one)
		case n > 1:
			parts = append(parts, comma(int(n))+" "+many)
		}
	}
	add(c.DirectorySymlinks, "symbolic link to a directory", "symbolic links to directories")
	add(c.DanglingSymlinks, "broken symbolic link", "broken symbolic links")
	add(c.SpecialFiles, "special file (a device, socket or fifo)", "special files (devices, sockets, fifos)")
	if len(parts) == 0 {
		return ""
	}
	what := "entry is"
	if c.Total() > 1 {
		what = "entries are"
	}
	return fmt.Sprintf("%s %s not shown here: %s. They are in the volume and visible over the WebDAV endpoint.",
		comma(int(c.Total())), what, strings.Join(parts, ", "))
}

// comma groups an integer with thousands separators, because "412006" in a
// sentence a person reads is a number they have to count the digits of.
func comma(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The in-flight guard
// ---------------------------------------------------------------------------

// flight collapses concurrent identical listings into one.
//
// It is thirty lines rather than golang.org/x/sync/singleflight because that
// module is an indirect dependency today and this is the only caller: the
// whole behaviour is "the second arrival waits for the first", and the
// interesting part is that nothing is retained afterwards.
type flight struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	res *listing
	err error
}

func newFlight() *flight { return &flight{calls: map[string]*flightCall{}} }

// do runs fn for key, or waits for the fn already running for it. The result
// is shared by pointer and must be treated as READ-ONLY by every caller: two
// responses can be rendering the same listing at the same instant, so a
// handler that adjusted a field on it would be racing itself.
func (f *flight) do(key string, fn func() (*listing, error)) (*listing, error) {
	f.mu.Lock()
	if c, ok := f.calls[key]; ok {
		f.mu.Unlock()
		c.wg.Wait()
		return c.res, c.err
	}
	c := &flightCall{}
	c.wg.Add(1)
	f.calls[key] = c
	f.mu.Unlock()

	// The call is not deferred-unlocked around fn: a readdir of a large
	// directory is the thing being shared, and holding f.mu across it would
	// serialize every other directory too.
	c.res, c.err = fn()
	c.wg.Done()

	f.mu.Lock()
	delete(f.calls, key)
	f.mu.Unlock()
	return c.res, c.err
}
