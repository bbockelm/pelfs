// Package webapi is the JSON data plane of `pelfs browse`: work item U11 of
// docs/design-webui.md. It answers the SVAR file manager's REST contract
// under /api/v1 over internal/vfsbilly, which is the same volume, the same
// namespace and the same permission model every other frontend sees.
//
// # It implements an observed protocol, not an invented one
//
// The contract is the one the real @svar-ui/react-filemanager speaks,
// recorded from the component itself by work item U0 and committed as
// internal/webui/testdata/svar-contract/recording.json. contract_test.go in
// this package REPLAYS that recording against these handlers, so a component
// upgrade that changes the wire shape fails here rather than in a browser.
// SVAR's own Go reference server was read and not copied: it has no licence
// file, so it is all-rights-reserved, and a route contract is a protocol
// (docs/design-webui.md, Verification 3).
//
// Eight routes, which is the eleven-pattern contract minus what the threat
// model replaces and what M3 drops (each id route is registered twice, for
// the reason Routes gives):
//
//	GET    /api/v1/files            the ROOT directory, not the whole tree
//	GET    /api/v1/files/{id}       one directory, capped
//	GET    /api/v1/info/{id}        what that directory's listing did NOT say
//	POST   /api/v1/files/{id}       mkdir / touch inside {id}
//	PUT    /api/v1/files/{id}       rename
//	PUT    /api/v1/files            batch move or copy, PER-ID results
//	DELETE /api/v1/files            batch delete, PER-ID results
//	POST   /api/v1/upload?id={dir}  one whole-file multipart upload
//
// GET /direct is replaced by /d/<ticket> (browsesession.DownloadHandler over
// the Source this package returns), because a download must not be an
// ambient-credential GET. GET /preview and GET /icons/{size}/{name} are
// dropped: rendering user content from this origin is the stored-XSS problem.
// GET /api/v1/info (no id) is the durability panel and belongs to the browse
// server, which already serves it.
//
// # Four facts from the probe that the code is shaped by
//
//  1. THE COMPONENT LAZY-LOADS, one directory per navigation, and caches a
//     loaded directory for the life of the page. So a listing is a
//     per-directory answer and never a tree walk, and every folder entry
//     carries `lazy: true` — the store only emits `request-data` for a
//     folder marked lazy, so without it the tree never loads.
//  2. THE STORE FIRES `request-data` TWICE for one navigation. The provider
//     has an in-flight guard; this side has one too (listings are
//     single-flighted by path), because a 100k-entry directory listed twice
//     per navigation is two full readdirs and the guard on the far side is
//     not ours to depend on.
//  3. IT DOES NOT VIRTUALIZE. 100,000 entries measured 1,000,067 DOM nodes
//     and 703 MB of heap (internal/webui/testdata/svar-contract/
//     u0-measurements.json). So the response cap is the design and not a
//     fallback — Cap entries, in name order, deterministically.
//  4. SEARCH IS CLIENT-SIDE over loaded data only. Therefore a capped
//     listing is also a PARTIAL SEARCH, and the user has to be told: every
//     listing carries the true count in headers, GET /api/v1/info/{id}
//     returns it as JSON along with the exact sentence to display, and
//     Notice is that sentence's only source so that no surface has to
//     re-word it.
//
// # What it must never do
//
// Invent an operation internal/vfsbilly cannot express (docs/design-webui.md,
// "What the JSON surface owes WebDAV"). A batch move is N sequential renames
// with N results, because there is no atomic N-way rename in the overlay, in
// WebDAV or in POSIX — and a surface that answered "moved" for a batch whose
// fourth rename hit EACCES would be lying in the one place the user cannot
// check.
//
// # The permission model is the one everybody else uses
//
// internal/fsperm, through internal/vfsbilly, and nothing here re-decides it:
// a refusal arrives as EACCES/EPERM from the layer below and becomes a 403.
// The binding MUST be built with vfsbilly.OpenAnsweredHere — an HTTP handler
// has a real open, so that check is the only open check there is. NewVolume
// below is the constructor that gets it right; a call-site test in
// internal/vfsbilly fails any caller that reaches for the NFS ones.
package webapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// DefaultCap is how many entries one listing may contain.
//
// 5,000 is the design's number and it has two independent justifications:
// it is what scripts/sftp-clients-docker.sh already proves a real client
// handles (`dir-5000: ok`), and it is two orders of magnitude below the
// measured cliff — the component built 1,000,067 DOM nodes and 703 MB of
// heap for 100,000 entries, and it windows nothing. A cap the user is told
// about is a limitation; an unbounded response that hangs the tab is a
// defect.
const DefaultCap = 5000

// PartSuffix is the temp-name-then-rename convention, shared with the
// WebDAV surface (docs/design-guiclients.md, docs/design-webui.md).
//
// It is a DURABILITY requirement rather than a compatibility one: a browser
// upload that dies at 90% leaves bytes in the overlay, and the next
// checkpoint would publish a truncated file under its final name. So bytes
// land under <name>.pelfs-part, the name appears only on a completed
// Rename, and an abandoned upload is unlinked. The same convention makes the
// two surfaces legible to each other — a *.pelfs-part visible over WebDAV is
// obviously an upload in flight, as a WinSCP *.filepart is here.
const PartSuffix = ".pelfs-part"

// uploadBufSize is the streaming buffer for one upload, and it is the whole
// memory cost of a 68 MB file: the body is copied part-to-file in these
// chunks and never assembled. See Upload for why ParseMultipartForm is
// forbidden rather than merely discouraged.
const uploadBufSize = 32 << 10

// DefaultUploadIdle is how long an upload may make NO progress before the
// server gives up on it.
//
// It is an IDLE deadline, not a total one, and that distinction is the
// design: a whole-file upload of a 68 MB SIF on a slow link is a legitimate
// minutes-long request, so a total deadline would kill exactly the transfer
// this route exists for, while an unbounded one leaks a connection and a
// .pelfs-part per stalled tab. The deadline is extended on every chunk that
// arrives, so progress — however slow — is never the thing that fails.
const DefaultUploadIdle = 2 * time.Minute

// MaxNameLen bounds a single path component, as every filesystem pelfs
// stages onto does.
const MaxNameLen = 255

// ErrNotReady is a volume that is not open yet. `pelfs browse` serves the
// page before the volume is mounted (the phase the connection panel calls
// "connecting"), so the honest answer for that window is 503 and not an
// empty directory: an empty listing is a statement about the volume, and we
// do not have one to make.
var ErrNotReady = errors.New("the volume is still opening")

// ErrBadRequest is anything malformed in the request itself: a body that is
// not JSON, a name with a slash in it, an unknown operation.
var ErrBadRequest = errors.New("bad request")

// ErrReadOnly is a mutation asked of a read-only session.
//
// It wraps fs.ErrPermission so it is a 403 like any other refusal, but it is
// its own sentinel because the two refusals need different sentences: "the
// mode bits say no on this path" is actionable (chmod it, or ask whoever owns
// it), and "this whole session cannot write" is a different action entirely
// (restart with --rw). Answering the second with the first sends the user to
// look at a file that is fine.
var ErrReadOnly = fmt.Errorf("%w: read-only session", fs.ErrPermission)

// VolumeFunc supplies the live volume, or ErrNotReady while there is none.
//
// A function rather than a field because the browse server exists BEFORE the
// volume does and its route table is built at that moment; an API holding a
// nil billy.Filesystem would have to answer for it on every request anyway,
// and this way the answer is in one place.
type VolumeFunc func() (billy.Filesystem, error)

// Static is a VolumeFunc for a volume that is already open.
func Static(bfs billy.Filesystem) VolumeFunc {
	return func() (billy.Filesystem, error) {
		if bfs == nil {
			return nil, ErrNotReady
		}
		return bfs, nil
	}
}

// NewVolume is the binding this surface must be built with, and it exists so
// that no caller has to remember why.
//
// vfsbilly.New/NewAs carry NFS's owner override (OpenAnsweredByClient),
// which lets a file's owner write it whatever the mode says — justified for
// NFSv3, where the client already answered open(2) from our ACCESS reply,
// and indefensible here, where this check IS the open check. A JSON PUT that
// truncated a 0444 file the kernel, FUSE and the NFS ACCESS reply all refuse
// would be the same bug internal/vfsbilly's owneroverride_test.go was
// written to catch.
//
// A READ-ONLY SESSION HAS NO OVERLAY — `pelfs browse` without --rw leaves
// genSession.ov nil — so it is not this constructor's case. Build that one
// as
//
//	vfsbilly.NewReadOnlyFor(g.gfs, cred, vfsbilly.OpenAnsweredHere)
//
// which is the same semantics over the published generation, and which this
// package does not wrap only because there is no *genfs.FS to test such a
// wrapper against without exporting one from internal/testvol. Everything
// downstream of the binding is identical: writable() asks billy whether the
// filesystem has the write capability, and a read-only one refuses every
// mutation with ErrReadOnly before it reaches the volume.
func NewVolume(ov *overlay.FS, cred vfsbilly.Cred) billy.Filesystem {
	return vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere)
}

// Config is what an API needs.
type Config struct {
	// Volume supplies the live volume. Required.
	Volume VolumeFunc
	// Prefix is the URL prefix, without a trailing slash. "" means
	// "/api/v1", which is what the component's provider is built with.
	Prefix string
	// Cap bounds one listing; 0 means DefaultCap. A negative value is
	// rejected rather than read as "unlimited", because "unlimited" is the
	// defect the cap exists to prevent.
	Cap int
	// UploadIdle overrides DefaultUploadIdle.
	UploadIdle time.Duration
}

// API is the handler set. Immutable after New and safe for concurrent use.
type API struct {
	vol        VolumeFunc
	prefix     string
	cap        int
	uploadIdle time.Duration

	// inflight single-flights listings by path: see fact 2 in the package
	// comment.
	inflight *flight

	// hidden counts what listings could not represent, cumulatively, in the
	// shape internal/vfsdav reports it — so a status line can say the same
	// number about either surface.
	hidden hiddenCounts
}

// New builds the API.
func New(cfg Config) (*API, error) {
	if cfg.Volume == nil {
		return nil, errors.New("webapi: Config.Volume is required")
	}
	if cfg.Cap < 0 {
		return nil, fmt.Errorf("webapi: Cap %d is negative; there is no unlimited listing", cfg.Cap)
	}
	if cfg.UploadIdle < 0 {
		return nil, fmt.Errorf("webapi: UploadIdle %s is negative", cfg.UploadIdle)
	}
	a := &API{
		vol:        cfg.Volume,
		prefix:     strings.TrimSuffix(cfg.Prefix, "/"),
		cap:        cfg.Cap,
		uploadIdle: cfg.UploadIdle,
		inflight:   newFlight(),
	}
	if a.prefix == "" {
		a.prefix = "/api/v1"
	}
	if a.cap == 0 {
		a.cap = DefaultCap
	}
	if a.uploadIdle == 0 {
		a.uploadIdle = DefaultUploadIdle
	}
	return a, nil
}

// Cap is the listing cap in force, for a caller that wants to report it.
func (a *API) Cap() int { return a.cap }

// Route is one mount: the surface names the principal, which is the one
// decision a contributor cannot skip (internal/httpguard).
type Route struct {
	Surface httpguard.Surface
	Pattern string
	Handler http.Handler
}

// Routes is the whole route table, in the order it is documented.
//
// # Why every id route is registered twice
//
// The component sends the id as a full path percent-encoded into ONE segment
// (/api/v1/files/%2Fdir-0%2Fdir-1). ServeMux matches that as a single segment
// and PathValue returns it decoded exactly once, which is what makes both the
// ordinary case and a filename containing the literal characters "%2F" work;
// r.URL.Path, by contrast, has already collapsed the %2F into a real slash
// and is unusable for the id. So {id} is the contract.
//
// It has one hole, found by probing net/http rather than by reading it: a
// segment that is EXACTLY "%2F" — the volume root as an id — does not match a
// {id} wildcard at all. Unescaped it is a trailing empty segment, and the
// matcher answers 404. The component reaches the root listing through the
// un-pathed form so it never notices, but "create a folder in the root" is
// POST /api/v1/files/%2F and would 404 for the same reason.
//
// The {id...} sibling closes it. It is strictly less specific, so it takes
// nothing away from {id} — it catches the bare "%2F" (PathValue gives "/")
// and, as a bonus, the unescaped form a person types at a terminal
// (/api/v1/files/dir/sub). cleanPath makes both safe.
func (a *API) Routes() []Route {
	h := func(f func(http.ResponseWriter, *http.Request)) http.Handler { return http.HandlerFunc(f) }
	return []Route{
		{httpguard.SurfaceAPI, "GET " + a.prefix + "/files", h(a.ListRoot)},
		{httpguard.SurfaceAPI, "GET " + a.prefix + "/files/{id}", h(a.List)},
		{httpguard.SurfaceAPI, "GET " + a.prefix + "/files/{id...}", h(a.List)},
		{httpguard.SurfaceAPI, "GET " + a.prefix + "/info/{id}", h(a.Info)},
		{httpguard.SurfaceAPI, "GET " + a.prefix + "/info/{id...}", h(a.Info)},
		{httpguard.SurfaceAPI, "POST " + a.prefix + "/files/{id}", h(a.NewFile)},
		{httpguard.SurfaceAPI, "POST " + a.prefix + "/files/{id...}", h(a.NewFile)},
		{httpguard.SurfaceAPI, "PUT " + a.prefix + "/files/{id}", h(a.Rename)},
		{httpguard.SurfaceAPI, "PUT " + a.prefix + "/files/{id...}", h(a.Rename)},
		{httpguard.SurfaceAPI, "PUT " + a.prefix + "/files", h(a.Batch)},
		{httpguard.SurfaceAPI, "DELETE " + a.prefix + "/files", h(a.Delete)},
		// The upload is the one route on SurfaceUpload: multipart instead of
		// JSON and no body cap, because the cap is the point of failure on a
		// 68 MB upload. multipart/form-data IS CORS-safelisted, so here the
		// preflight trigger is the session header alone — which is why that
		// header is required on every surface that mutates and must not be
		// relaxed on this one.
		{httpguard.SurfaceUpload, "POST " + a.prefix + "/upload", h(a.Upload)},
	}
}

// Register mounts every route on a guarded router.
func (a *API) Register(r *httpguard.Router) {
	for _, rt := range a.Routes() {
		r.Handle(rt.Surface, rt.Pattern, rt.Handler)
	}
}

// volume resolves the live volume for one request.
func (a *API) volume() (billy.Filesystem, error) {
	bfs, err := a.vol()
	if err != nil {
		return nil, err
	}
	if bfs == nil {
		return nil, ErrNotReady
	}
	return bfs, nil
}

// writable reports whether this session may mutate. It is billy's own
// answer, so a read-only `pelfs browse` refuses a write here for the same
// reason and with the same error it refuses one over WebDAV.
func writable(bfs billy.Filesystem) bool {
	return billy.CapabilityCheck(bfs, billy.WriteCapability)
}

// idOf reads the id the component sent, from PathValue and nowhere else.
//
// The id is a full volume path, percent-encoded into one path segment.
// PathValue has already decoded exactly one layer, which is the whole
// subtlety: a file whose NAME contains the three characters "%2F" arrives
// double-encoded (%252F) and comes back out of PathValue as the literal
// "%2F" it always was. Decoding again here would turn that name into a
// directory separator and the request into a traversal — so this function
// decodes nothing.
func idOf(r *http.Request) (string, error) {
	return cleanPath(r.PathValue("id"))
}

// cleanPath normalizes a volume path: rooted, cleaned, no NUL. path.Clean
// resolves any ".." before it can mean anything, so "/../etc/passwd" is
// "/etc/passwd" INSIDE the volume — there is no host path a request here can
// name, which is the same property internal/vfsdav relies on.
func cleanPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: a path may not contain NUL", ErrBadRequest)
	}
	if p == "" {
		return "/", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p), nil
}

// validName checks one path COMPONENT — the "name" field of a create or a
// rename. A name is not a path: a slash in it would move the object
// somewhere the client did not say, and the batch move route is the one that
// takes a target.
func validName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: an empty name", ErrBadRequest)
	case name == "." || name == "..":
		return fmt.Errorf("%w: %q is not a name", ErrBadRequest, name)
	case strings.ContainsAny(name, "/\x00"):
		return fmt.Errorf("%w: %q contains a path separator or NUL; a name is one component", ErrBadRequest, name)
	case len(name) > MaxNameLen:
		return fmt.Errorf("%w: a name may not exceed %d bytes", ErrBadRequest, MaxNameLen)
	}
	return nil
}

// decodeJSON reads a small JSON body. The guard has already capped it at
// httpguard.APIBodyLimit and required application/json; this refuses unknown
// fields so that a client sending an operation we do not implement is told
// so instead of having it silently ignored.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	// Exactly one document, so a body with a second one appended cannot
	// smuggle anything past a handler that stopped reading.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: expected exactly one JSON document", ErrBadRequest)
	}
	return nil
}

// statusFor maps one error to the status the UI acts on.
//
// The sentinels are io/fs's rather than syscall's so that this is one
// mapping on every platform: internal/vfsbilly answers with
// *os.PathError{Err: syscall.EACCES|EPERM|ENOENT|EEXIST}, and syscall.Errno
// already reports those as fs.ErrPermission / fs.ErrNotExist / fs.ErrExist.
func statusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrNotReady):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, fs.ErrPermission):
		return http.StatusForbidden
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, fs.ErrExist):
		return http.StatusConflict
	case errors.Is(err, fs.ErrInvalid):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// writeJSON is the one place a response body is written.
func writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// A marshalling failure cannot be answered with the thing that
		// failed to marshal.
		http.Error(w, `{"error":"cannot render this response"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeErr answers one refusal. The message is written for a person: a file
// manager's user sees it, so "permission denied" beats "EACCES" and a path
// in it is a path they typed.
func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, statusFor(err), map[string]string{"error": errText(err)})
}

// errText renders an error for a user. An *os.PathError's Op is a syscall
// name and means nothing to anybody reading a browser, so the sentinel
// cases get sentences.
func errText(err error) string {
	switch {
	case errors.Is(err, ErrNotReady):
		return "the volume is still opening; try again in a moment"
	case errors.Is(err, ErrReadOnly):
		return "this session is read-only: restart `pelfs browse` with --rw to change anything"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied: " + pathOf(err)
	case errors.Is(err, fs.ErrNotExist):
		return "no such file or directory: " + pathOf(err)
	case errors.Is(err, fs.ErrExist):
		return "already exists: " + pathOf(err)
	}
	return err.Error()
}

// pathOf digs the path out of an *os.PathError, or falls back to the whole
// message. It never reports a host path: every path in this package is a
// volume path.
func pathOf(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Path
	}
	return err.Error()
}

// hiddenCounts is what listings hid, cumulatively. Occurrences rather than
// distinct entries, exactly as internal/vfsdav counts them: remembering
// every path ever listed is a leak on a volume of millions, and the number
// answers "is anything being hidden here" rather than "how many things
// exist".
type hiddenCounts struct {
	mu       sync.Mutex
	dangling int64
	dirLinks int64
	special  int64
}

// Counts is what a listing could not represent.
type Counts struct {
	// DanglingSymlinks is links whose target does not resolve.
	DanglingSymlinks int64 `json:"dangling_symlinks"`
	// DirectorySymlinks is links to directories, which are hidden because
	// the layer below cannot traverse a symlinked directory component.
	DirectorySymlinks int64 `json:"directory_symlinks"`
	// SpecialFiles is fifos, sockets and device nodes.
	SpecialFiles int64 `json:"special_files"`
}

// Any reports whether anything was hidden at all.
func (c Counts) Any() bool { return c.Total() > 0 }

// Total is how many entries were hidden.
func (c Counts) Total() int64 {
	return c.DanglingSymlinks + c.DirectorySymlinks + c.SpecialFiles
}

func (h *hiddenCounts) add(c Counts) {
	h.mu.Lock()
	h.dangling += c.DanglingSymlinks
	h.dirLinks += c.DirectorySymlinks
	h.special += c.SpecialFiles
	h.mu.Unlock()
}

// Counts reports what every listing so far hid from the UI. A mount summary
// should say the number out loud rather than let a tree look smaller than it
// is.
func (a *API) Counts() Counts {
	a.hidden.mu.Lock()
	defer a.hidden.mu.Unlock()
	return Counts{
		DanglingSymlinks:  a.hidden.dangling,
		DirectorySymlinks: a.hidden.dirLinks,
		SpecialFiles:      a.hidden.special,
	}
}
