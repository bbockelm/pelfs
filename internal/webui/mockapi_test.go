package webui

// The JSON API, mocked, so that the app in webui/frontend is testable BEFORE
// the real handlers exist.
//
// WHY THIS IS A TEST FILE AND NOT A PACKAGE. Work item U11 owns the real
// `/api/v1` over internal/vfsbilly; it is a sibling's work and it is not
// landed. An app built with nothing to talk to is an app nobody has run, so
// this is the stand-in — and it lives in a _test.go file for the same reason
// TestServeEmbeddedForBrowserSuite does: nothing in cmd/pelfs can reach it,
// so no shipped binary can ever serve a fake filesystem.
//
// WHAT IT IS FAITHFUL TO, deliberately, because these are the properties the
// browser suite is asserting and a lenient mock would assert nothing:
//
//   - THE SESSION CREDENTIAL IS REQUIRED on every /api/v1 route except the
//     bootstrap exchange, and it is required on GET as well as on writes.
//     That is what makes the app's `send()` override (webui/frontend/src/api/
//     provider.ts, finding 1) load-bearing in a real browser: drop the
//     override and the file manager gets 401 on its first listing. The U0
//     probe measured that `provider.setHeaders()` never reaches the wire; this
//     is the standing test of the fix.
//
//   - MUTATIONS MUST BE application/json, or 415. The shipped provider sends
//     `text/plain;charset=UTF-8` (finding 2), which internal/httpguard's
//     SurfaceAPI answers with 415, so a regression here is a file manager
//     whose every write fails. Same rule, same status, in the mock.
//
//   - THE UPLOAD IS STREAMED with r.MultipartReader(), never
//     ParseMultipartForm. docs/design-webui.md calls this "the single most
//     important implementation note in this section" (ParseMultipartForm
//     spills to a temp file and writes a large payload to disk twice), and a
//     mock that used the easy call would be a bad example sitting next to the
//     rule.
//
//   - A LISTING IS CAPPED, and the cap is REPORTED. The component does not
//     virtualize (measured: 100,000 entries -> 703 MB of heap), so the API
//     caps; a cap the UI cannot see is a UI that lies about a directory. The
//     headers are the app's assumed contract for U11 to honour:
//     X-Pelfs-Listing-Total and X-Pelfs-Listing-Cap.
//
// WHAT IT IS NOT. It is not the threat model: it has no Host allowlist and no
// provenance check, because the embedded-bundle server is also where the
// cross-origin suite proves that --host-resolver-rules really does send
// `Host: attacker.test:PORT` (see /__host in serve_test.go), and a 421 there
// would hide the very thing that spec measures. The threat model is
// internal/httpguard's, asserted in Go by its own table and in a browser
// against the real `pelfs browse`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
)

// mockListingCap is the response cap, small enough that the browser suite can
// prove the notice appears and large enough to be the real shape of the
// problem. The production number is a U11 decision; the design says ~5,000
// and the U0 sweep says 5,000 entries cost 40 MB of heap and 320 ms to
// render, which is the last row that is comfortable.
const mockListingCap = 5000

// mockBigDir is how many entries the one over-cap directory holds.
const mockBigDir = 6000

type mockEntry struct {
	id    string
	dir   bool
	size  int64
	mtime time.Time
	// staged is true for an entry this session created: the mock's stand-in
	// for "in the overlay, not in the federation".
	staged bool
	// ro makes every mutation of this entry answer 403, the way
	// internal/fsperm does through internal/vfsbilly on a path the session may
	// not write. It exists for ONE assertion the browser suite has to be able
	// to make: that a refused rename does not stay on the screen.
	//
	// A refusal cannot be arranged any other way here. The real 403 comes from
	// a mode bit on a real volume, a fresh volume has no such path, and
	// creating one through the UI would be testing the upload path instead of
	// the refusal. Intercepting the request in the browser was the other
	// option and it would have proved less: a fulfilled route is the suite
	// asserting against its own fixture, where this is the app meeting a
	// server that says no.
	ro   bool
	body string
}

// mockAPI is one volume, in memory, plus the durability state the page reads.
type mockAPI struct {
	sessions *browsesession.Manager

	mu      sync.Mutex
	ent     map[string]*mockEntry
	gen     uint64
	staged  int
	sbytes  int64
	job     *mockJob
	mode    string
	volume  string
	streams int
}

type mockJob struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitzero"`
	Summary string    `json:"summary,omitempty"`
	Error   string    `json:"error,omitempty"`
}

func newMockAPI(m *browsesession.Manager) *mockAPI {
	a := &mockAPI{
		sessions: m,
		ent:      map[string]*mockEntry{},
		gen:      87,
		mode:     "read-write",
		volume:   "pelican://demo.example/prefix",
	}
	a.seed()
	return a
}

// seed builds the volume, and it is called again by the reset hook so that a
// browser suite is ORDER-INDEPENDENT. Without it, a test that uploads a file
// leaves the next test's "nothing is staged yet" precondition false, and the
// suite passes or fails depending on the order the runner happened to pick --
// which is the same class of flakiness as a fixed sleep.
func (a *mockAPI) seed() {
	a.ent = map[string]*mockEntry{}
	a.gen, a.staged, a.sbytes, a.job = 87, 0, 0, nil
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	add := func(id string, dir bool, size int64) {
		a.ent[id] = &mockEntry{id: id, dir: dir, size: size, mtime: now, body: "pelfs mock bytes for " + id + "\n"}
	}
	for _, d := range []string{"/data", "/data/runs", "/plots", "/large"} {
		add(d, true, 0)
	}
	add("/README.txt", false, 42)
	// The one path this volume refuses to change. See mockEntry.ro.
	add("/read-only.dat", false, 4096)
	a.ent["/read-only.dat"].ro = true
	add("/data/sample.root", false, 68497408)
	add("/data/runs/run-001.txt", false, 1024)
	add("/plots/figure-1.png", false, 204800)
	// The one directory that is over the cap. It exists so the browser suite
	// can assert the notice, with the true count in it, against a real
	// truncated listing rather than a mocked header.
	for i := 0; i < mockBigDir; i++ {
		add(fmt.Sprintf("/large/f%05d.dat", i), false, int64(i))
	}
}

// ---- routing -------------------------------------------------------------

func (a *mockAPI) mount(mux *http.ServeMux) {
	// The exchange, which cannot require the credential it mints.
	mux.Handle("POST /api/v1/session", browsesession.ExchangeHandler(a.sessions))
	// Everything else does.
	api := func(h http.HandlerFunc) http.Handler { return a.authed(h) }
	mux.Handle("GET /api/v1/info", api(a.info))
	mux.Handle("GET /api/v1/files", api(a.list))
	// {id...} AND NOT {id}, which is a trap this mock walked into first and
	// U11 would walk into second.
	//
	// The component addresses a directory by putting its whole path in ONE
	// percent-encoded segment: `files/${encodeURIComponent(parent)}`. For the
	// volume root that is `files/%2F` -- and net/http's ServeMux unescapes a
	// path segment by segment BEFORE matching, so `/api/v1/files/%2F` is
	// matched as `/api/v1/files//`, whose last segment is EMPTY. A `{id}`
	// wildcard matches a non-empty segment only, so the route does not match
	// at all and the request falls through to whatever handles "/" -- which
	// here is the SPA's index.html, served with a 200. The app then reports
	// "the answer was not JSON", which is a true statement about an HTML page
	// and a very indirect way of learning about a routing bug.
	//
	// Measured: `{id}` matches %2Fdata and %2Fdata%2Fx and misses %2F;
	// `{id...}` matches all three, giving "/", "/data" and "/data/x". So
	// every mutation AT THE ROOT -- the first thing a person does -- is what
	// breaks under `{id}`. cmd/pelfs/browse.go's own route-table comment
	// already writes the seam as `{path...}`, which is right.
	mux.Handle("GET /api/v1/files/{id...}", api(a.list))
	mux.Handle("POST /api/v1/files/{id...}", api(a.create))
	mux.Handle("PUT /api/v1/files/{id...}", api(a.rename))
	mux.Handle("PUT /api/v1/files", api(a.batch))
	mux.Handle("DELETE /api/v1/files", api(a.remove))
	mux.Handle("POST /api/v1/upload", api(a.upload))
	mux.Handle("POST /api/v1/publish", api(a.publish))
	mux.Handle("POST /api/v1/download", api(a.mintTicket))
	// The same route name M1 gives its own driver hook, so one helper in the
	// browser suite drives both surfaces. It only ever puts this in-memory
	// volume back the way it started.
	mux.Handle("POST /api/v1/testhook", api(a.resetHook))
	mux.Handle("GET /events", a.events())
	mux.Handle("GET /d/{"+browsesession.TicketPathValue+"}",
		browsesession.DownloadHandler(a.sessions, mockSource{a}))
}

// authed is the session credential and the content-type rule, which are the
// two things the app's provider override exists to satisfy.
func (a *mockAPI) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.sessions.ValidSession(r.Header.Get("X-Pelfs-Session")) {
			writeMockJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "no valid session: the X-Pelfs-Session header is required on every API request"})
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			ct := r.Header.Get("Content-Type")
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			want := "application/json"
			if r.URL.Path == "/api/v1/upload" {
				want = "multipart/form-data"
			}
			if !strings.EqualFold(strings.TrimSpace(ct), want) {
				writeMockJSON(w, http.StatusUnsupportedMediaType, map[string]string{
					"error": "expected Content-Type: " + want})
				return
			}
		}
		h(w, r)
	})
}

// ---- the tree ------------------------------------------------------------

// children lists one directory. It sorts (folders first, then by name) so the
// cap takes a stable prefix: a cap over an unordered listing would show a
// different 5,000 entries on every reload, which is worse than showing fewer.
func (a *mockAPI) children(dir string) []*mockEntry {
	var out []*mockEntry
	for id, e := range a.ent {
		if path.Dir(id) == dir && id != dir {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].dir != out[j].dir {
			return out[i].dir
		}
		return out[i].id < out[j].id
	})
	return out
}

type wireEntry struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
	Date string `json:"date,omitempty"`
	Lazy bool   `json:"lazy,omitempty"`
}

func (a *mockAPI) list(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		id = "/"
	}
	a.mu.Lock()
	kids := a.children(id)
	total := len(kids)
	if total > mockListingCap {
		kids = kids[:mockListingCap]
	}
	out := make([]wireEntry, 0, len(kids))
	for _, e := range kids {
		t := "file"
		if e.dir {
			t = "folder"
		}
		out = append(out, wireEntry{
			ID: e.id, Type: t, Size: e.size,
			Date: e.mtime.UTC().Format(time.RFC3339),
			// EVERY FOLDER IS LAZY, or the store never asks for its
			// contents: `set-path` fires `request-data` only for a node
			// marked lazy. A folder without it is an empty folder forever.
			Lazy: e.dir,
		})
	}
	a.mu.Unlock()

	if total > len(out) {
		// The cap, reported in headers so the body stays the bare array the
		// component requires (RestDataProvider.loadFiles hands it to
		// parseDates, which calls forEach on it).
		w.Header().Set("X-Pelfs-Listing-Total", fmt.Sprint(total))
		w.Header().Set("X-Pelfs-Listing-Cap", fmt.Sprint(mockListingCap))
	}
	writeMockJSON(w, http.StatusOK, out)
}

func (a *mockAPI) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "expected {name, type}"})
		return
	}
	parent := r.PathValue("id")
	if parent == "" {
		parent = "/"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := join(parent, req.Name)
	if _, clash := a.ent[id]; clash {
		writeMockJSON(w, http.StatusConflict, map[string]string{"error": "that name is taken"})
		return
	}
	a.ent[id] = &mockEntry{id: id, dir: req.Type == "folder", mtime: time.Now(), staged: true}
	a.stage(1, 0)
	writeMockJSON(w, http.StatusOK, map[string]any{
		"result": map[string]any{"id": id, "type": req.Type},
	})
}

func (a *mockAPI) rename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Operation != "rename" {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": `expected {"operation":"rename","name":…}`})
		return
	}
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.ent[id]
	if !ok {
		writeMockJSON(w, http.StatusNotFound, map[string]string{"error": "no such path"})
		return
	}
	if e.ro {
		refuseMockWrite(w, id)
		return
	}
	to := join(path.Dir(id), req.Name)
	a.movePath(e, to)
	a.stage(1, 0)
	writeMockJSON(w, http.StatusOK, map[string]any{"result": map[string]any{"id": to}})
}

// batch is move and copy, and it answers PER ID.
//
// docs/design-webui.md's "semantic restraint": there is no atomic N-way
// rename in the overlay, in WebDAV or in POSIX, so the operation is N
// sequential ones and the response says what happened to each. The app reads
// an `error` on any element and says so out loud (provider.ts,
// partialFailure) -- a batch that reported success for a partial failure
// would be lying in the one place a user cannot check.
func (a *mockAPI) batch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Operation string   `json:"operation"`
		IDs       []string `json:"ids"`
		Target    string   `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	results := make([]map[string]any, 0, len(req.IDs))
	for _, id := range req.IDs {
		e, ok := a.ent[id]
		if !ok {
			results = append(results, map[string]any{"id": id, "error": "no such path"})
			continue
		}
		// A MOVE of a read-only entry is refused per id, which is the
		// partial-failure case: the batch is a 200 and the app still has to
		// say that one of them did not happen. (A COPY is not refused: the
		// source is only read.)
		if e.ro && req.Operation != "copy" {
			results = append(results, map[string]any{
				"id": id, "error": "permission denied: this session may not write " + id,
			})
			continue
		}
		to := join(req.Target, path.Base(id))
		if _, clash := a.ent[to]; clash {
			results = append(results, map[string]any{"id": id, "error": "the target already has that name"})
			continue
		}
		if req.Operation == "copy" {
			cp := *e
			cp.id = to
			cp.staged = true
			a.ent[to] = &cp
		} else {
			a.movePath(e, to)
		}
		a.stage(1, e.size)
		results = append(results, map[string]any{"id": to})
	}
	writeMockJSON(w, http.StatusOK, map[string]any{"result": results})
}

func (a *mockAPI) remove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "expected {ids}"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range req.IDs {
		if e, ok := a.ent[id]; ok && e.ro {
			refuseMockWrite(w, id)
			return
		}
		for k := range a.ent {
			if k == id || strings.HasPrefix(k, id+"/") {
				delete(a.ent, k)
			}
		}
		a.stage(1, 0)
	}
	writeMockJSON(w, http.StatusOK, map[string]any{"result": true})
}

// upload is ONE whole multipart POST, streamed.
func (a *mockAPI) upload(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get("id")
	if parent == "" {
		parent = "/"
	}
	mr, err := r.MultipartReader()
	if err != nil {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "expected multipart/form-data"})
		return
	}
	name := ""
	var size int64
	var body strings.Builder
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed multipart body"})
			return
		}
		switch p.FormName() {
		case "name":
			b, _ := io.ReadAll(io.LimitReader(p, 4096))
			if name == "" {
				name = string(b)
			}
		case "file":
			if name == "" {
				name = p.FileName()
			}
			// Streamed, not buffered to a temp file: the same shape the real
			// handler must take. The mock keeps a bounded prefix so the
			// ticketed download has something to serve.
			n, err := io.Copy(&limitWriter{w: &body, max: 1 << 16}, p)
			if err != nil {
				writeMockJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			size = n
		}
		_ = p.Close()
	}
	if name == "" {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "the upload named no file"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := join(parent, path.Base(name))
	a.ent[id] = &mockEntry{id: id, size: size, mtime: time.Now(), staged: true, body: body.String()}
	a.stage(1, size)
	writeMockJSON(w, http.StatusOK, map[string]any{
		"result": map[string]any{"id": id, "size": size},
	})
}

// limitWriter keeps the mock's memory bounded without failing the upload.
type limitWriter struct {
	w   *strings.Builder
	max int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if room := l.max - l.w.Len(); room > 0 {
		if len(p) <= room {
			l.w.Write(p) //nolint:errcheck
		} else {
			l.w.Write(p[:room]) //nolint:errcheck
		}
	}
	return len(p), nil
}

// movePath moves an entry and everything under it. Called with a.mu held.
// refuseMockWrite is the answer internal/fsperm produces, in the shape
// internal/httpguard lets through: a real status and a real body, so the app's
// `explain` has something to put on the screen.
func refuseMockWrite(w http.ResponseWriter, id string) {
	writeMockJSON(w, http.StatusForbidden, map[string]string{
		"error": "permission denied: this session may not write " + id,
	})
}

func (a *mockAPI) movePath(e *mockEntry, to string) {
	from := e.id
	for k, v := range a.ent {
		if k != from && !strings.HasPrefix(k, from+"/") {
			continue
		}
		delete(a.ent, k)
		v.id = to + strings.TrimPrefix(k, from)
		v.staged = true
		a.ent[v.id] = v
	}
}

// stage records that something is now on this machine only. Called with mu.
func (a *mockAPI) stage(files int, bytes int64) {
	a.staged += files
	a.sbytes += bytes
}

func join(dir, name string) string {
	if dir == "" || dir == "/" {
		return "/" + strings.TrimPrefix(name, "/")
	}
	return strings.TrimSuffix(dir, "/") + "/" + strings.TrimPrefix(name, "/")
}

// ---- state, publish, events ---------------------------------------------

// mockState is cmd/pelfs/browse.go's browseState, plus the drive numbers the
// component's own panel reads. Keeping the field names identical is the point:
// the app is one client of one contract, and this mock is the other end of it.
func (a *mockAPI) state() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := map[string]any{
		"phase":          "ready",
		"volume":         a.volume,
		"mode":           a.mode,
		"branch":         "main",
		"generation":     a.gen,
		"lease":          "held",
		"staged_files":   a.staged,
		"staged_bytes":   a.sbytes,
		"dirty_nodes":    a.staged,
		"upload_backlog": 0,
		"next_publish_s": 221,
		"test_hooks":     false,
		"streams":        a.streams,
		"used":           1 << 30,
		"total":          1 << 34,
	}
	if a.job != nil {
		st["publish"] = *a.job
	}
	return st
}

// resetHook is the driver hook, and it does two things.
//
// `{"reset": true}` (or an empty body) puts the volume back the way it started
// -- see seed for why a browser suite has to be order-independent.
//
// `{"mode": "read-only"}` is the second, and it exists for one assertion the
// browser suite cannot otherwise make: `pelfs browse` is READ-ONLY BY DEFAULT,
// and the whole point of the shipped design is that such a session renders no
// publish control at all rather than a disabled one explaining itself. The
// harness runs `pelfs browse --rw` (it has to: the publish path is the other
// thing under test), so read-only is not reachable there, and this mock is the
// only server in the suite that can report it.
func (a *mockAPI) resetHook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reset bool   `json:"reset"`
		Mode  string `json:"mode"`
	}
	// A body is optional and a malformed one is not worth a 400 here: the
	// zero value is "reset", which is what every caller but one wants.
	_ = json.NewDecoder(r.Body).Decode(&req)
	a.mu.Lock()
	switch req.Mode {
	case "read-only", "read-write":
		a.mode = req.Mode
	default:
		a.seed()
		a.mode = "read-write"
	}
	a.mu.Unlock()
	writeMockJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *mockAPI) info(w http.ResponseWriter, _ *http.Request) {
	writeMockJSON(w, http.StatusOK, a.state())
}

// publish is 202-and-a-job-id, and 409 for a second concurrent request --
// the same two answers cmd/pelfs/browse.go gives, because the app's handling
// of them is what the browser suite asserts.
func (a *mockAPI) publish(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	if a.job != nil && a.job.State == "running" {
		id := a.job.ID
		a.mu.Unlock()
		writeMockJSON(w, http.StatusConflict, map[string]string{
			"error": "a publish is already running", "job": id})
		return
	}
	job := &mockJob{ID: fmt.Sprintf("mock-%d", time.Now().UnixNano()%1e6), State: "running", Started: time.Now()}
	a.job = job
	a.mu.Unlock()
	go func() {
		// A real seal is minutes; this is long enough for a browser driver to
		// observe "running" and short enough not to pad the gate.
		time.Sleep(300 * time.Millisecond)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.gen++
		job.State, job.Ended = "done", time.Now()
		job.Summary = fmt.Sprintf("generation %d", a.gen)
		a.staged, a.sbytes = 0, 0
		for _, e := range a.ent {
			e.staged = false
		}
	}()
	writeMockJSON(w, http.StatusAccepted, map[string]any{"job": job.ID, "watch": "/events"})
}

func (a *mockAPI) mintTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMockJSON(w, http.StatusBadRequest, map[string]string{"error": "expected {path}"})
		return
	}
	a.mu.Lock()
	_, ok := a.ent[req.Path]
	a.mu.Unlock()
	if !ok {
		writeMockJSON(w, http.StatusNotFound, map[string]string{"error": "no such path"})
		return
	}
	tk, err := a.sessions.MintTicket(req.Path)
	if err != nil {
		writeMockJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeMockJSON(w, http.StatusOK, map[string]string{
		"url": "/d/" + tk, "ttl": browsesession.TicketTTL.String(),
	})
}

// mockSource is where a ticketed download gets its bytes. It consults the
// TICKET's path and nothing from the request, which is the rule the interface
// states: by the time it is called, the only statement about what to serve is
// the ticket.
type mockSource struct{ a *mockAPI }

func (s mockSource) Open(_ context.Context, p string) (*browsesession.Content, error) {
	s.a.mu.Lock()
	e, ok := s.a.ent[p]
	var body string
	if ok {
		body = e.body
	}
	s.a.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &browsesession.Content{
		Name: path.Base(p), Size: int64(len(body)), ModTime: time.Now(),
		Body: readSeekNop{strings.NewReader(body)},
	}, nil
}

// readSeekNop keeps io.Seeker, so the handler takes http.ServeContent's path
// and Range works exactly as it will for a real file.
type readSeekNop struct{ *strings.Reader }

func (readSeekNop) Close() error { return nil }

// events is the SSE stream: COMPLETE SNAPSHOTS, never deltas, exactly as
// cmd/pelfs/browse.go's serveEvents. That is what makes a reconnect safe, and
// the browser suite asserts it by breaking the connection and watching the
// page catch up without a reload.
func (a *mockAPI) events() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.sessions.ValidSession(r.URL.Query().Get("s")) {
			http.Error(w, "no valid session", http.StatusUnauthorized)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-store")
		rc := http.NewResponseController(w)
		a.mu.Lock()
		a.streams++
		a.mu.Unlock()
		defer func() {
			a.mu.Lock()
			a.streams--
			a.mu.Unlock()
		}()
		fmt.Fprint(w, "retry: 1000\n\n")
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			doc, err := json.Marshal(a.state())
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", doc); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
		}
	})
}

func writeMockJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
