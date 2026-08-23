package main

// `pelfs browse` is M1 of docs/design-webui.md: a loopback HTTP listener,
// one hand-written page, and the two things a file manager cannot give —
// a publish button and an honest answer to "is my data in the federation
// yet".
//
// It deliberately does NOT browse files. docs/design-guiclients.md
// identified the trap this milestone exists to close: a modest
// drag-and-drop finishes, the user closes the client, and nothing has been
// published for up to five minutes. Neither half of that is a
// file-manager feature, and both are on the page below.
//
// # What this verb is, in one paragraph
//
// It is a mount-gen session with no mount. Everything except the kernel
// binding is the same code the mount runs: pelicanobj, refs, genfs, the
// write overlay, the advisory lease, the periodic checkpointer, the seal
// at exit, the session statistics. That is why runBrowse reads like
// runMountGen — it is deliberately the same sequence in the same order,
// because the teardown discipline there is load-bearing (drain the
// checkpointer BEFORE anything closes the overlay; seal before the lease
// is released; report the phase split) and a second, subtly different copy
// of it is how a session loses somebody's data.
//
// # The one ordering that is NOT the mount's
//
// The mount opens the volume and then attaches a frontend. A browser is
// the other way round: if the volume opened first, the very first
// device-flow prompt would be generated with no page to show it on, and
// the user would watch a hung tab while the URL sat in a terminal they
// were told they would not need. So runBrowse binds, serves and prints the
// URL FIRST — none of which can fail on the federation — and opens the
// volume afterwards, with the page already loaded and showing
// "connecting". docs/design-webui.md calls this out as a real requirement
// on new code rather than an observation, and it is why browseServer has a
// phase at all.
//
// # What the web surface may reach
//
// Three things: publish, session status, dirty counts. They are reached by
// calling the same in-process functions the control socket's hooks call —
// NOT by proxying internal/control. That package's comment states its own
// licence for exposing the whole of net/http/pprof: "the socket is the
// auth boundary (0600 in the state dir)". A browser session on 127.0.0.1
// is not that boundary; a heap profile of this process contains file
// paths, catalog contents and plausibly credential material, and
// /debug/pprof/cmdline contains the prefix and every flag. So this
// listener has its own hand-written route table, pprof is not on it, and
// a test asserts the 404.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// browseAssets is the page. One file, hand-written, no bundler, no Node —
// and no third-party JavaScript, which is why the CSP below can be strict
// enough to make a stored-XSS finding harmless.
//
//go:embed browse.html
var browseAssets embed.FS

// browsePage is parsed once at startup so a template error is a startup
// failure rather than a 500 on the first request.
var browsePage = template.Must(template.ParseFS(browseAssets, "browse.html"))

// browseArgs are the verb's own knobs; everything else comes from the
// shared flags (--rw is here rather than there because `browse` defaults
// read-only and `mount` does too, but the help text differs).
type browseArgs struct {
	branch    string
	pubkeyHex string
	rw        bool
	open      bool
	testHooks bool
}

// cmdBrowse implements `pelfs browse [flags] <prefix>`.
func cmdBrowse(args []string) int {
	a := browseArgs{branch: "main"}
	o, pos, err := parseArgs("browse", args, 1, 1, func(fs *flag.FlagSet, _ *cmdOpts) {
		fs.StringVar(&a.branch, "branch", "main", "branch to open")
		fs.StringVar(&a.pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		// Read-only is the default, and --rw is one word of typing, for
		// the reason docs/design-webui.md gives: a read-only browse
		// session cannot lose anything, cannot publish anything, and its
		// entire threat model collapses to disclosure of data the user can
		// already read. That is a much better default for the first thing
		// somebody runs.
		fs.BoolVar(&a.rw, "rw", false, "open read-write: a local overlay, a branch lease, and a seal at exit (default: read-only)")
		fs.BoolVar(&a.open, "open", false, "launch the platform's browser at the URL (the URL is printed either way)")
		fs.BoolVar(&a.testHooks, "test-hooks", false, browseTestHooksUsage)
	})
	if err != nil {
		return exitErr(err)
	}
	if o.readOnly && a.rw {
		return exitErr(errors.New("--ro and --rw contradict each other; browse is read-only unless --rw"))
	}
	return runBrowse(o, pos[0], a)
}

const browseTestHooksUsage = "expose a state-override route for the browser-driver test suite " +
	"(NEVER on a real volume: it lets the page be driven into states the volume is not in)"

// browseStop ends a session where a signal cannot. It is nil in every real
// build — a nil channel blocks forever in a select, so the case costs
// nothing — and only a test sets it, because a test process cannot safely
// send itself SIGINT: the signal races the very signal.Notify it is meant
// to reach, and losing that race kills the test binary.
//
// The same shape as genSession.reclaimFn ("Only tests set it"), and for
// the same reason: the alternative is leaving the whole verb — the
// listener, the volume open, the seal at exit — with no test at all.
var browseStop chan struct{}

// runBrowse serves one browse session. The shape is runMountGen's, minus
// the mount and with the listener moved to the front; see the file comment
// for why both of those are deliberate.
func runBrowse(o *cmdOpts, prefix string, a browseArgs) int {
	ctx := context.Background()
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return exitErr(err)
	}

	g := &genSession{
		prefix:     prefix,
		branch:     a.branch,
		stateDir:   stateDir,
		backend:    "browse",
		sessionID:  newSessionID(),
		started:    time.Now(),
		rw:         a.rw,
		overlayDir: filepath.Join(stateDir, "overlay"),
		down:       &phaseClock{},
	}
	defer g.reportTeardown()
	g.statsPath = o.statsFile
	if g.statsPath == "" {
		g.statsPath = filepath.Join(stateDir, "pelfs-stats.json")
	}
	g.stats = stats.New(prefix, g.sessionID, g.statsPath)
	g.stats.Update(func(sum *stats.Summary) {
		sum.Branch = a.branch
		sum.Backend = g.backend
		sum.Writable = a.rw
		sum.PrefetchMode = o.prefetch
	})

	// ---- 1. The listener, the guard and the page, before anything that
	// can touch the network. tcp4 explicitly, and 127.0.0.1 rather than
	// 0.0.0.0: internal/nfsmount.Serve's comment applies word for word
	// ("a hostname like 'localhost' can resolve to ::1 where nothing
	// listens"), and binding the wildcard address would put this UI on the
	// machine's LAN address — a mistake that turns a local threat model
	// into a network one.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(fmt.Errorf("browse listen: %w", err))
	}
	port := ln.Addr().(*net.TCPAddr).Port
	sessions, err := browsesession.New()
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
	bs := newBrowseServer(prefix, a, o.snapshotInterval, sessions)
	guard := httpguard.New(httpguard.Config{Port: port, Sessions: sessions})
	srv := &http.Server{
		Handler: bs.routes(guard),
		// No ReadTimeout/WriteTimeout: /events is a response that stays
		// open for the life of the tab, and a WriteTimeout would kill it.
		// ReadHeaderTimeout is the one that matters for a slow-loris and
		// it costs nothing here.
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv.RegisterOnShutdown(bs.closeStreams)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	launch := sessions.LaunchURL(guard.Origin())
	printLaunch(prefix, launch, a)
	if a.testHooks {
		// Loud, once, and on the page as well (see browse.html): an
		// affordance that lets the UI show states the volume is not in
		// must never be mistaken for the real thing.
		ui.Warn("--test-hooks is ON: this session exposes {route}, which overrides what the page reports. "+
			"It is for the browser-driver suite only, and the page says so in a banner.",
			"route", "POST /api/v1/testhook")
	}
	if a.open {
		if err := openInBrowser(launch); err != nil {
			// Never fatal: a login node or a container has no opener, and
			// the URL is on the terminal already. This is exactly the
			// fallback every other pelfs verb gives.
			ui.Warn("could not launch a browser ({error}); open the URL above yourself", "error", err)
		}
	}

	// ---- 2. Now the volume. This is where a device-flow prompt fires,
	// and by construction the page is already loadable when it does.
	fail := func(err error) int {
		bs.setFailed(err)
		_ = g.stats.Finalize(1, false)
		// The page's stream carries the failure, but the terminal is still
		// where a pelfs error belongs: the tab may never have been opened.
		return exitErr(err)
	}
	raw, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		Insecure:     o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return fail(err)
	}
	if err := pelicanobj.Preflight(ctx, raw, prefix, !a.rw); err != nil {
		return fail(err)
	}
	g.inner = countedStore{ObjectStore: stats.WrapStorage(raw, g.stats), raw: raw}

	var trusted ed25519.PublicKey
	if a.pubkeyHex != "" {
		k, err := hex.DecodeString(a.pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return fail(errors.New("--volume-pubkey must be 64 hex characters"))
		}
		trusted = k
	}
	// The lease is taken BEFORE the branch head is read, exactly as
	// runMountGen takes it, so the generation the overlay is built over
	// cannot be advanced by another writer between the fetch and the seal.
	if a.rw && !o.noLease {
		l, err := g.acquireLease(ctx, o, prefix)
		if err != nil {
			return fail(err)
		}
		g.lease = l
		defer g.down.timed("lease", g.releaseLease)
	}
	rstore, err := refs.New(g.inner, stateDir, trusted)
	if err != nil {
		return fail(err)
	}
	g.refs = rstore
	f, err := rstore.Fetch(ctx, a.branch)
	if err != nil {
		return fail(err)
	}
	g.sb, g.prevRaw = f.Superblock, f.Raw
	sb := g.sb
	if o.encryptKeyPath != "" {
		kek, err := superblock.LoadRSAPrivateKeyFile(o.encryptKeyPath, keyPassphrase())
		if err != nil {
			return fail(fmt.Errorf("load --encrypt-key: %w", err))
		}
		for _, ke := range sb.KeyTable {
			key, err := superblock.UnwrapKey(kek, ke.Wrapped)
			if err != nil {
				return fail(fmt.Errorf("unwrap key %d: %w", ke.ID, err))
			}
			switch ke.Kind {
			case superblock.KeyKindDEK:
				g.dek, g.keyID = key, ke.ID
			case superblock.KeyKindIdentity:
				g.identityKey = key
			}
		}
	}
	cacheBytes, err := o.cacheBudget()
	if err != nil {
		return fail(err)
	}
	g.gfs, err = genfs.Open(ctx, genfs.Options{
		Inner:    g.inner,
		SB:       sb,
		DEK:      g.dek,
		CacheDir: filepath.Join(stateDir, "gencache"),
		// The path-based bound, not the FUSE one: no kernel owns inode
		// lifetimes here, and the surfaces this listener will grow (U6's
		// WebDAV, U11's JSON API) re-descend from the root on every
		// operation exactly as the loopback-NFS frontend does. So
		// residency is a genuine working set and can be capped as one.
		MaxResident: nfsMaxResident,
		CacheBytes:  cacheBytes,
	})
	if err != nil {
		return fail(err)
	}
	defer g.down.timed("gencache", func() { g.gfs.Close() }) //nolint:errcheck
	g.stats.Update(func(sum *stats.Summary) { sum.Generation = sb.Generation })
	if err := g.runPrefetch(ctx, o.prefetch); err != nil {
		return fail(err)
	}
	if a.rw {
		ovOpts := overlay.Options{
			NextInode:      g.gfs.NextInode(),
			BaseRoot:       g.gfs.RootCatalog(),
			BaseGeneration: g.gfs.Generation(),
		}
		if ovOpts.Memtable, err = g.openContent(ctx, false); err != nil {
			return fail(err)
		}
		g.ov, err = overlay.Open(g.overlayDir, g.gfs, ovOpts)
		if err != nil {
			if errors.Is(err, overlay.ErrGeneration) {
				err = fmt.Errorf("%w\n"+
					"the unsealed overlay at %s was recorded over an older generation of %s.\n"+
					"its contents are intact but cannot be sealed onto the current head; move it aside to start a fresh overlay",
					err, g.overlayDir, a.branch)
			}
			return fail(fmt.Errorf("open overlay: %w", err))
		}
		// Registered before the overlay's own close so LIFO runs it after:
		// the seal renders the content store's records.
		if closeContent := g.closeContent; closeContent != nil {
			defer g.down.timed("content", func() { closeContent() }) //nolint:errcheck
		}
		defer g.down.timed("overlay", func() { g.ov.Close() }) //nolint:errcheck
	}

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	bs.setReady(g, sessionCtx)
	mode := "read-only"
	if a.rw {
		mode = "read-write (overlay; Ctrl-C seals)"
	}
	ui.Info("generation {generation} open {mode} for the browser at {url}",
		"generation", sb.Generation, "mode", mode, "url", guard.Origin())

	go g.stats.RunPeriodic(sessionCtx, statsInterval)
	go sweepRetiredOverlays(stateDir)
	go sweepStateScratch(stateDir)
	go g.sample(sessionCtx, statsInterval)
	// The control socket, for the same reason every other session has one:
	// `pelfs ctl <state-dir> status|stats|bugreport` is how a browse
	// session that misbehaves gets diagnosed. It is NOT reachable from the
	// browser, and nothing on the web surface proxies it.
	if ctl := g.startControl(); ctl != nil {
		defer g.down.timed("control", func() { ctl.Close() }) //nolint:errcheck
	}
	if a.rw && o.snapshotInterval > 0 {
		g.startCheckpointer(sessionCtx, o.snapshotInterval)
		defer g.drainCheckpoints()
		ui.Info("checkpointing every {interval} (--snapshot-interval 0 disables); "+
			"the page says when the next one is due",
			"interval", o.snapshotInterval)
	}

	// ---- 3. Serve until interrupted. Ctrl-C is the unmount: this verb is
	// deliberately not a daemon, because a background browse session that
	// seals on a signal nobody sends is how data gets left staged for a
	// week.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	code := 0
	select {
	case <-sigs:
	case <-browseStop:
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			ui.Error("browse listener: {error}", "error", err)
			code = 1
		}
	}

	// ---- 4. Teardown, in runMountGen's order.
	g.beginTeardown()
	// Streams first: closing them lets Shutdown return instead of waiting
	// on a response that is open by design.
	bs.closeStreams()
	shutCtx, cancelShut := context.WithTimeout(ctx, 5*time.Second)
	_ = srv.Shutdown(shutCtx)
	cancelShut()
	g.down.mark("web server")
	// A publish the user asked for is still the user's work, so it is
	// waited for rather than abandoned — and it holds g.mu, so the seal
	// below would wait for it anyway. Waiting here is what makes the wait
	// visible in the phase breakdown.
	bs.waitForPublish()
	g.down.mark("publish drain")
	stopSession()
	g.down.mark("session stop")
	g.drainCheckpoints()
	sealErr := g.sealAtExit(ctx)
	g.down.mark("seal")
	if sealErr != nil {
		ui.Error("{error}", "error", sealErr)
		if code == 0 {
			code = 1
		}
	}
	g.refresh()
	if err := g.stats.Finalize(code, sealErr == nil); err != nil {
		ui.Warn("write stats file: {error}", "error", err)
	}
	g.reportPhaseSplit()
	g.down.mark("stats")
	return code
}

// printLaunch is the terminal block from docs/design-webui.md's M1 mock.
//
// It is a document, like `pelfs cache`'s report, so it goes to stdout with
// fmt rather than through ui: the reader is being handed a URL to act on,
// not told what the program is doing.
//
// ONE DEPARTURE FROM THE MOCK, and it matters: the doc shows
// "opening http://127.0.0.1:49731/ in your browser" with no fragment. The
// URL must carry `#bt=<token>` or the page it opens has no credential to
// exchange and the third line's promise ("paste that URL") is false. So
// the full URL is printed. Reported back to the doc.
func printLaunch(prefix, launch string, a browseArgs) {
	verb := "open"
	if a.open {
		verb = "opening"
	}
	tail := "Ctrl-C to stop; read-only, so there is nothing to seal."
	if a.rw {
		tail = "Ctrl-C to stop; the session seals on exit."
	}
	fmt.Printf("pelfs browse %s\n  %s %s in your browser\n"+
		"  (if it did not open, paste that URL — the link is single-use, 2-minute expiry)\n  %s\n",
		prefix, verb, launch, tail)
}

// openInBrowser hands the URL to the platform's opener.
//
// Three programs with three parsers, and the URL carries a `#`, which is a
// comment character in a shell. Nothing here goes through a shell —
// exec.Command takes an argv — so the fragment survives on Unix. Windows
// uses rundll32 rather than `cmd /c start`, because start eats `&` and
// treats a bare URL with a fragment inconsistently, and because it needs
// no quoting rules of its own.
//
// docs/design-webui.md lists "whether #bt= survives every platform opener"
// as unverified. It still is on Windows; the fallback is the URL on the
// terminal, which is printed first and unconditionally for exactly this
// reason.
func openInBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

// browseServer holds everything the HTTP surface needs and nothing the
// session needs. It exists before the volume does (see the ordering note
// in the file comment), so every accessor has to tolerate g == nil.
type browseServer struct {
	prefix   string
	args     browseArgs
	interval time.Duration
	sessions *browsesession.Manager

	mu sync.Mutex
	// g is nil until the volume is open. phase is what the page shows in
	// the meantime.
	g       *genSession
	ctx     context.Context
	phase   string // "connecting" | "ready" | "failed"
	openErr string
	// staged* keep the last sample that was readable. pressure() answers
	// -1 while a seal has the overlay, and reporting zero staged bytes
	// mid-publish would be the one lie this page must not tell.
	stagedBytes int64
	stagedNodes int
	// publishing state, and the last job's outcome.
	job *publishJob
	// lastPublish anchors "next automatic publish in ...". The periodic
	// checkpointer owns the real ticker and does not expose it, so this is
	// a floor rather than a promise, and the page words it that way.
	lastPublish time.Time
	// streams are the live SSE subscribers. U10 (seal on idle) wants
	// exactly this set: "the last /events stream closed" is a real event
	// on the same footing as an SSH channel close.
	streams map[chan struct{}]struct{}
	// doneCh is closed once, when the process is leaving, so every stream
	// can say goodbye and return; Server.Shutdown would otherwise wait
	// forever on a response that is open by design.
	doneCh chan struct{}
	closed bool
	// publishWG joins the publish goroutine at teardown.
	publishWG sync.WaitGroup
	// test-hook overrides; see browseTestHooksUsage.
	over testOverrides
}

// testOverrides is what --test-hooks lets the browser-driver suite set.
// Every field is inert unless the flag was passed.
type testOverrides struct {
	on            bool
	lease         string
	stagedFiles   int
	stagedBytes   int64
	uploadBacklog int64
	publishStall  time.Duration
	// downloadBody, when set, registers a synthetic download source so the
	// ticket round trip is exercisable from a real browser.
	downloadBody string
}

type publishJob struct {
	ID      string    `json:"id"`
	State   string    `json:"state"` // running | done | failed | idle
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitzero"`
	Summary string    `json:"summary,omitempty"`
	Error   string    `json:"error,omitempty"`
}

func newBrowseServer(prefix string, a browseArgs, interval time.Duration, m *browsesession.Manager) *browseServer {
	return &browseServer{
		prefix:      prefix,
		args:        a,
		interval:    interval,
		sessions:    m,
		phase:       "connecting",
		lastPublish: time.Now(),
		streams:     map[chan struct{}]struct{}{},
		over:        testOverrides{on: a.testHooks},
	}
}

// routes is THE ROUTE TABLE, and the seam the later milestones mount onto.
//
// Every line names a surface, and the surface names the principal
// (internal/httpguard). What lands here next:
//
//	U6  WebDAV:  r.Handle(httpguard.SurfaceExternal, "/dav/", vfsdav.Handler(...))
//	U7  OAuth:   r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", ...)
//	             r.Handle(httpguard.SurfaceExchange,   "POST /oauth/token", ...)
//	U11 JSON:    r.Handle(httpguard.SurfaceAPI,    "GET /api/v1/files/{path...}", ...)
//	             r.Handle(httpguard.SurfaceUpload, "POST /api/v1/upload", ...)
//
// and the one thing that does NOT land here, ever, is anything that
// forwards to internal/control.
func (b *browseServer) routes(g *httpguard.Guard) http.Handler {
	r := g.NewRouter()
	// The app shell. Unauthenticated because there is no secret in it: the
	// page ships no state at all and asks for everything over the API,
	// which is also what lets its CSP have no data in it to smuggle.
	r.HandleFunc(httpguard.SurfaceApp, "GET /{$}", b.servePage)
	// The bootstrap-for-session exchange: the one route that cannot
	// require the session header, because it mints it.
	r.Handle(httpguard.SurfaceExchange, "POST /api/v1/session",
		browsesession.ExchangeHandler(b.sessions))
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/info", b.serveInfo)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/publish", b.servePublish)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/download", b.serveMintTicket)
	r.HandleFunc(httpguard.SurfaceStream, "GET /events", b.serveEvents)
	// The ticketed download. M1 registers no Source, so a redeemed ticket
	// 404s — the MECHANISM is what this milestone owes U11, and it is
	// cheaper to build it with the guard than to retrofit it afterwards
	// (see internal/browsesession.DownloadHandler for why an <a href>
	// download cannot use the session credential).
	r.Handle(httpguard.SurfaceTicket, "GET /d/{"+browsesession.TicketPathValue+"}",
		browsesession.DownloadHandler(b.sessions, b.downloadSource()))
	if b.args.testHooks {
		r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/testhook", b.serveTestHook)
	}
	return r
}

// downloadSource is nil in a normal build; --test-hooks supplies a
// synthetic one so a browser driver can prove the no-credential download
// and the single-use ticket end to end.
func (b *browseServer) downloadSource() browsesession.Source {
	if !b.args.testHooks {
		return nil
	}
	return testDownloadSource{b}
}

type testDownloadSource struct{ b *browseServer }

func (s testDownloadSource) Open(_ context.Context, p string) (*browsesession.Content, error) {
	s.b.mu.Lock()
	body := s.b.over.downloadBody
	s.b.mu.Unlock()
	if body == "" {
		return nil, errors.New("no synthetic download configured")
	}
	if p == "/forbidden" {
		return nil, browsesession.ErrForbidden
	}
	return &browsesession.Content{
		Name: filepath.Base(p), Size: int64(len(body)), ModTime: time.Now(),
		// A ReadSeeker, so the handler exercises the same
		// http.ServeContent path (and therefore the same Range support) a
		// real file will take in U11.
		Body: readSeekNopCloser{strings.NewReader(body)},
	}, nil
}

// readSeekNopCloser is a strings.Reader that satisfies io.ReadCloser
// without giving up io.Seeker.
type readSeekNopCloser struct{ *strings.Reader }

func (readSeekNopCloser) Close() error { return nil }

// ---- state ---------------------------------------------------------------

// browseState is what the page renders, and it is the whole contract
// between the page and the server: /api/v1/info returns one of these, and
// every SSE frame IS one of these. See serveEvents for why the stream
// carries snapshots rather than deltas.
type browseState struct {
	// Phase is "connecting" until the volume is open, then "ready", or
	// "failed" with Error set.
	Phase string `json:"phase"`
	Error string `json:"error,omitempty"`
	// Volume is the prefix, exactly as the user typed it.
	Volume string `json:"volume"`
	// Mode is "read-only" or "read-write".
	Mode       string `json:"mode"`
	Branch     string `json:"branch"`
	Generation uint64 `json:"generation"`
	// Lease is the control socket's own vocabulary: held, stale,
	// interrupted, lost — four different answers to "can this session
	// still publish". "none" is a read-only or --no-lease session, which
	// is not a fifth state of the same kind and must not read as one.
	Lease    string  `json:"lease"`
	LeaseAge float64 `json:"lease_age_s,omitempty"`

	// Durability. Two counters, never one: what is on this machine and
	// what is in the federation are different facts and the page must
	// never merge them into a single checkmark.
	StagedFiles   int   `json:"staged_files"`
	StagedBytes   int64 `json:"staged_bytes"`
	DirtyNodes    int   `json:"dirty_nodes"`
	UploadBacklog int64 `json:"upload_backlog"`
	// NextPublishS is a floor, not a promise: write pressure can fire a
	// checkpoint sooner, and the page says so.
	NextPublishS int64 `json:"next_publish_s"`
	// Publish is the current or last job.
	Publish *publishJob `json:"publish,omitempty"`
	// TestHooks is true when --test-hooks was passed, so the page can say
	// so where a person will see it.
	TestHooks bool `json:"test_hooks"`
	// Streams is how many /events subscribers there are, which is the
	// signal U10 will seal on.
	Streams int `json:"streams"`
}

func (b *browseServer) setReady(g *genSession, ctx context.Context) {
	b.mu.Lock()
	b.g, b.ctx, b.phase = g, ctx, "ready"
	b.mu.Unlock()
	b.nudge()
}

func (b *browseServer) setFailed(err error) {
	b.mu.Lock()
	b.phase, b.openErr = "failed", err.Error()
	b.mu.Unlock()
	b.nudge()
}

// state samples everything the page shows. It holds b.mu only around its
// own fields: the session's own samplers (pressure, lease state, the
// generation) take their own locks and none of them is the seal's lock, so
// this keeps answering during a publish — which is exactly when the user
// is watching.
func (b *browseServer) state() browseState {
	b.mu.Lock()
	g, phase, openErr := b.g, b.phase, b.openErr
	last, over, streams := b.lastPublish, b.over, len(b.streams)
	// The job is COPIED under the lock. The publish goroutine mutates it
	// (under the same lock), and marshalling the live pointer outside the
	// lock would be a data race the race detector finds and a user never
	// would.
	var job *publishJob
	if b.job != nil {
		cp := *b.job
		job = &cp
	}
	b.mu.Unlock()

	st := browseState{
		Phase:     phase,
		Error:     openErr,
		Volume:    b.prefix,
		Mode:      "read-only",
		Branch:    b.args.branch,
		Lease:     "none",
		Publish:   job,
		TestHooks: over.on,
		Streams:   streams,
	}
	if b.args.rw {
		st.Mode = "read-write"
	}
	if g == nil {
		return st
	}
	st.Generation = g.gfs.Generation()
	if g.lease != nil {
		ls := g.lease.State()
		st.Lease, st.LeaseAge = ls.Name(), ls.Age.Seconds()
	}
	bytes, nodes := g.pressure()
	b.mu.Lock()
	if bytes >= 0 {
		// A readable sample replaces the remembered one. A -1 means the
		// overlay is mid-seal, and the last known numbers are the truth
		// about what the seal is publishing — not zero.
		b.stagedBytes, b.stagedNodes = bytes, nodes
	}
	st.StagedBytes, st.DirtyNodes = b.stagedBytes, b.stagedNodes
	b.mu.Unlock()
	// StagedFiles is the file count behind those bytes; overlay.Stats has
	// it, and pressure() (shared with the checkpoint policy) does not
	// return it, so it is sampled here — under the SAME lock pressure
	// uses. ovMu guards overlay liveness, not the seal, which is what
	// lets this keep answering while a checkpoint runs; reading g.ov
	// without it would be a data race against the seal that retires it.
	g.ovMu.RLock()
	ov, spent := g.ov, g.spent
	g.ovMu.RUnlock()
	if ov != nil && !spent {
		if s, err := ov.Stats(); err == nil {
			st.StagedFiles = s.StagedFiles
		}
	}
	st.UploadBacklog = g.uploadBacklog()
	if over.on {
		// The overrides land last so they can express states a real
		// volume in this session cannot reach (a stale lease, a staged
		// drag-and-drop) for a driver test to assert on.
		if over.lease != "" {
			st.Lease = over.lease
		}
		if over.stagedFiles != 0 {
			st.StagedFiles = over.stagedFiles
		}
		if over.stagedBytes != 0 {
			st.StagedBytes = over.stagedBytes
			st.DirtyNodes = over.stagedFiles
		}
		if over.uploadBacklog != 0 {
			st.UploadBacklog = over.uploadBacklog
		}
	}
	if b.args.rw && b.interval > 0 {
		left := b.interval - time.Since(last)
		if left < 0 {
			left = 0
		}
		st.NextPublishS = int64(left.Seconds())
	}
	return st
}

func (b *browseServer) serveInfo(w http.ResponseWriter, _ *http.Request) {
	writeBrowseJSON(w, http.StatusOK, b.state())
}

// ---- publish -------------------------------------------------------------

// servePublish is 202-and-a-job-id, never a synchronous 200.
//
// genSession.checkpoint takes g.mu and holds it across the entire seal —
// fence, freeze, walk, upload, flip. On a large drag that is minutes. A
// handler that blocked on it would hold an HTTP request open for the whole
// thing, hit every intermediary timeout there is, and give the user a
// spinner with no information in it. So the work runs on its own
// goroutine, on the SESSION context rather than the request's (a request
// context is cancelled the moment the 202 is written, which would abort
// the seal it just accepted), and the page watches /events.
//
// A second concurrent request gets 409 rather than a queue. g.mu already
// serializes it; saying so is better than letting two clicks silently
// become one publish and one long wait.
func (b *browseServer) servePublish(w http.ResponseWriter, _ *http.Request) {
	b.mu.Lock()
	g, ctx := b.g, b.ctx
	switch {
	case g == nil:
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the volume is still opening; publish is not available yet"})
		return
	case !g.rw:
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusForbidden, map[string]string{
			"error": "this is a read-only session (start pelfs browse with --rw to publish)"})
		return
	case b.job != nil && b.job.State == "running":
		id := b.job.ID
		b.mu.Unlock()
		// 409, with the job that is holding the lock, so the page can
		// follow it instead of retrying.
		writeBrowseJSON(w, http.StatusConflict, map[string]string{
			"error": "a publish is already running", "job": id})
		return
	}
	job := &publishJob{ID: newJobID(), State: "running", Started: time.Now()}
	b.job = job
	stall := b.over.publishStall
	b.mu.Unlock()
	b.publishWG.Add(1)
	go func() {
		defer b.publishWG.Done()
		if stall > 0 {
			// --test-hooks only: makes "publishing" long enough for a
			// browser driver to see it. A real seal provides its own
			// duration.
			select {
			case <-time.After(stall):
			case <-ctx.Done():
			}
		}
		summary, err := g.checkpoint(ctx)
		b.mu.Lock()
		job.Ended = time.Now()
		if err != nil {
			job.State, job.Error = "failed", err.Error()
		} else {
			job.State, job.Summary = "done", summary
			b.lastPublish = job.Ended
		}
		b.mu.Unlock()
		b.nudge()
	}()
	b.nudge()
	writeBrowseJSON(w, http.StatusAccepted, map[string]any{
		"job": job.ID, "watch": "/events",
	})
}

// waitForPublish joins a publish the user asked for. See the teardown
// section of runBrowse for why it is waited for rather than abandoned.
func (b *browseServer) waitForPublish() { b.publishWG.Wait() }

func newJobID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// ---- tickets -------------------------------------------------------------

// serveMintTicket is the authenticated half of the download pair: it
// checks (in U11, against the real permission model) and then mints. The
// /d/<ticket> route does no checking at all, because it has no principal
// to check with.
func (b *browseServer) serveMintTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	if b.downloadSource() == nil {
		// M1 has no file surface. Saying so beats minting a ticket that
		// can only ever 404.
		writeBrowseJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "this build has no file surface yet: downloads arrive with the JSON API (U11)"})
		return
	}
	tk, err := b.sessions.MintTicket(req.Path)
	if err != nil {
		writeBrowseJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeBrowseJSON(w, http.StatusOK, map[string]string{
		"url": "/d/" + tk,
		"ttl": browsesession.TicketTTL.String(),
	})
}

// ---- events --------------------------------------------------------------

// serveEvents is the SSE stream.
//
// IT CARRIES SNAPSHOTS, NOT DELTAS, and that is the whole answer to
// reconnection: a browser will drop and re-establish this stream (a
// suspended laptop, a network blip, a driver test that reloads the page),
// and every connection begins with a complete state frame and every
// subsequent frame is also complete. So there is nothing to replay,
// Last-Event-ID is not needed, and a reconnected page cannot show a stale
// or half-updated view. `retry:` asks for a one-second reconnect, which is
// the browser's own mechanism and needs no code on the page.
//
// The cost of snapshots is bytes on the wire, and the whole document is a
// few hundred of them at 500 ms — for one tab on loopback, that is not a
// cost at all.
func (b *browseServer) serveEvents(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	// Proxy buffering is not a thing on loopback, but the header is free
	// and costs one line of confusion later.
	h.Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	nudge, done := b.subscribe()
	defer b.unsubscribe(nudge)

	fmt.Fprint(w, "retry: 1000\n\n")
	var last string
	send := func() bool {
		st := b.state()
		doc, err := json.Marshal(st)
		if err != nil {
			return false
		}
		if string(doc) == last {
			return true
		}
		last = string(doc)
		if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", doc); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send() {
		return
	}
	// 500 ms is the resolution of "next automatic publish in 3m41s"
	// counting down, and it is the ceiling on how long a state change
	// nobody nudged (a lease going stale, an upload backlog draining)
	// takes to appear.
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			// The process is going away. Say so, so the page can show
			// "pelfs exited" rather than "connection lost", and return so
			// Server.Shutdown is not left waiting on a response that is
			// open by design.
			fmt.Fprint(w, "event: bye\ndata: {\"reason\":\"pelfs browse is exiting\"}\n\n")
			_ = rc.Flush()
			return
		case <-nudge:
			if !send() {
				return
			}
		case <-tick.C:
			if !send() {
				return
			}
		}
	}
}

// subscribe registers a stream. The nudge channel is buffered depth 1 and
// written non-blockingly, so a slow reader delays only itself: nothing on
// a session path may ever block on a browser.
func (b *browseServer) subscribe() (nudge chan struct{}, done chan struct{}) {
	nudge = make(chan struct{}, 1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		// Closed already: hand back a done that is already closed so the
		// handler says goodbye and returns.
		c := make(chan struct{})
		close(c)
		return nudge, c
	}
	if b.doneCh == nil {
		b.doneCh = make(chan struct{})
	}
	b.streams[nudge] = struct{}{}
	return nudge, b.doneCh
}

func (b *browseServer) unsubscribe(nudge chan struct{}) {
	b.mu.Lock()
	delete(b.streams, nudge)
	b.mu.Unlock()
}

// nudge wakes every stream. Non-blocking by construction: see subscribe.
func (b *browseServer) nudge() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.streams {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

// closeStreams tells every stream the process is leaving. Idempotent,
// because it is called both from the teardown path and from
// Server.RegisterOnShutdown.
func (b *browseServer) closeStreams() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	if b.doneCh != nil {
		close(b.doneCh)
	}
}

// ---- the page ------------------------------------------------------------

// servePage renders the one HTML file.
//
// The CSP carries a per-response nonce rather than 'unsafe-inline'. The
// page is one file with one inline <script> and one inline <style>, which
// is the point of a milestone with no bundler — and 'unsafe-inline' would
// give away the exact protection that makes A5 (the volume holds files the
// user did not write) survivable. A nonce keeps both: one file, and a
// script-src a stored-XSS payload cannot satisfy.
func (b *browseServer) servePage(w http.ResponseWriter, _ *http.Request) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, "cannot mint a CSP nonce", http.StatusInternalServerError)
		return
	}
	// base64url, not standard base64: CSP's nonce grammar accepts both, and
	// the URL alphabet has no '+' or '/'. html/template escapes a '+' in an
	// attribute value to &#43;, which a browser decodes back — so a
	// standard-alphabet nonce works only by way of entity decoding, and a
	// security-critical attribute should not depend on that.
	nonce := base64.RawURLEncoding.EncodeToString(raw[:])
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
			"img-src 'self' data:; connect-src 'self'; object-src 'none'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := browsePage.Execute(w, map[string]any{
		"Nonce":      nonce,
		"Volume":     b.prefix,
		"SessionHdr": httpguard.SessionHeader,
	}); err != nil {
		// The header is already out by the time a template error can
		// happen, so there is nothing to do but say so in the log.
		ui.Warn("render the browse page: {error}", "error", err)
	}
}

// ---- test hooks ----------------------------------------------------------

// serveTestHook overrides what the page reports.
//
// WHY A FLAG AND NOT A BUILD TAG. A build tag would mean the browser-driver
// suite runs a DIFFERENT BINARY from the one CI ships and users install,
// which is the one property a browser test is there to check. So it is a
// flag, and three things make that safe rather than convenient:
//
//   - it is off by default and there is no environment variable for it;
//   - it is on httpguard.SurfaceAPI, so it needs the session credential —
//     anything that can reach it can already publish, so it adds no reach;
//   - it announces itself twice, in the terminal at startup and in a
//     banner on the page, so a session running with it cannot be mistaken
//     for a real one.
//
// It sets no state on the volume. It only changes what the page is TOLD,
// which is precisely what a driver test needs and is the least dangerous
// thing that could work.
func (b *browseServer) serveTestHook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Lease          string `json:"lease"`
		StagedFiles    int    `json:"staged_files"`
		StagedBytes    int64  `json:"staged_bytes"`
		UploadBacklog  int64  `json:"upload_backlog"`
		PublishStallMS int    `json:"publish_stall_ms"`
		DownloadBody   string `json:"download_body"`
		Reset          bool   `json:"reset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	b.mu.Lock()
	if req.Reset {
		b.over = testOverrides{on: true}
	} else {
		b.over.lease = req.Lease
		b.over.stagedFiles = req.StagedFiles
		b.over.stagedBytes = req.StagedBytes
		b.over.uploadBacklog = req.UploadBacklog
		b.over.publishStall = time.Duration(req.PublishStallMS) * time.Millisecond
		b.over.downloadBody = req.DownloadBody
	}
	b.mu.Unlock()
	b.nudge()
	writeBrowseJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func writeBrowseJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
