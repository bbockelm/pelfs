package main

// `pelfs browse` is docs/design-webui.md's whole plan: a loopback HTTP
// listener, and on it TWO pages with two addresses.
//
//	GET /          the file manager (internal/webui's committed bundle)
//	GET /connect   the connection page (browse.html, hand-written)
//
// The file manager is at `/` because that is what the verb promises, and the
// connection page is where the credential desk, the SSO cards and the
// generated Cyberduck profile live. BOTH render the durability panel, from
// the same `/events` snapshot and in the same words — see
// internal/webui/durability_test.go, which fails if the two ever drift —
// because that panel is the two things a file manager cannot give: a publish
// button and an honest answer to "is my data in the federation yet".
//
// docs/design-guiclients.md identified the trap this verb exists to close: a
// modest drag-and-drop finishes, the user closes the client, and nothing has
// been published for up to five minutes. Neither half of that is a
// file-manager feature, which is why the panel is above the grid rather than
// behind a tab, and on both pages rather than on one.
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

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	"github.com/bbockelm/pelfs/internal/vfsdav"
	"github.com/bbockelm/pelfs/internal/webapi"
	"github.com/bbockelm/pelfs/internal/webui"
)

// browseAssets is the CONNECTION page, served at /connect. One file,
// hand-written, no bundler, no Node — and no third-party JavaScript, which is
// why the CSP below can be strict enough to make a stored-XSS finding
// harmless. The file manager at / is internal/webui's bundle; see
// appHandler.
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
	// port is --port: 0 means "the first free port at or above 8443", -1
	// means "an OS-chosen ephemeral one", anything else is an exact
	// request. See browseListen.
	port int
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
		fs.IntVar(&a.port, "port", 0, browsePortUsage)
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
		stateRoot:  o.stateRoot(),
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
	// can touch the network. The port is PROBED FROM 8443 UPWARD rather
	// than taken from the OS, because it is baked into every connection
	// file this session hands out and an OS-chosen one made every generated
	// profile and saved bookmark single-use; the probe, the window and the
	// security reasoning are all in cmd/pelfs/browseport.go.
	ln, probed, err := browseListen(a.port)
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	sayBrowsePort(port, a.port, probed)
	sessions, err := browsesession.New()
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
	// The persistent client identity lives in the state directory, beside
	// the volume signing key and under the same 0700 — and it is created
	// LAZILY, so a session that never generates a connection profile leaves
	// no new secret behind. Opening it can fail (a file from a future pelfs,
	// a corrupt one), and that is a startup failure rather than a surprise
	// at the first download: a session that cannot agree with the profiles
	// this volume has already handed out should not be serving one.
	identity, err := localoauth.OpenIdentity(stateDir)
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
	// And the grants a human already authorized, beside it and under the
	// same rules — 0600, lazily created, atomically written. This is what
	// makes a saved Cyberduck bookmark reconnect across a restart with NO
	// CLICK: the refresh token the client is holding is recognised because
	// this file remembers an HMAC of it. Consent is unchanged and is still
	// required to CREATE a grant; internal/localoauth/grants.go is the
	// argument for why those are different things.
	//
	// Unreadable is a startup failure for the same reason the identity is:
	// the alternative is silently forgetting every connection, which looks
	// to the user exactly like the bug this file exists to fix.
	grants, err := localoauth.OpenGrants(stateDir)
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
	bs, err := newBrowseServer(prefix, a, o.snapshotInterval, sessions, port, identity, grants)
	if err != nil {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}
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

	// ---- 2. The device-flow hook, which is step 3 of
	// docs/design-webui.md's ordering: after the page is servable, before
	// anything can prompt.
	//
	// THIS IS THE ONLY PLACE IN PELFS THAT INSTALLS IT. The hook is
	// process-wide (an atomic.Pointer in pelican's oauth2), so installing
	// it in internal/pelicanobj — where the flow actually fires, from
	// primeCredential — would change `pelfs mount` and `pelfs get` too, and
	// their user is at a terminal that already gets the URL. See
	// cmd/pelfs/ssoprompt.go for what the handler may and may not do; the
	// short version is that it blocks the user's own login, so it does one
	// map insert and returns.
	//
	// Removed on the way out rather than left installed: this process
	// outlives the volume only during teardown, and a prompt raised then
	// has nowhere to go — the streams are already closed.
	defer installPromptHandler(bs)()

	// ---- 3. Now the volume. This is where a device-flow prompt fires,
	// and by construction the page is already loadable when it does.
	//
	// A FAILURE HERE DOES NOT END THE PROCESS AT ONCE, and that is the fix
	// for the report this comment is written under: "whenever I start
	// read-write, I just get a page that says 'reading the overlay…'. Never
	// seems to progress." The page had already been printed, opened and
	// loaded by the time the open failed — a killed session's branch lease
	// is the ordinary way in, since it outlives its holder by a TTL — and
	// the process then exited inside the second it took the browser to
	// attach. What the user was left looking at was a tab whose event
	// stream had died against a closed port, and a page that renders every
	// phase that is not "ready" with the same "reading the overlay…" line.
	// Nothing about it said the volume had refused to open, or why.
	//
	// So the failure is now SERVED rather than raced: the reason goes on
	// the page, the listener stays up long enough for a browser to attach
	// and show it, and the exit is an orderly Shutdown, which sends every
	// stream `event: bye` — the difference between a page that says "pelfs
	// browse is exiting" and a page that says nothing at all. The exit code
	// is unchanged, and so is the terminal's error line: a script sees what
	// it always saw, a few seconds later.
	fail := func(err error) int {
		err = browseOpenFailure(err, stateDir, prefix)
		// setFailed FIRST, so the frame is already queued for any stream
		// that is attached by the time the terminal line is written.
		bs.setFailed(err)
		// The terminal is still where a pelfs error belongs — the tab may
		// never have been opened at all — it is simply no longer the only
		// place the reason exists.
		code := exitErr(err)
		bs.lingerAfterFailedOpen(guard.Origin())
		// The orderly close, in the teardown's order and for its reasons:
		// the streams are told the process is leaving, and Shutdown can
		// then return instead of waiting on a response that is open by
		// design. There is no volume to seal and no lease to release —
		// nothing below this line in the happy path has run.
		bs.closeStreams()
		shutCtx, cancelShut := context.WithTimeout(ctx, 5*time.Second)
		_ = srv.Shutdown(shutCtx)
		cancelShut()
		_ = g.stats.Finalize(code, false)
		return code
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
		// Seal on idle (U10). A tab has no unmount, and 200 documents at
		// ~2 MB fire neither write-pressure trigger, so without this a
		// finished drag-and-drop can sit unpublished until the interval
		// comes round — with the browser closed and the user telling a
		// collaborator the data is there.
		//
		// The ticker is created here rather than inside run() so the defer
		// that stops it belongs to the function that owns the session.
		idle := newIdleSealer(bs, g, o.snapshotInterval)
		idleTick := time.NewTicker(idleSampleInterval)
		defer idleTick.Stop()
		go idle.run(sessionCtx, idleTick.C)
		ui.Info("the session also publishes on its own once the last browser tab "+
			"has been gone for {window} with nothing written",
			"window", idle.window)
	}

	// ---- 4. Serve until interrupted. Ctrl-C is the unmount: this verb is
	// deliberately not a daemon, because a background browse session that
	// seals on a signal nobody sends is how data gets left staged for a
	// week.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	code := 0
	// WHICH DOOR THE SESSION LEFT BY IS SAID OUT LOUD. There are three, they
	// mean entirely different things — the user asked, a test asked, the
	// listener died — and until this line the teardown that follows looked
	// identical for all three. "The browse server shut down on its own" is a
	// report that cannot be diagnosed from a log that does not say whether a
	// signal arrived, so the log now says.
	select {
	case sig := <-sigs:
		ui.Info("{signal} received; stopping this browse session", "signal", sig)
	case <-browseStop:
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			ui.Error("browse listener: {error}", "error", err)
			code = 1
		}
	}

	// ---- 5. Teardown, in runMountGen's order.
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
	// port is the port the listener actually got. Every generated
	// connection file names it — the profile's `Default Port`, the DAV URL,
	// the bookmark — so it is carried rather than re-derived.
	port int
	// api is the JSON data plane (U11) and oauth is the authorization
	// server and credential registry (U7/U8). BOTH EXIST BEFORE THE VOLUME
	// DOES, which is the ordering this file is built around: the api
	// reaches the volume through b.volume, which answers webapi.ErrNotReady
	// until setReady runs, and the oauth server never touches the volume at
	// all. The WebDAV handler is the one piece that cannot be built here —
	// see setReady.
	api   *webapi.API
	oauth *localoauth.Server
	// prompts is the device-flow prompt registry (U13). It exists before
	// the volume does, because that is when the first flow fires.
	prompts *promptRegistry
	// now is the clock. nil means time.Now; a test sets it once, at
	// construction, before anything else can read it. Nothing mutates it
	// afterwards, which is why it needs no lock.
	now func() time.Time

	mu sync.Mutex
	// g is nil until the volume is open. phase is what the page shows in
	// the meantime.
	g       *genSession
	ctx     context.Context
	phase   string // "connecting" | "ready" | "failed"
	openErr string
	// binding is the volume as billy, built ONCE at setReady rather than
	// per request: vfsbilly's dir cache and residency bound belong to the
	// binding, and a fresh one per request would throw both away on every
	// listing. nil until the volume opens, which is what b.volume reports
	// as webapi.ErrNotReady.
	binding billy.Filesystem
	// dav is the WebDAV surface over that binding. It is built at setReady
	// for the reason given there, and until it exists /dav/* answers 503.
	dav http.Handler
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
	// streamsIdleSince is when the set last became empty, and the zero
	// time while any stream is open. It is set by the unsubscribe that
	// EMPTIES the set — so closing one of two tabs is not an event — and
	// zeroed by any subscribe, which is what makes a reconnecting browser
	// (the page asks for `retry: 1000`) unable to trigger a seal.
	//
	// It starts at the session's own start rather than at zero: a session
	// whose browser never attached — --open on a login node, or a WebDAV
	// client on this same listener once U6 lands — is idle in exactly the
	// sense that matters, and the quiet window then runs from its last
	// write.
	streamsIdleSince time.Time
	// beaconAt is the last sendBeacon hint. A hint, never a trigger: see
	// idleHintedWindow.
	beaconAt time.Time
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
	ID    string `json:"id"`
	State string `json:"state"` // running | done | failed | idle
	// Reason is who asked: "user" for the button, "idle" for the seal that
	// runs when the last tab has been gone for a quiet window (U10). The
	// page says which, because a generation the user did not ask for is
	// otherwise indistinguishable from one they forgot asking for.
	Reason  string    `json:"reason,omitempty"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitzero"`
	Summary string    `json:"summary,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// newBrowseServer builds the whole HTTP surface EXCEPT the WebDAV handler,
// which needs a filesystem that does not exist yet (setReady).
//
// It returns an error because two of the three pieces can refuse to be
// built — a negative listing cap, a read-only session that was asked for a
// writable authorization server — and both are startup failures rather than
// 500s on the first request. A third refusal joined them with the
// persistent client identity: an identity file in the state directory that
// cannot be read is a startup failure too, because the alternative is
// serving a session whose generated profiles disagree with the ones the
// user has installed.
//
// `id` is the persistent client identity (internal/localoauth's
// identity.go): the per-volume key that makes a generated
// .cyberduckprofile byte-identical across restarts. `grants` is the
// persistent grant roster (grants.go): what makes a program that has been
// authorized once reconnect after a restart with no consent screen. nil for
// either is the ephemeral server this verb started with — every client id
// crypto/rand, every credential dead at exit — which is what the tests that
// are not about persistence pass. `grants` without `id` is refused by
// localoauth.New, because a grant is bound to a persistent identity.
func newBrowseServer(prefix string, a browseArgs, interval time.Duration,
	m *browsesession.Manager, port int, id *localoauth.Identity,
	grants *localoauth.GrantStore) (*browseServer, error) {
	b := &browseServer{
		prefix:      prefix,
		args:        a,
		interval:    interval,
		sessions:    m,
		port:        port,
		phase:       "connecting",
		lastPublish: time.Now(),
		streams:     map[chan struct{}]struct{}{},
		over:        testOverrides{on: a.testHooks},
	}
	b.streamsIdleSince = b.lastPublish
	var err error
	// Cap 0 means webapi.DefaultCap (5000), which is U0's measured number
	// and not a guess; see that package's comment for the 100k-entry
	// measurement it comes from.
	if b.api, err = webapi.New(webapi.Config{Volume: b.volume}); err != nil {
		return nil, err
	}
	// The session's own mode is the ceiling on every credential this server
	// will ever mint, and it is named HERE, once — a read-only `pelfs
	// browse` cannot even register a client that could ask for
	// pelfs.write. Sessions is the browser-session presence check (A7
	// control 2): *browsesession.Manager satisfies it as it stands.
	//
	// Identity is what makes the CLIENT identity outlive the process;
	// Grants is what makes the CONNECTION outlive it. Between them a saved
	// bookmark works next session with no download, no reinstall and no
	// click. What does NOT change is the gesture that creates a grant in the
	// first place: consent is required on every /oauth/authorize, never
	// remembered there, and there is no password on this listener at all.
	if b.oauth, err = localoauth.New(localoauth.Config{
		Writable: a.rw,
		Volume:   prefix,
		Sessions: m,
		Identity: id,
		Grants:   grants,
	}); err != nil {
		return nil, err
	}
	// The registry's fan-out is b.nudge, and the registry calls it on its
	// own goroutine: the device-flow hook runs on the goroutine driving the
	// flow and BLOCKS it, so nothing it calls may wait on a mutex a slow
	// state() sample could be holding.
	b.prompts = newPromptRegistry(b.nowTime, b.nudge)
	return b, nil
}

// volume is webapi.VolumeFunc: the live binding, or webapi.ErrNotReady
// while the volume is still opening (which the JSON surface answers 503).
//
// A function rather than a field for the reason webapi.VolumeFunc gives —
// the route table is built before the volume exists — and it hands back the
// binding CACHED at setReady rather than building one per request.
func (b *browseServer) volume() (billy.Filesystem, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.binding == nil {
		return nil, webapi.ErrNotReady
	}
	return b.binding, nil
}

// nowTime is the server's clock: time.Now unless a test injected one.
func (b *browseServer) nowTime() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// routes is THE ROUTE TABLE. Every line names a surface, and the surface
// names the principal (internal/httpguard). Three principals reach this
// listener and no credential minted for one is accepted at another:
//
//	the page          X-Pelfs-Session, on SurfaceApp/API/Exchange/Upload/Stream
//	an <a href>       a single-use ticket in the path, on SurfaceTicket
//	a WebDAV client   Basic or Bearer, on SurfaceExternal, plus the two
//	                  routes that mint it (SurfaceNavigation, SurfaceToken)
//
// POST /oauth/token IS ON SurfaceToken AND NOT ON SurfaceExchange, and this
// comment said the opposite until the wiring pass. It matters: the caller
// is Cyberduck's Apache HttpClient making a back-channel POST, so it sends
// no Origin and no Sec-Fetch-Site (SurfaceExchange's provenance rule would
// answer 403) and its body is application/x-www-form-urlencoded, which RFC
// 6749 §4.1.3 mandates (SurfaceExchange's JSON rule would answer 415). A
// profile pointed at a SurfaceExchange token endpoint fails EVERY exchange.
// internal/httpguard.SurfaceToken exists for exactly this, and
// internal/localoauth's TestTokenEndpointCannotLiveOnSurfaceExchange pins
// it so nobody moves the route back for consistency's sake.
//
// The one thing that does NOT land here, ever, is anything that forwards to
// internal/control.
func (b *browseServer) routes(g *httpguard.Guard) http.Handler {
	r := g.NewRouter()
	// ---- the two surfaces, and their addresses --------------------------
	//
	// `/` IS THE FILE MANAGER. The verb's pitch is "browse and upload
	// files", so the address the terminal prints has to be the thing that
	// does it; a user who lands on a credential desk and has to find a link
	// to the files has been given the tool's plumbing as its front door.
	//
	// `/connect` IS THE CONNECTION PAGE — M1's hand-written file: the
	// credential desk (U7/U8), the SSO cards (U13), and its own copy of the
	// durability panel. It keeps that panel rather than losing it, because
	// the panel is what this whole design exists for and a page a user may
	// sit on for the length of a Cyberduck setup must not be the one page
	// that cannot say whether the data is published.
	//
	// Neither page is a fallback for the other and neither is authenticated
	// at the transport: both ship no state and ask for everything over the
	// API, which is also what lets both CSPs have nothing in them to
	// smuggle. What links them is one anchor each way — see
	// webui/frontend/src/ui/Durability.tsx and browse.html's nav.
	//
	// No catch-all. The bundle's own handler falls back to index.html for
	// an unknown path so a client-side route survives a reload, but this app
	// HAS no client-side routes (there is no router in it: the open
	// directory is component state, not the URL), so a catch-all would only
	// turn a mistyped `/api/v1/fil` into an HTML page pretending to be an
	// answer. Four exact patterns instead, and a 404 is a 404.
	app := appHandler()
	r.Handle(httpguard.SurfaceApp, "GET /{$}", app)
	r.Handle(httpguard.SurfaceApp, "GET /assets/{file}", app)
	r.Handle(httpguard.SurfaceApp, "GET /brand/{file}", app)
	r.Handle(httpguard.SurfaceApp, "GET /third_party.txt", app)
	r.HandleFunc(httpguard.SurfaceApp, "GET /connect", b.servePage)
	// The bootstrap-for-session exchange: the one route that cannot
	// require the session header, because it mints it.
	r.Handle(httpguard.SurfaceExchange, "POST /api/v1/session",
		browsesession.ExchangeHandler(b.sessions))
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/info", b.serveInfo)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/publish", b.servePublish)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/download", b.serveMintTicket)
	// The SSO card's one control (U13). A prompt is dismissible because the
	// hook is ONE-WAY: nothing tells us the flow finished, failed or
	// expired, so a card the user has dealt with can only be taken off the
	// screen by the user.
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/sso/dismiss", b.serveDismissPrompt)
	// The idle-seal hint (U10). SurfaceExchange, not SurfaceAPI, and that
	// is forced rather than chosen: navigator.sendBeacon cannot set a
	// request header, so X-Pelfs-Session cannot be on it. Exchange is the
	// surface class whose rules are exactly right for that — every
	// provenance and content-type check, with the credential in the body —
	// and the handler checks the session token itself.
	r.HandleFunc(httpguard.SurfaceExchange, "POST /api/v1/beacon", b.serveBeacon)
	r.HandleFunc(httpguard.SurfaceStream, "GET /events", b.serveEvents)
	// The ticketed download, over the volume (see downloadSource). An
	// <a href> cannot carry a request header, so authority is a single-use
	// 30-second ticket in the path and this route accepts no session
	// credential at all — see internal/browsesession.DownloadHandler.
	r.Handle(httpguard.SurfaceTicket, "GET /d/{"+browsesession.TicketPathValue+"}",
		browsesession.DownloadHandler(b.sessions, b.downloadSource()))

	// ---- the credential surface (U7/U8) ---------------------------------
	//
	// The two navigation routes and the token endpoint are what an external
	// WebDAV client touches; the three /api/v1/credentials routes are what
	// the PAGE touches to hand it a profile and to take it away again. A
	// credential the user cannot see is a credential the user cannot revoke
	// (docs/design-webui.md, A6), so the list and the revoke are as much
	// part of this milestone as the download is.
	//
	// SurfaceNavigation cannot require a custom header — Cyberduck reaches
	// /oauth/authorize by opening the user's browser at it — so its
	// controls are elsewhere entirely: an exact-string redirect_uri
	// allowlist, a per-download client_id, PKCE S256, and one real gesture
	// on a consent screen that runs no script. internal/localoauth's
	// package comment is the specification; nothing here re-decides any of
	// it.
	r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", b.oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceNavigation, "POST /oauth/authorize", b.oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceToken, "POST /oauth/token", b.oauth.TokenHandler())
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/credentials", b.serveListCredentials)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/credentials", b.serveNewCredential)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/credentials/revoke", b.serveRevokeCredential)

	// ---- WebDAV (U6) ----------------------------------------------------
	//
	// The session token is REFUSED on this surface and an Authorization
	// header is refused on the API surface: that pair is the two-principals
	// rule, and it is a property of the route table rather than of a
	// handler's memory.
	r.Handle(httpguard.SurfaceExternal, davprofile.DAVPath, http.HandlerFunc(b.serveDAV))

	// ---- the JSON data plane (U11) --------------------------------------
	//
	// Eleven patterns for eight routes, all of them webapi's own; it names
	// its own surfaces, which is why this is one line and not eleven.
	b.api.Register(r)

	// ---- the branch picker (cmd/pelfs/browsebranch.go) ------------------
	//
	// On the page's surface and nowhere else: a WebDAV client's credential
	// cannot move the session it is connected to.
	b.registerBranchRoutes(r)

	if b.args.testHooks {
		r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/testhook", b.serveTestHook)
	}
	return r
}

// downloadSource is the file surface behind /d/<ticket>: the volume, through
// the same vfsbilly binding and the same internal/fsperm mode check every
// other frontend uses.
//
// The synthetic source stays AHEAD of it. A browser-driver run passes
// --test-hooks precisely to reach states the volume is not in, and a driver
// that had to create a file before it could exercise the ticket round trip
// would be testing the upload path instead of the ticket. The flag is off in
// every real session, so the real source is what a user ever meets.
func (b *browseServer) downloadSource() browsesession.Source {
	if b.args.testHooks {
		return testDownloadSource{b}
	}
	return b.api.Source()
}

// serveDAV is the WebDAV surface, or a 503 while the volume is still
// opening.
//
// A DELEGATOR rather than the handler itself, and that is the one place the
// wiring could not take its author's line verbatim: vfsdav.New reads the
// filesystem's write capability AT CONSTRUCTION (vfsdav.go's `writable:
// billy.CapabilityCheck(bfs, ...)`), so it cannot be built before there is a
// filesystem — and this route table is built before the volume opens,
// deliberately, so that a device-flow prompt has a page to appear on. The
// alternative was a lazy billy.Filesystem that answered the capability
// question from browseArgs.rw, which would have put a second opinion about
// writability next to billy's, and billy's is the one every other surface
// asks. So the handler is built at setReady and this stands in front of it.
//
// 503 rather than 401: the credential is not the problem, and a WebDAV
// client told 401 goes looking for a password it was never meant to have.
func (b *browseServer) serveDAV(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	h := b.dav
	b.mu.Unlock()
	if h == nil {
		w.Header().Set("Retry-After", "2")
		http.Error(w, "the volume is still opening", http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
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
	// signal U10 seals on.
	Streams int `json:"streams"`
	// IdleSealS is the quiet window an unattended session seals after, in
	// seconds, and 0 when idle sealing is off (read-only, or
	// --snapshot-interval 0). It is on the document so the page can promise
	// what will happen when the tab closes rather than leaving it a
	// surprise.
	IdleSealS int64 `json:"idle_seal_s,omitempty"`
	// Prompts are the live device-flow cards (U13): what the user must do
	// to authorize this session. Never a token — see ssoPrompt.
	Prompts []ssoPrompt `json:"prompts,omitempty"`
}

// setReady binds the volume to the surfaces that were registered without
// one.
//
// THE BINDING IS BUILT HERE, ONCE, and not per request: vfsbilly carries a
// directory cache and a residency bound, and a fresh binding per HTTP
// request would discard both on every listing — which is the difference
// between one readdir and one per navigation on a large directory.
//
// vfsbilly.NewFor/NewReadOnlyFor with OpenAnsweredHere, never the NFS
// constructors. Those carry the owner override (OpenAnsweredByClient),
// which lets a file's owner write it whatever the mode says: defensible for
// NFSv3, where the client already answered open(2) from our ACCESS reply,
// and indefensible for an HTTP handler, where THIS check is the open check.
// A call-site allowlist test in internal/vfsbilly fails any caller here that
// reaches for the other four.
func (b *browseServer) setReady(g *genSession, ctx context.Context) {
	var bind billy.Filesystem
	if g.ov != nil {
		bind = webapi.NewVolume(g.ov, vfsbilly.ProcessCred())
	} else {
		// A read-only session has no overlay, so the binding is over the
		// published generation. Everything downstream is identical: billy
		// answers "no write capability", and webapi and vfsdav both refuse
		// a mutation from that one answer rather than from a flag of their
		// own.
		bind = vfsbilly.NewReadOnlyFor(g.gfs, vfsbilly.ProcessCred(), vfsbilly.OpenAnsweredHere)
	}
	dav, err := vfsdav.New(vfsdav.Config{
		FS: bind, Prefix: strings.TrimSuffix(davprofile.DAVPath, "/"),
		Auth: b.oauth.DAVAuth(davRealm),
	})
	if err != nil {
		// Only a nil FS or a nil Auth can produce this, so it is a wiring
		// bug rather than anything a session can hit. Say so and leave
		// /dav/* answering 503; nothing else about the session is harmed.
		ui.Warn("the WebDAV surface could not be built ({error}); /dav/ is unavailable this session",
			"error", err)
	}
	b.mu.Lock()
	b.g, b.ctx, b.phase = g, ctx, "ready"
	b.binding = bind
	if err == nil {
		b.dav = dav
	}
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
		Phase:  phase,
		Error:  openErr,
		Volume: b.prefix,
		Mode:   "read-only",
		// The branch the flags asked for until the volume is open, and the
		// one the SESSION is on after that. They differ the moment the
		// branch picker is used, and a durability panel still naming the
		// branch a switch moved off is the stale binding this route was
		// most at risk of.
		Branch:    b.args.branch,
		Lease:     "none",
		Publish:   job,
		TestHooks: over.on,
		Streams:   streams,
		// Sampled OUTSIDE b.mu: the registry has its own lock and the
		// device-flow goroutine that writes it must never wait behind a
		// state sample. A prompt raised before any browser attached is on
		// the first frame every stream receives, which is what stops it
		// being lost.
		Prompts: b.prompts.Cards(),
	}
	if b.args.rw {
		st.Mode = "read-write"
		if w := idleQuietWindow(b.interval); w > 0 {
			st.IdleSealS = int64(w.Seconds())
		}
	}
	if g == nil {
		return st
	}
	st.Branch = g.currentBranch()
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
	job := &publishJob{ID: newJobID(), State: "running", Reason: "user", Started: b.nowTime()}
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
		b.finishJob(job, summary, err)
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

// serveMintTicket is the authenticated half of the download pair: it mints,
// and the /d/<ticket> route does no checking at all, because it has no
// principal to check with.
//
// It deliberately does NOT pre-check readability. The permission model is
// internal/fsperm through internal/vfsbilly and it is applied where the
// bytes are opened (webapi's Source), which is the only place that can be
// right — a check here would be a second opinion, evaluated at a different
// moment, about a file another writer may have chmod'd in between. What a
// ticket carries is a path, not an authorization: redeeming one for a file
// the session may not read is a 403 from the layer that owns the answer.
func (b *browseServer) serveMintTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	if _, err := b.volume(); err != nil {
		// The volume is still opening. Saying so beats minting a ticket
		// that expires in thirty seconds and can only ever 503.
		writeBrowseJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the volume is still opening; downloads are not available yet"})
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

// ---- the idle hint -------------------------------------------------------

// serveBeacon records a `navigator.sendBeacon` hint that the tab is going
// away, which SHORTENS the idle-seal wait and can never start one.
//
// Three properties, and the first two are the reason this is not simply
// "seal when the beacon arrives":
//
//   - A beacon is best-effort BY SPECIFICATION. Browsers may drop it, and
//     they always drop it when the process dies. A durability decision that
//     rested on one would be wrong exactly when it mattered most.
//   - visibilitychange fires when a tab is merely HIDDEN — switched away
//     from, or minimised — with the stream still open and the user still
//     working. So the hint only has an effect while the stream set is
//     empty, which is a fact the sealer checks and this handler does not
//     have to know.
//   - It cannot carry X-Pelfs-Session, because sendBeacon sets no request
//     headers. The token is in the body instead, checked here in
//     constant time by the same verifier the guard uses.
func (b *browseServer) serveBeacon(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	if !b.sessions.ValidSession(req.Session) {
		writeBrowseJSON(w, http.StatusUnauthorized, map[string]string{"error": "no valid session"})
		return
	}
	b.mu.Lock()
	b.beaconAt = b.nowTime()
	b.mu.Unlock()
	// 204: sendBeacon discards the response, and there is nothing to say.
	w.WriteHeader(http.StatusNoContent)
}

// ---- the SSO card --------------------------------------------------------

// serveDismissPrompt takes one device-flow card off the screen. See
// promptRegistry.Dismiss for why dismissal is a user action rather than
// something the flow's completion could do.
func (b *browseServer) serveDismissPrompt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	found := b.prompts.Dismiss(req.ID)
	b.nudge()
	writeBrowseJSON(w, http.StatusOK, map[string]bool{"dismissed": found})
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
	// A tab is attached, so no quiet window is running. This is the line
	// that makes an SSE reconnect — which happens routinely, one second
	// after any blip — unable to cause a seal.
	b.streamsIdleSince = time.Time{}
	return nudge, b.doneCh
}

func (b *browseServer) unsubscribe(nudge chan struct{}) {
	b.mu.Lock()
	delete(b.streams, nudge)
	// Only the unsubscribe that EMPTIES the set starts the window: two
	// windows open means one closing is not idle.
	if len(b.streams) == 0 {
		b.streamsIdleSince = b.nowTime()
	}
	b.mu.Unlock()
}

// idleSignal is everything the idle sealer needs to know about the
// browser: how many streams are attached, when the set became empty, and
// when the last sendBeacon hint arrived.
func (b *browseServer) idleSignal() (streams int, idleSince, hint time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.streams), b.streamsIdleSince, b.beaconAt
}

// claimIdleJob takes the publish slot for an automatic seal, and reports
// false when it cannot have it.
//
// It is the same slot the "Publish now" button takes, which is what makes
// the two mutually exclusive: genSession.checkpoint holds g.mu across the
// entire seal, so a second concurrent caller would wait minutes and then
// publish nothing. A user clicking Publish while this runs gets the 409
// servePublish already sends, with this job's id to follow.
//
// It refuses once the session is going away (b.closed, which teardown's
// FIRST step sets), so nothing new starts while the exit path is joining:
// sealAtExit publishes whatever is left, so refusing here loses nothing.
// The WaitGroup is incremented under the same lock that observes closed,
// which is what makes "no Add after Wait" a property rather than a hope.
func (b *browseServer) claimIdleJob() (*publishJob, *genSession, context.Context, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.g == nil || !b.g.rw {
		return nil, nil, nil, false
	}
	if b.job != nil && b.job.State == "running" {
		return nil, nil, nil, false
	}
	job := &publishJob{ID: newJobID(), State: "running", Reason: "idle", Started: b.nowTime()}
	b.job = job
	b.publishWG.Add(1)
	return job, b.g, b.ctx, true
}

// finishJob records how a publish ended. Shared by the button's goroutine
// and the idle sealer so that "what the page shows when a publish ends" has
// one implementation. It does NOT touch publishWG: each caller owns its own
// Add/Done pairing, which is where the teardown join is decided.
func (b *browseServer) finishJob(job *publishJob, summary string, err error) {
	b.mu.Lock()
	job.Ended = b.nowTime()
	if err != nil {
		job.State, job.Error = "failed", err.Error()
	} else {
		job.State, job.Summary = "done", summary
		b.lastPublish = job.Ended
	}
	b.mu.Unlock()
	b.nudge()
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

// appHandler is the file manager: internal/webui's committed bundle, on the
// route table.
//
// internal/webui owns the bundle's own two behaviours (immutable caching for
// the hashed assets, no-store for index.html) and deliberately owns none of
// the security work, so the one thing added here is the policy — webui.CSP,
// which is the bundle's own statement of what it loads.
//
// WHY THE HEADER HAS TO BE SET AT ALL, since the guard already sets one:
// internal/httpguard puts `default-src 'none'` on every response
// (securityHeaders), which is exactly right for a JSON answer and leaves the
// app a BLANK PAGE — index.html arrives and its own <script src> is refused.
// That is what happened the first time this route existed; it is one of the
// two things that only broke once the app was reachable. webui.CSP is the
// same shape with the bundle's own sources named. It is `'self'` and not a
// nonce because every byte of the bundle's script and style is a hashed file:
// see webui.CSP for why 'unsafe-inline' must never join it.
func appHandler() http.Handler {
	bundle := webui.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", webui.CSP)
		bundle.ServeHTTP(w, r)
	})
}

// servePage renders the connection page: one HTML file, at /connect.
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
