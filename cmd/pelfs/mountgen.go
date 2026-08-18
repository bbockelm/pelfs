package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/nfsmount"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// statsInterval is how often a live session rewrites its statistics file.
const statsInterval = 30 * time.Second

// newSessionID names one mount session uniquely; it identifies the lease
// holder to any other client that finds the prefix busy.
func newSessionID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102T150405Z"), host, hex.EncodeToString(b[:]))
}

// genSession is one `pelfs mount-gen` session: the served generation, the
// optional write overlay, and the session-level facilities around them:
// statistics, the advisory write lease, and the control socket.
//
// It also owns the SEAL ANCHOR (sb/prevRaw): the generation this session's
// next seal grows from. A mid-session checkpoint advances it, which is the
// only state a checkpoint changes (see checkpoint).
type genSession struct {
	prefix     string
	branch     string
	tag        string
	stateDir   string
	mountpoint string
	backend    string
	sessionID  string
	started    time.Time
	rw         bool
	noSeal     bool

	overlayDir string
	inner      pelicanobj.Store // counted transport; see countedStore
	gfs        *genfs.FS
	ov         *overlay.FS // nil unless --rw

	stats     *stats.Collector
	statsPath string
	lease     *lease.Lease // held for writable sessions unless --no-lease

	dek            []byte
	identityKey    []byte
	keyID          uint32
	signingKeyPath string

	// mu serializes sealing: a control-socket checkpoint and the seal at
	// unmount must never overlap, and both move the anchor.
	mu      sync.Mutex
	sb      *superblock.Superblock
	prevRaw []byte

	// ovMu guards overlay LIVENESS only, never a seal in progress: the
	// statistics sampler must keep answering while a checkpoint runs, and
	// overlay.FS serializes its own operations anyway.
	ovMu  sync.RWMutex
	spent bool // the overlay was sealed and retired; no further seal

	// down times everything between the payload exiting and the process
	// exiting. It stays inert until the exit path calls begin().
	down *phaseClock
	// downOnce draws the teardown boundary exactly once, from whichever
	// path first notices the session is over: the payload exiting, a
	// signal, or an unmount performed from outside this process. The
	// racing candidates are on different goroutines, so the Once is what
	// makes the clock's fields safe as well as the boundary singular.
	downOnce sync.Once

	// Session upload accounting, for the periodic "still uploading" line.
	uploadMu    sync.Mutex
	uploadPacks int
	uploadBytes int64
	uploadSaid  time.Time

	// closeContent releases the write path's content store and its
	// journal, in that order. Nil when the session keeps its content in
	// staging files.
	closeContent func() error

	// reclaimFn overrides how a retired directory's bytes are freed; nil
	// takes the background default. Only tests set it.
	reclaimFn func(string)
}

// countedStore re-forms a pelicanobj.Store around the statistics wrapper.
// The counter speaks only the object surface; the stack needs the two
// Pelican-specific methods back on top of it.
type countedStore struct {
	pelicanobj.ObjectStore
	raw pelicanobj.Store
}

// The mount hands this store to refs and to the lease, both of which
// probe for transport capabilities; losing Unwrap silently disables them.
var _ pelicanobj.Unwrapper = countedStore{}

// Unwrap exposes the transport underneath the counter. Without it this
// decorator hides every capability the real store has beyond the Store
// interface: the direct-read rule for mutable objects and the
// unverified-read fallback both probe for such interfaces, and without a
// way through the counter both go silently inert on this path.
func (s countedStore) Unwrap() pelicanobj.Store { return s.raw }

func (s countedStore) ListDir(ctx context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	return s.raw.ListDir(ctx, dir)
}

func (s countedStore) StatKey(ctx context.Context, key string) (*pelicanobj.KeyInfo, error) {
	return s.raw.StatKey(ctx, key)
}

// genArgs are the mount knobs. `pelfs shell` and `pelfs mount` fill them
// in too, so the primary workflows run on exactly this path rather than
// parallel copies of it.
type genArgs struct {
	branch, tag, pubkeyHex  string
	rw, noSeal, subshell    bool
	noMemtable              bool
	signingKeyPath, backend string
	poll                    time.Duration
}

func cmdMountGen(args []string) int {
	a := genArgs{branch: "main"}
	o, pos, command, err := parseArgsWithCommand("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&a.branch, "branch", "main", "branch to mount")
		fs.StringVar(&a.tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&a.pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&a.rw, "rw", false, "mount read-write through a local overlay; unmount SEALS the changes into the next generation")
		fs.BoolVar(&a.noSeal, "no-seal", false, "with --rw, keep the overlay at unmount instead of publishing it (resume by remounting)")
		fs.BoolVar(&a.noMemtable, "no-memtable", false, "with --rw, keep written content in staging files and chunk it all at the seal, instead of packing and uploading during the session")
		fs.BoolVar(&a.subshell, "subshell", false, "run a subshell in the mount and unmount (sealing, with --rw) when it exits; a trailing `-- command [args...]` runs that instead of a shell and implies this flag")
		fs.DurationVar(&a.poll, "poll", 0, "read-only: re-check the branch head this often and swap generations live (0 = pinned, the reproducible-batch default)")
		fs.StringVar(&a.signingKeyPath, "signing-key", "", "hex Ed25519 volume signing key file to seal with (default: <state-dir>/v2-signing.key; a volume's key is per-VOLUME, so a second machine must import it)")
	})
	if err != nil {
		return exitErr(err)
	}
	if len(command) > 0 {
		a.subshell = true
	}
	if a.backend, err = resolveBackend(o); err != nil {
		return exitErr(err)
	}
	return runMountGen(o, pos[0], pos[1], command, a)
}

// openContent builds the write path's content store: writes land in an
// mmap'd ring, age out into packs, and reach the federation DURING the
// session instead of at the seal that ends it (docs/design-writepath.md).
//
// It is the default because of what it removes rather than what it adds.
// A staging session leaves every byte it wrote to be chunked, hashed and
// uploaded after the user types exit; it copies a whole file into staging
// the first time one byte of a base file is written; and its checkpoints
// freeze by hardlinking every dirty file with the mount's lock held,
// which is measured in seconds on a source tree.
//
// It returns nil — meaning staging files — only for --no-memtable.
// Encrypted volumes are served here too: the packer runs pack entries
// through the same codec publish does (zstd unless it grows them, then
// AES-256-GCM under the volume's key), so what reaches the federation is
// the same objects a seal would have written.
func (g *genSession) openContent(ctx context.Context, disabled bool) (*memtable.Store, error) {
	if disabled {
		return nil, nil
	}
	store, rep, closeStore, err := overlay.OpenContentStore(filepath.Join(g.stateDir, "content"), memtable.Options{
		Obj:               g.inner,
		Base:              g.gfs,
		Hasher:            chunkid.NewHasher(g.identityKey),
		DEK:               g.dek,
		KeyID:             int64(g.keyID),
		PromotionDistance: memtable.DefaultPromotionDistance,
		OnUpload:          g.reportSessionUpload,
	})
	if err != nil {
		return nil, fmt.Errorf("open the write path's content store: %w", err)
	}
	// Recovery is allowed to lose content — a mount is tied to a job, and
	// a crashed job usually discards its state — but it is never allowed
	// to lose it quietly.
	if rep.Loss() {
		ui.Warn("the previous session left content that could not be recovered:\n{report}", "report", rep.String())
	}
	// Once-only: the seal at exit closes it as soon as the last thing that
	// reads it is done, and the teardown defer closes it on every other
	// path. Both must be able to call it.
	g.closeContent = sync.OnceValue(closeStore)
	return store, nil
}

// markSwapped closes the swap phase and hands back the overlay, so the
// rebase that follows is timed on its own.
func (g *genSession) markSwapped(phases *phaseClock) *overlay.FS {
	phases.mark("swap")
	return g.ov
}

// longestWait renders the worst single wait, when this seal set it. A
// total says how much serving time went; the worst says whether it went
// as one stall a client would time out on, or as many nobody noticed.
func longestWait(worst time.Duration) string {
	if worst <= 0 {
		return ""
	}
	return ", longest " + worst.Round(time.Millisecond).String()
}

// sessionUploadInterval is how often a session says it is uploading. Per
// pack would be a line every second or two on a fast link; the point is
// only to make a long, slow push distinguishable from a stall, which one
// line a minute does.
const sessionUploadInterval = 30 * time.Second

// reportSessionUpload accounts for what the write path sends while the
// user works, and says so periodically.
//
// Silence here was read as a hang, and reasonably: a mount that has
// stopped answering and a mount pushing 64 MiB up a 2 MiB/s link look
// identical from the outside. Reporting the RATE is what tells them
// apart, so it is the rate this prints.
func (g *genSession) reportSessionUpload(pack string, bytes int64, elapsed time.Duration) {
	g.uploadMu.Lock()
	g.uploadPacks++
	g.uploadBytes += bytes
	packs, total := g.uploadPacks, g.uploadBytes
	since := time.Since(g.uploadSaid)
	if since < sessionUploadInterval && g.uploadSaid.After(g.started) {
		g.uploadMu.Unlock()
		return
	}
	g.uploadSaid = time.Now()
	g.uploadMu.Unlock()
	ui.Info("uploading as you write: {packs} packs, {bytes} so far (last pack {size} in {elapsed})",
		"packs", packs, "bytes", ui.ByteCount(total),
		"size", ui.ByteCount(bytes), "elapsed", elapsed.Round(time.Millisecond))
}

// runMountGen serves one generation. Reached from `pelfs mount-gen` and,
// for a v2 volume, from `pelfs shell`.
func runMountGen(o *cmdOpts, prefix, mountpoint string, command []string, a genArgs) int {
	branch, tag, pubkeyHex := a.branch, a.tag, a.pubkeyHex
	rw, noSeal, subshell := a.rw, a.noSeal, a.subshell
	signingKeyPath, backend, poll := a.signingKeyPath, a.backend, a.poll
	ctx := context.Background()

	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return exitErr(err)
	}

	g := &genSession{
		prefix:         prefix,
		branch:         branch,
		tag:            tag,
		stateDir:       stateDir,
		mountpoint:     mountpoint,
		backend:        backend,
		sessionID:      newSessionID(),
		started:        time.Now(),
		rw:             rw,
		noSeal:         noSeal,
		overlayDir:     filepath.Join(stateDir, "overlay"),
		signingKeyPath: signingKeyPath,
		down:           &phaseClock{},
	}
	// Deferred FIRST so it runs LAST: every other deferred teardown step
	// must have marked itself before the breakdown is printed.
	defer g.reportTeardown()
	g.statsPath = o.statsFile
	if g.statsPath == "" {
		g.statsPath = filepath.Join(stateDir, "pelfs-stats.json")
	}
	g.stats = stats.New(prefix, g.sessionID, g.statsPath)
	g.stats.Update(func(sum *stats.Summary) {
		sum.MountPoint = mountpoint
		sum.Branch = branch
		sum.Tag = tag
		sum.Backend = backend
		sum.Writable = rw
		sum.PrefetchMode = o.prefetch
	})
	// fail finalizes the statistics for a session that never got as far as
	// serving: a supervisor must be able to tell "died at startup" from
	// "never ran".
	fail := func(err error) int {
		_ = g.stats.Finalize(1, false)
		return exitErr(err)
	}

	// Startup is a sequence of federation round trips, and someone waiting
	// on a slow mount cannot tell which one they waited on. Each phase is
	// timed and reported together at the end, in the same spirit as the
	// seal cost line.
	startup := newPhaseClock()
	raw, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix,
		TokenPath: o.token,
		Insecure:  o.insecure,
		// Without this the client never runs a token-acquisition flow, so
		// a session with no cached credential fails at its first
		// federation read instead of asking for one.
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return fail(err)
	}
	// Probe access up front. This is what triggers the interactive flow
	// once, for the read+create+modify union a whole session needs, and it
	// turns a missing or too-narrow credential into one clear message here
	// rather than an opaque failure deep in the mount.
	startup.mark("discovery")
	if err := pelicanobj.Preflight(ctx, raw, prefix, !rw); err != nil {
		return fail(err)
	}
	startup.mark("access")
	// Every byte the stack moves — pack range reads, catalog
	// fetches, ref reads, seal uploads — goes through the counter.
	g.inner = countedStore{ObjectStore: stats.WrapStorage(raw, g.stats), raw: raw}

	var trusted ed25519.PublicKey
	if pubkeyHex != "" {
		k, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return fail(errors.New("--volume-pubkey must be 64 hex characters"))
		}
		trusted = k
	}

	// The advisory lease covers the whole write window. It is taken BEFORE
	// the branch head is read, so the generation the overlay is built over
	// cannot be advanced by another writer between the fetch and the seal,
	// and released only after the seal — which is itself a write to the
	// federation. A read-only mount takes nothing: reads never conflict.
	if rw && !o.noLease {
		l, err := g.acquireLease(ctx, o, prefix)
		if err != nil {
			return fail(err)
		}
		g.lease = l
		defer g.down.timed("lease", g.releaseLease)
	}
	startup.mark("lease")

	rstore, err := refs.New(g.inner, stateDir, trusted)
	if err != nil {
		return fail(err)
	}
	if tag != "" {
		if g.sb, g.prevRaw, err = rstore.FetchTag(ctx, tag); err != nil {
			return fail(err)
		}
		if rw {
			// A tag names a frozen generation; sealing onto it would have
			// to advance SOME branch, and guessing which is worse than
			// refusing.
			return fail(errors.New("--rw cannot mount a tag: mount the branch you intend to advance"))
		}
	} else {
		f, err := rstore.Fetch(ctx, branch)
		if err != nil {
			return fail(err)
		}
		g.sb, g.prevRaw = f.Superblock, f.Raw
	}
	sb := g.sb
	startup.mark("head")

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
				// Sealing MUST reuse the volume's identity key: it defines
				// the dedup domain, and a new one would re-upload the world.
				g.identityKey = key
			}
		}
	}

	// A path-based frontend re-descends from the root on every operation,
	// so its residency can be bounded; a FUSE binding's cannot, because
	// the kernel owns those lifetimes and tells us when to drop them.
	maxResident := 0
	if backend == "nfs" {
		maxResident = 100000
	}
	g.gfs, err = genfs.Open(ctx, genfs.Options{
		Inner:       g.inner,
		SB:          sb,
		DEK:         g.dek,
		CacheDir:    filepath.Join(stateDir, "gencache"),
		MaxResident: maxResident,
		// PackCacheBytes is left at its default: the whole-pack cache lives
		// under the state directory's gencache and outlives the session
		// deliberately, because packs are immutable and content-addressed —
		// remounting a volume must not re-fetch what the last mount already
		// pulled down.
	})
	if err != nil {
		return fail(err)
	}
	defer g.down.timed("gencache", func() { g.gfs.Close() }) //nolint:errcheck
	startup.mark("root catalog")
	g.stats.Update(func(sum *stats.Summary) { sum.Generation = sb.Generation })

	if err := g.runPrefetch(ctx, o.prefetch); err != nil {
		return fail(err)
	}
	startup.mark("prefetch")

	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return fail(err)
	}

	var srv *fuse.Server
	var nfsSrv *nfsmount.Server
	if rw {
		// The write path: a crash-safe local overlay shadows the immutable
		// generation, and unmount seals it into the next one. Nothing
		// mutates the base, so an interrupted session loses at most the
		// unsealed overlay — which survives on disk for a remount.
		ovOpts := overlay.Options{
			NextInode:      g.gfs.NextInode(),
			BaseRoot:       g.gfs.RootCatalog(),
			BaseGeneration: g.gfs.Generation(),
		}
		if ovOpts.Memtable, err = g.openContent(ctx, a.noMemtable); err != nil {
			return fail(err)
		}
		g.ov, err = overlay.Open(g.overlayDir, g.gfs, ovOpts)
		if err != nil {
			if errors.Is(err, overlay.ErrGeneration) {
				// The branch moved on while this overlay sat unsealed —
				// another writer, or a crash after a mid-session
				// checkpoint. The overlay's whiteouts and COW copies are
				// meaningful only over the generation they were recorded
				// against, so it cannot be replayed onto the new head.
				err = fmt.Errorf("%w\n"+
					"the unsealed overlay at %s was recorded over an older generation of %s.\n"+
					"its contents are intact but cannot be sealed onto the current head; move it aside to start a fresh overlay",
					err, g.overlayDir, branch)
			}
			return fail(fmt.Errorf("open overlay: %w", err))
		}
		// The content store outlives the overlay: the seal at exit renders
		// its records, so it closes after everything that reads it. Defers
		// run last-in-first-out, so registering it FIRST is what puts it
		// last.
		if closeContent := g.closeContent; closeContent != nil {
			// Captured, not re-read: the seal path is entitled to have
			// closed it already, and a nil field then is not an error.
			defer g.down.timed("content", func() { closeContent() }) //nolint:errcheck
		}
		defer g.down.timed("overlay", func() { g.ov.Close() }) //nolint:errcheck
	}
	startup.mark("overlay")
	switch backend {
	case "nfs":
		// A loopback NFS server over the same stack: the only way to
		// mount on macOS without macFUSE. Generation swap cannot push
		// invalidations here — NFS caching is client-driven — so --poll
		// is refused rather than silently doing nothing.
		var bfs billy.Filesystem
		if rw {
			bfs = vfsbilly.New(g.ov)
		} else {
			bfs = vfsbilly.NewReadOnly(g.gfs)
		}
		nfsSrv, err = nfsmount.Serve(bfs)
		if err == nil {
			defer g.down.timed("server", func() { nfsSrv.Close() }) //nolint:errcheck
			err = nfsSrv.Mount(mountpoint, "pelfs")
		}
	case "fuse", "":
		if rw {
			srv, err = rawfuse.MountRW(mountpoint, g.ov, o.debug)
		} else {
			srv, err = rawfuse.Mount(mountpoint, g.gfs, o.debug)
		}
	default:
		return fail(fmt.Errorf("unknown --backend %q (want fuse or nfs)", backend))
	}
	if err != nil {
		return fail(fmt.Errorf("mount: %w (fuse needs Linux FUSE or macFUSE; try --backend nfs)", err))
	}
	startup.mark("mount")
	// Reported after the mount, not after the generation opens: "ready to
	// serve" is not true until the kernel can reach the tree, and the steps
	// in between (opening the overlay, standing up the frontend, the OS
	// mount itself) are exactly the ones nobody could attribute before.
	startup.report("ready to serve in {total} ({packs} packs; discovery {discovery}, "+
		"access {access}, lease {lease}, head {head}, root catalog {root catalog}, "+
		"prefetch {prefetch}, overlay {overlay}, mount {mount})",
		"packs", len(sb.PackList))
	mode := "read-only"
	if rw {
		mode = "read-write (overlay; unmount seals)"
	}
	ui.Info("generation {generation} mounted {mode} on {mountpoint} (catalog-native)",
		"generation", sb.Generation, "mode", mode, "mountpoint", mountpoint)

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	go g.stats.RunPeriodic(sessionCtx, statsInterval)
	// Reclaiming what earlier sessions retired belongs here, behind a live
	// mount, and not on either the startup path or the exit path: it is
	// pure unlinking, and both of those are times a user is waiting.
	go sweepRetiredOverlays(stateDir)
	// Nothing in the write path calls back, so overlay pressure and the
	// served generation are sampled on the same cadence.
	go g.sample(sessionCtx, statsInterval)

	if ctl := g.startControl(); ctl != nil {
		defer g.down.timed("control", func() { ctl.Close() }) //nolint:errcheck
	}

	// Seal on a cadence, not only at unmount. A session that sealed
	// nothing until exit pays for everything it did in one lump at the
	// end -- minutes of packing and uploading after the user has already
	// typed `exit`, when the same work spread across the session would
	// have overlapped with the writes that produced it. The checkpoint
	// path is explicitly safe to run under a live mount (it seals a frozen
	// snapshot while writes continue), so drive it on a timer.
	//
	// What each seal after the first costs is the DELTA in content: files
	// a previous generation already published are carried forward by
	// identity and never read back (internal/publish, ContentReuser). The
	// tree walk and the catalog rebuild are still whole-tree, so the cost
	// scales with the size of the namespace, not with the bytes in it.
	if rw && o.snapshotInterval > 0 {
		go g.checkpointPeriodically(sessionCtx, o.snapshotInterval)
		ui.Info("checkpointing every {interval} (--snapshot-interval 0 disables)",
			"interval", o.snapshotInterval)
	}
	retractRecord := g.publishMountRecord()
	defer g.down.timed("record", retractRecord)

	// Live refresh: read-only mounts can follow the branch. Writable
	// mounts never do — the overlay is pinned to the generation it
	// shadows, and swapping underneath it would strand its dirty state.
	if poll > 0 && nfsSrv != nil {
		ui.Info("--poll ignored with --backend nfs (NFS caching is client-driven; there is no invalidation channel to push to)")
	} else if poll > 0 && !rw && tag == "" {
		r := rawfuse.NewRefresher(g.gfs, srv, func(c context.Context) (*superblock.Superblock, error) {
			f, err := rstore.Fetch(c, branch)
			if err != nil {
				return nil, err
			}
			return f.Superblock, nil
		}, poll)
		go g.follow(sessionCtx, r, poll)
		ui.Info("following {branch}, re-checking every {interval}", "branch", branch, "interval", poll)
	} else if poll > 0 {
		ui.Info("--poll ignored (writable mounts and tags are pinned by design)")
	}

	code := 0
	var unmountErr error
	if subshell {
		// The payload owns the session: when it exits we unmount, and the
		// seal (with --rw) happens on the way out just as it does for a
		// signalled mount — a failing command still gets its teardown, and
		// still carries its status out.
		code = runInMount(o, prefix, mountpoint, command)
		// Everything from here on is teardown: the user has stopped
		// working and is now waiting on us.
		g.beginTeardown()
		if nfsSrv != nil {
			unmountErr = nfsmount.Unmount(mountpoint)
			if unmountErr != nil {
				ui.Error("unmount: {error}", "error", unmountErr)
			}
		} else {
			if unmountErr = srv.Unmount(); unmountErr != nil {
				ui.Error("unmount: {error}", "error", unmountErr)
			}
			srv.Wait()
		}
	} else {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
		if nfsSrv != nil {
			<-sigs
			g.beginTeardown()
			if unmountErr = nfsmount.Unmount(mountpoint); unmountErr != nil {
				ui.Error("unmount: {error}", "error", unmountErr)
			}
		} else {
			go func() {
				<-sigs
				g.beginTeardown()
				_ = srv.Unmount()
			}()
			srv.Wait()
		}
	}
	// A mount can also end without either of the paths above running it
	// down: `fusermount -u` or `pelfs umount` detaches it from outside,
	// and Wait simply returns. Without this the whole exit seal was
	// charged to the session phase and reported as a checkpoint, which is
	// the opposite of what happened. Idempotent, so the paths that
	// already drew the boundary keep the earlier, truer instant.
	g.beginTeardown()
	g.down.mark("unmount")

	stopSession()
	g.down.mark("session stop")
	sealErr := g.sealAtExit(ctx)
	g.down.mark("seal")
	if sealErr != nil {
		ui.Error("{error}", "error", sealErr)
		// A failing payload already reported a status; keep it rather than
		// flattening it to 1.
		if code == 0 {
			code = 1
		}
	}
	g.refresh()
	if err := g.stats.Finalize(code, unmountErr == nil && sealErr == nil); err != nil {
		ui.Warn("write stats file: {error}", "error", err)
	}
	g.reportPhaseSplit()
	g.down.mark("stats")
	return code
}

// acquireLease takes the advisory mount lease for a writable session.
//
// The lease is read and written through a DIRECT-READ store: it is a
// mutable object, and a federation cache serving a stale copy would either
// hide a live holder or resurrect a dead one. It never goes through the
// statistics wrapper's sibling encryption layers either — a client with
// the wrong volume key must still see that the prefix is busy.
func (g *genSession) acquireLease(ctx context.Context, o *cmdOpts, prefix string) (*lease.Lease, error) {
	metaStore, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		Insecure:     o.insecure,
		AcquireToken: !o.noAcquireToken,
		DirectRead:   true,
	})
	if err != nil {
		return nil, err
	}
	l, err := lease.Acquire(ctx, lease.Options{
		Store:   metaStore,
		Session: g.sessionID,
		Steal:   o.stealLease,
		OnConflict: func(holder *lease.Info) {
			g.stats.Update(func(sum *stats.Summary) { sum.LeaseConflictObserved = true })
			ui.Warn("another client took over this prefix: {holder}\n"+
				"concurrent writers WILL corrupt each other; stop one of them.\n"+
				"this session keeps running but no longer renews the lease;\n"+
				"the seal at unmount will be REFUSED if that client advanced the branch.",
				"holder", holder.Describe())
		},
	})
	if err != nil {
		return nil, err
	}
	g.stats.Update(func(sum *stats.Summary) { sum.LeaseHeld = true })
	return l, nil
}

// releaseLease stops renewals and removes the lease. It is deferred at
// acquisition, so it runs after the seal at unmount — the seal is itself a
// write to the federation and must be covered.
func (g *genSession) releaseLease() {
	if g.lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := g.lease.Release(ctx); err != nil {
		ui.Warn("release lease: {error}", "error", err)
	}
	g.lease = nil
	// A federation round trip on the exit path, so it belongs in the
	// teardown breakdown rather than in whatever phase it lands next to.
	g.down.mark("lease release")
}

// runPrefetch honors the shared --prefetch flag's three modes.
func (g *genSession) runPrefetch(ctx context.Context, mode string) error {
	record := func(rep *genfs.PrefetchReport, complete bool) {
		g.stats.Update(func(sum *stats.Summary) {
			sum.PrefetchChunks = int64(rep.Chunks)
			sum.PrefetchBytes = rep.Bytes
			sum.PrefetchFailed = int64(rep.Failed)
			sum.PrefetchComplete = complete
		})
		_ = g.stats.Flush()
	}
	switch mode {
	case "", "none":
	case "all":
		ui.Info("prefetching the generation into the local cache...")
		rep, err := g.gfs.Prefetch(ctx, pelicanobj.TransferWorkers())
		if err != nil {
			return fmt.Errorf("prefetch: %w", err)
		}
		record(rep, rep.Failed == 0)
		if rep.Failed > 0 {
			return fmt.Errorf("prefetch: %d chunk(s) could not be fetched (%v); refusing to mount",
				rep.Failed, rep.Sample)
		}
		ui.Info("prefetched {chunks} chunks ({cached} already cached) across {files} files, {bytes}",
			"chunks", rep.Chunks, "cached", rep.Cached, "files", rep.Files,
			"bytes", ui.ByteCount(rep.Bytes))
	case "background":
		go func() {
			// Half the transfer pool, so warming never starves the
			// interactive I/O the mount is serving.
			rep, err := g.gfs.Prefetch(ctx, max(1, pelicanobj.TransferWorkers()/2))
			if err != nil {
				ui.Warn("background prefetch: {error}", "error", err)
				return
			}
			record(rep, rep.Failed == 0)
			ui.Info("background prefetch done: {chunks} chunks, {failed} failed",
				"chunks", rep.Chunks, "failed", rep.Failed)
		}()
	default:
		return fmt.Errorf("unknown --prefetch %q (want none, all, or background)", mode)
	}
	return nil
}

// follow drives the live-refresh poller and counts the swaps it applied.
// rawfuse.Refresher.Run does the polling but reports only to the log; the
// swap count belongs in the session statistics.
func (g *genSession) follow(ctx context.Context, r *rawfuse.Refresher, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			before := g.gfs.Generation()
			if err := r.Refresh(ctx); err != nil {
				// A federation hiccup must never take down a mount that is
				// serving a perfectly good generation.
				ui.Warn("refresh: {error} (still serving generation {generation})",
					"error", err, "generation", g.gfs.Generation())
				continue
			}
			if after := g.gfs.Generation(); after != before {
				g.stats.Update(func(sum *stats.Summary) {
					sum.GenerationSwaps++
					sum.Generation = after
				})
			}
		}
	}
}

// refresh samples the facts nothing else pushes: the generation on offer
// and how much unsealed work the overlay is holding. A retired overlay
// keeps its last sample — that is the work the seal consumed, not zero.
func (g *genSession) refresh() {
	gen := g.gfs.Generation()
	var st overlay.Stats
	var live bool
	g.ovMu.RLock()
	if g.ov != nil && !g.spent {
		var err error
		st, err = g.ov.Stats()
		live = err == nil
	}
	g.ovMu.RUnlock()
	g.stats.Update(func(sum *stats.Summary) {
		sum.Generation = gen
		if !live {
			return
		}
		sum.OverlayDirtyNodes = int64(st.DirtyNodes)
		sum.OverlayDirtyEdges = int64(st.DirtyEdges)
		sum.OverlayStagedFiles = int64(st.StagedFiles)
		sum.OverlayStagedBytes = st.StagedBytes
	})
}

func (g *genSession) sample(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.refresh()
		}
	}
}

// sealLocked publishes the overlay's current merged view as the next
// generation on the branch. Callers hold mu.
// sealCost samples what a seal is about to spend. A seal is the
// operation users actually wait on, and when it is slow the first
// question is which resource it went to: re-chunking work looks nothing
// like a slow uplink, and the remedies are opposite.
type sealCost struct {
	wall time.Time
	cpu  time.Duration
	get  int64
	put  int64
}

func (g *genSession) beginSealCost() sealCost {
	c := sealCost{wall: time.Now(), cpu: processCPU()}
	g.stats.Update(func(sum *stats.Summary) {
		c.get, c.put = sum.Get.Bytes, sum.Put.Bytes
	})
	return c
}

// reportSealCost prints what the seal spent and, from up, when it spent
// it. The two upload numbers are what make "the pipe stayed full" a
// checkable claim: how long the seal ran before anything was on the wire,
// and what share of the seal had something on the wire. A seal that
// uploaded nothing new (everything carried forward) says so instead,
// because a 0s/0% pair on that line reads as a defect rather than as an
// absence of work.
func (g *genSession) reportSealCost(c sealCost, up publish.UploadReport) {
	wall := time.Since(c.wall)
	cpu := processCPU() - c.cpu
	var down, sent int64
	g.stats.Update(func(sum *stats.Summary) {
		down, sent = sum.Get.Bytes-c.get, sum.Put.Bytes-c.put
	})
	args := []any{"wall", wall, "cpu", cpu,
		"downloaded", ui.ByteCount(down), "uploaded", ui.ByteCount(sent)}
	if up.Packs == 0 {
		ui.Info("seal took {wall} ({cpu} CPU, {downloaded} downloaded, {uploaded} uploaded; no packs to upload)", args...)
		return
	}
	var busy ui.Percent
	if wall > 0 {
		busy = ui.Percent(min(float64(up.Busy)/float64(wall), 1))
	}
	ui.Info("seal took {wall} ({cpu} CPU, {downloaded} downloaded, {uploaded} uploaded; "+
		"first pack on the wire {firstpack} in, uploading {uploading} of the seal)",
		append(args, "firstpack", up.First, "uploading", busy)...)
}

// phaseClock times a sequence phase by phase, so "the mount took 15
// seconds" can be answered with which part did. Startup and teardown both
// use one: each is a chain of federation round trips and OS calls, and
// nobody waiting on a slow one can otherwise tell which link they waited
// on.
//
// A clock is inert until begin() — the teardown clock is built with the
// session but must not start counting until the payload has exited, and
// marks that arrive before then (there are none today, but the exit path
// is deferred and reordering it is easy) are dropped rather than folded
// into the first phase.
type phaseClock struct {
	start   time.Time
	last    time.Time
	running bool
	names   []string
	parts   []any
}

func newPhaseClock() *phaseClock {
	c := &phaseClock{}
	c.begin()
	return c
}

func (c *phaseClock) begin() {
	// Already running means the boundary was drawn by an earlier, better
	// informed caller; restarting here would discard the phases it has
	// already timed.
	if c == nil || c.running {
		return
	}
	now := time.Now()
	c.start, c.last, c.running = now, now, true
}

// mark closes the phase that was running and names it. name is the label
// a reader sees in the sentence; ui derives the structured key from it, so
// a two-word phase reads as one ("lease release") without costing the log
// a key it cannot parse.
func (c *phaseClock) mark(name string) {
	if c == nil || !c.running {
		return
	}
	now := time.Now()
	c.names = append(c.names, name)
	c.parts = append(c.parts, name, now.Sub(c.last).Round(time.Millisecond))
	c.last = now
}

// timed runs fn as one phase.
func (c *phaseClock) timed(name string, fn func()) {
	fn()
	c.mark(name)
}

// report emits the breakdown as one line. The sentence is the caller's,
// because the lead-in worth printing differs (a mount reports its pack
// count, a teardown does not); the clock supplies {total} and one
// attribute per phase.
func (c *phaseClock) report(sentence string, extra ...any) {
	if c == nil || !c.running || len(c.names) == 0 {
		return
	}
	args := append([]any{"total", time.Since(c.start).Round(time.Millisecond)}, extra...)
	ui.Info(sentence, append(args, c.parts...)...)
}

// sentence builds "<lead> in {total} (a {a}, b {b})" over the phases that
// actually ran. Teardown's shape varies — backend, whether a seal
// happened, whether a lease was held — and a fixed sentence would either
// name phases that never ran or quietly omit ones that did.
func (c *phaseClock) sentence(lead string) string {
	var b strings.Builder
	b.WriteString(lead)
	b.WriteString(" in {total} (")
	for i, n := range c.names {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(n)
		b.WriteString(" {")
		b.WriteString(n)
		b.WriteString("}")
	}
	b.WriteString(")")
	return b.String()
}

// beginTeardown draws the line the whole phase split rests on: the
// payload has exited and everything after this point is the user waiting
// on us. The teardown clock and the statistics phase move together
// because they are two views of the same instant, and a split drawn a few
// statements away from the clock would be a split nobody could defend.
func (g *genSession) beginTeardown() {
	g.downOnce.Do(func() {
		g.down.begin()
		g.stats.SetPhase(stats.PhaseTeardown)
	})
}

// reportPhaseSplit is the answer to "was any of this published while I
// was working?", stated as two numbers that add up to the session total.
// It runs on every writable session, including the ones where the honest
// answer is that the session phase uploaded nothing at all.
func (g *genSession) reportPhaseSplit() {
	if !g.rw {
		return
	}
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	ui.Info("uploaded {session} during the session and {teardown} after it exited "+
		"({checkpoints} while mounted, {exitseals} at exit)",
		"session", ui.ByteCount(sum.SessionPhase.Put.Bytes),
		"teardown", ui.ByteCount(sum.TeardownPhase.Put.Bytes),
		"checkpoints", ui.Count(sum.SessionPhase.Seals, "seal"),
		"exitseals", ui.Count(sum.TeardownPhase.Seals, "seal"))
}

// reportTeardown says where the time between the payload exiting and the
// process exiting went. It is deferred FIRST in runMountGen so it runs
// last, after every other deferred step has marked itself.
func (g *genSession) reportTeardown() {
	g.down.report(g.down.sentence("torn down"))
}

// processCPU is this process's user+system time. Seals are mostly
// chunking and SQLite, so CPU well below wall time points at the network
// and CPU near wall time points at us.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	return tv(ru.Utime) + tv(ru.Stime)
}

// sealLocked publishes the overlay as the next generation. follow says
// whether the MOUNT should then be moved onto what was published: true
// for a mid-session checkpoint, which keeps serving afterwards, and false
// at unmount, where nothing will read the result.
func (g *genSession) sealLocked(ctx context.Context, follow bool) (*publish.Result, error) {
	keyPath := g.signingKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(g.stateDir, "v2-signing.key")
	}
	signingKey, err := loadOrCreateSigningKey(keyPath, g.sb)
	if err != nil {
		return nil, err
	}
	// A seal is three jobs, not one — freeze, publish, release — and the
	// two that are not the publish were invisible until they were measured:
	// on a session that had touched a large tree the freeze alone rivalled
	// the publish it precedes.
	phases := newPhaseClock()
	blockedBefore, worstBefore, waitsBefore := int64(0), time.Duration(0), int64(0)
	if g.ov != nil {
		var total time.Duration
		total, worstBefore, waitsBefore = g.ov.LockWait()
		blockedBefore = int64(total)
	}
	defer func() {
		phases.report(phases.sentence("sealed"))
		// What the seal cost the MOUNT, which is a different question from
		// what it cost the seal: a phase that runs for ten seconds with the
		// overlay's lock held is ten seconds of a filesystem that does not
		// answer, and until this was reported the only evidence of it was
		// an NFS client giving up.
		if g.ov == nil {
			return
		}
		total, worst, waits := g.ov.LockWait()
		blocked := time.Duration(int64(total) - blockedBefore)
		if n := waits - waitsBefore; n > 0 && blocked > 250*time.Millisecond {
			if worst <= worstBefore {
				worst = 0
			}
			ui.Info("the mount was blocked {blocked} across {waits} operations during this seal"+
				"{longest}", "blocked", blocked.Round(time.Millisecond), "waits", n,
				"longest", longestWait(worst))
		}
	}()

	// A CHECKPOINT seals a FROZEN view, not the live overlay: it publishes
	// while writers keep working, so it needs its input to correspond to an
	// instant — the precondition for handing those inodes back to the
	// kernel as clean afterwards. Without it a write landing mid-walk could
	// be published half-observed, and an infinite TTL on that value would
	// make the mismatch permanent.
	//
	// The seal at UNMOUNT has neither the need nor anything to gain. It
	// runs after the mountpoint is gone and the server has stopped, so
	// there is no writer left to race: the live overlay IS an instant.
	// Nothing rebases afterwards either (follow is false), which is the
	// only consumer of a snapshot's sequence number. So freezing would
	// produce a view byte-for-byte identical to the one already on disk,
	// for someone who has stopped working and is waiting to get their
	// shell back.
	var snap *overlay.Snapshot
	release := func() {}
	if follow {
		snapDir, err := os.MkdirTemp(g.stateDir, "snapshot-*")
		if err != nil {
			return nil, err
		}
		snap, err = g.ov.Snapshot(ctx, snapDir)
		if err != nil {
			os.RemoveAll(snapDir) //nolint:errcheck
			return nil, fmt.Errorf("snapshot the overlay: %w", err)
		}
		// Releasing is deferred so it also covers the error returns below,
		// and called explicitly the moment the publish is done. The window
		// matters: while a snapshot is live, every mount write that lands
		// below a frozen length costs a rename plus a copy of that file
		// (overlay/snapshot.go). The seal stops reading the frozen view
		// when Seal returns, so nothing after that point needs to keep
		// paying for it — least of all the rebase, which drops staging
		// files by the thousand.
		releaseSnap := sync.OnceFunc(func() {
			// Discard, not Close: the scratch is retired by rename below
			// rather than unlinked file by file here.
			_ = snap.Discard()
			if err := g.retireDir(snapDir); err != nil {
				ui.Warn("the seal's snapshot scratch at {dir} could not be retired: {error}",
					"dir", snapDir, "error", err)
			}
			phases.mark("release")
		})
		defer releaseSnap()
		release = releaseSnap
		sc := snap.Cost()
		if sc.Drain > time.Second {
			// Said separately because it is NOT a stall: the mount served
			// throughout, and reporting it as freeze time is what made a
			// slow uplink look like a slow lock.
			ui.Info("pushed this session's remaining content in {drain} before freezing",
				"drain", sc.Drain.Round(time.Millisecond))
		}
		ui.Info("froze the overlay in {total} (vacuum {vacuum}, {staged} staged inodes in {pin}, "+
			"namespace {namespace}, open {open})",
			"total", sc.Total().Round(time.Millisecond), "vacuum", sc.Vacuum.Round(time.Millisecond),
			"staged", sc.Staged, "pin", sc.Freeze.Round(time.Millisecond),
			"namespace", sc.Edges.Round(time.Millisecond), "open", sc.Open.Round(time.Millisecond))
	}
	phases.mark("freeze")

	opts := publish.Options{
		Inner:          g.inner,
		SpoolDir:       g.stateDir,
		Branch:         g.branch,
		SigningKey:     signingKey,
		Prev:           g.sb,
		PrevRaw:        g.prevRaw,
		DEK:            g.dek,
		IdentityKey:    g.identityKey,
		KeyID:          g.keyID,
		KeyTable:       g.sb.KeyTable,
		DedupIndexPath: filepath.Join(g.stateDir, "v2-dedup.db"),
	}
	if snap != nil {
		opts.OverlaySnapshot = snap
	} else {
		opts.Overlay = g.ov
	}
	cost := g.beginSealCost()
	res, err := publish.Seal(ctx, opts)
	if err != nil {
		return nil, err
	}
	phases.mark("publish")
	// Nothing reads the frozen view from here on (the rebase below wants
	// only its sequence number), so the mount stops paying for it now
	// rather than at the end of the function.
	release()
	g.reportSealCost(cost, res.Upload)
	// The anchor must advance with the branch head: the next seal's
	// lineage hash and its compare-and-swap against refs/<branch> both
	// grow from what was just published, not from where the mount started.
	g.sb, g.prevRaw = res.Superblock, res.Raw

	// Return the published inodes to CLEAN so the kernel can cache them
	// again. Order is dictated by the overlay: the base must already
	// serve the sealed generation before its rows may be dropped, or the
	// merged view would silently regress to the old base — Rebase
	// refuses otherwise. Only inodes provably unmodified since the
	// snapshot go clean; anything written during the seal stays dirty.
	//
	// A failure here costs performance, never correctness: the session
	// simply keeps paying the short dirty TTL, and re-answering the
	// kernel's questions about it, for state that is already durable.
	//
	// All of it is skipped at unmount. Swap re-descends the whole resident
	// tree and Rebase rewrites overlay rows, both to hand a LIVE mount a
	// cheaper future — and the seal at unmount has no future: the overlay
	// is closed and deleted a few statements later, and the kernel has
	// already dropped the mount. Doing it there is pure latency on the
	// exit path, paid by someone who has stopped working and is waiting
	// to get their shell back.
	if follow {
		// Reported as two marks, not one. Swapping the base and rebasing
		// the overlay are different work under different locks — genfs's
		// swap lock and the overlay's — and a single "follow" number
		// cannot say which of them the mount was waiting behind.
		if _, err := g.gfs.Swap(ctx, res.Superblock); err != nil {
			ui.Warn("sealed generation {generation}, but the mount could not follow it ({error}); inodes stay dirty",
				"generation", res.Superblock.Generation, "error", err)
		} else if rep, err := g.markSwapped(phases).Rebase(ctx, snap.Seq(), overlay.Options{
			BaseRoot:       res.Superblock.RootCatalog,
			BaseGeneration: res.Superblock.Generation,
		}); err != nil {
			ui.Warn("sealed generation {generation}, but rebase failed ({error}); inodes stay dirty",
				"generation", res.Superblock.Generation, "error", err)
		} else {
			ui.Info("{clean} returned to clean; {dirty} still dirty",
				"clean", ui.Count(len(rep.Clean), "inode"), "dirty", rep.Dirty)
			g.stats.Update(func(sum *stats.Summary) { sum.RebasedClean += int64(len(rep.Clean)) })
		}
		phases.mark("rebase")
	}

	// The seal counts against whichever phase it ran in, so "0 seals while
	// mounted, 1 at exit" is readable straight off the summary.
	g.stats.UpdatePhase(func(sum *stats.Summary, ph *stats.PhaseCounters) {
		sum.Seals++
		ph.Seals++
		sum.SealedGeneration = res.Superblock.Generation
		sum.SealedChunks = int64(res.Stats.ChunksAdded)
		sum.SealedCatalogs = int64(res.Stats.Catalogs)
		sum.SealedPacks = int64(len(res.NewPacks))
	})
	return res, nil
}

// checkpoint is POST /v1/publish on a writable mount: seal what is in the
// overlay right now into a new generation, and keep serving.
//
// What the kernel is holding stays correct across it, and that is what
// makes an in-place checkpoint safe. Publishing reads a FROZEN view of
// the overlay (sealLocked takes a snapshot when it is going to follow),
// so the generation corresponds to an instant even though writers never
// stopped. Afterwards the mount moves onto what it just published and the
// overlay drops the rows that view made redundant, which is how the
// published inodes get their long clean TTLs back; anything written
// during the seal stays dirty and keeps the short one.
//
// Two properties a caller must know:
//
//   - Writes that land DURING the checkpoint are not in it. The frozen
//     view is the instant the snapshot was taken, so the generation is
//     self-consistent and signed but is not the tree as of the moment the
//     call returns. The next seal picks up the difference.
//   - The branch head now names a generation the ON-DISK overlay does not
//     sit over. Everything up to the checkpoint is durable — that is what
//     the verb is for — but a crash before unmount strands the delta
//     written after it: overlay.Open refuses a base it was not recorded
//     against.
func (g *genSession) checkpoint(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ov == nil || g.spent {
		return "", errors.New("this mount has no live overlay to seal (read-only, or already shutting down)")
	}
	st, err := g.ov.Stats()
	if err == nil && st.DirtyNodes == 0 && st.DirtyEdges == 0 {
		return fmt.Sprintf("nothing changed; still at generation %d", g.sb.Generation), nil
	}
	// Announced before the work, not after it: a checkpoint is the one
	// thing that publishes while the user is still working, so "did any of
	// this go out before I typed exit" has to be answerable from the
	// terminal at the moment it happens. Printed only once the overlay is
	// known dirty, so an idle cadence stays silent.
	ui.Info("checkpoint started: publishing what this session has written so far "+
		"({staged} staged, {dirty} dirty)",
		"staged", ui.ByteCount(st.StagedBytes), "dirty", ui.Count(st.DirtyNodes, "inode"))
	// A checkpoint keeps serving, so the mount must follow what it just
	// published — that is what lets the redundant overlay rows go.
	res, err := g.sealLocked(ctx, true)
	if err != nil {
		return "", err
	}
	ui.Info("checkpoint: sealed generation {generation} while mounted",
		"generation", res.Superblock.Generation)
	return fmt.Sprintf("generation %d: %d chunks uploaded, %d catalogs written (%d carried), %d new packs",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs,
		res.Stats.CatalogsReused, len(res.NewPacks)), nil
}

// slowCheckpoint is the duration past which a periodic checkpoint is
// reported. Checkpoints run behind a live mount, so they are invisible
// until they are slow enough to matter for the seal at exit.
const slowCheckpoint = 10 * time.Second

// checkpointPeriodically seals in the background for the life of the
// session. Nothing here is load-bearing for correctness: every change is
// already durable in the overlay, and the seal at unmount publishes
// whatever the last checkpoint did not. That is what makes it safe to
// swallow failures and keep going -- tearing a mount down over a
// transient federation error would cost the user far more than a late
// checkpoint does.
// checkpointBytes is how much staged content triggers a checkpoint
// regardless of the clock.
//
// A time-only trigger cannot adapt to write rate, and the failure is not
// subtle: extracting a kernel tree wrote 441 MiB in 1m45s against the 5
// minute default, so no checkpoint ever fired and the whole session's
// upload landed after the user typed exit — 40s of it, with the uplink
// saturated the entire time. Pressure is the honest trigger: a session
// that writes fast should publish often, whatever the clock says.
//
// 128 MiB is a compromise between filling the uplink early and paying a
// checkpoint's fixed costs too often. It is deliberately larger than the
// pack target so a checkpoint still cuts full packs.
const checkpointBytes = 128 << 20

// pressureSampleInterval is how often staged bytes are measured. It is a
// fraction of the checkpoint interval, floored so a long interval still
// notices a burst promptly and capped so a short one does not turn
// sampling into its own load.
func pressureSampleInterval(every time.Duration) time.Duration {
	d := every / 10
	if d < time.Second {
		d = time.Second
	}
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
}

// stagedBytes reports how much content is waiting to be published, or -1
// when the overlay cannot be sampled (it is being sealed, or is gone).
func (g *genSession) stagedBytes() int64 {
	g.ovMu.RLock()
	defer g.ovMu.RUnlock()
	if g.ov == nil || g.spent {
		return -1
	}
	st, err := g.ov.Stats()
	if err != nil {
		return -1
	}
	return st.StagedBytes
}

func (g *genSession) checkpointPeriodically(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	// Sampling is far more frequent than the interval so a burst is
	// noticed while it is still being written rather than after it.
	sample := time.NewTicker(pressureSampleInterval(every))
	defer sample.Stop()
	// A pressure checkpoint that fails must not be retried on the very
	// next sample. The pressure that triggered it does not go away when it
	// fails — the staged bytes are still there — so a federation refusing
	// the flip turns into a full publish every few seconds, each one
	// walking the tree and uploading packs before it is refused again.
	// That is what one broken CAS looked like from the terminal: the same
	// warning over and over, ~15 s apart, forever.
	//
	// Backing off doubles the wait to the checkpoint interval and stops
	// there, because at that point the periodic tick governs anyway.
	// Nothing is lost by waiting: every change is already durable in the
	// overlay, and the seal at unmount publishes whatever this did not.
	var retryAfter time.Time
	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sample.C:
			if n := g.stagedBytes(); n < checkpointBytes {
				continue
			}
			if time.Now().Before(retryAfter) {
				continue
			}
			start := time.Now()
			summary, err := g.checkpoint(ctx)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				backoff = min(max(2*backoff, pressureSampleInterval(every)), every)
				retryAfter = time.Now().Add(backoff)
				ui.Warn("checkpoint under write pressure failed, retrying in {backoff} "+
					"(your changes remain safe in the overlay): {error}",
					"backoff", backoff.Round(time.Second), "error", err)
			default:
				backoff, retryAfter = 0, time.Time{}
				ui.Info("checkpointed {staged} of staged content in {duration} ({summary})",
					"staged", ui.ByteCount(checkpointBytes), "duration", time.Since(start), "summary", summary)
			}
		case <-t.C:
			start := time.Now()
			summary, err := g.checkpoint(ctx)
			elapsed := time.Since(start)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				ui.Warn("periodic checkpoint failed, retrying next interval "+
					"(your changes remain safe in the overlay): {error}", "error", err)
			case elapsed > slowCheckpoint:
				ui.Info("checkpoint took {duration} ({summary})", "duration", elapsed, "summary", summary)
			}
		}
	}
}

// sealAtExit publishes a writable mount's changes as the next generation
// and retires the spent overlay. A read-only mount, an unchanged session,
// or --no-seal all return without publishing.
func (g *genSession) sealAtExit(ctx context.Context) error {
	if !g.rw || g.noSeal {
		if g.rw {
			ui.Info("overlay kept at {overlay} (--no-seal); remount to resume or seal",
				"overlay", g.overlayDir)
		}
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ov == nil || g.spent {
		return nil
	}
	st, err := g.ov.Stats()
	if err == nil && st.DirtyNodes == 0 && st.DirtyEdges == 0 {
		ui.Info("nothing changed; no new generation")
		return nil
	}
	ui.Info("sealing the overlay into the next generation...")
	// The exit path's "seal" phase is three separable pieces of work —
	// publishing, closing the overlay database, and retiring the spent
	// directory — and only the first is the seal. Reporting them as one
	// number hid tens of seconds of unlink storm behind a name that
	// implied federation work.
	exit := newPhaseClock()
	// Nothing reads the overlay after this, so the mount does not follow.
	res, err := g.sealLocked(ctx, false)
	if err != nil {
		ok := false
		g.stats.Update(func(sum *stats.Summary) { sum.SealOK = &ok })
		return fmt.Errorf("seal: %w (the overlay is intact at %s; remount to retry)", err, g.overlayDir)
	}
	exit.mark("publish")
	ok := true
	g.stats.Update(func(sum *stats.Summary) { sum.SealOK = &ok })
	// Carried and pruned are reported next to written, because the number
	// that matters is the RATIO: a one-file change that writes one catalog
	// and carries thirty is the intended behavior, and the same line
	// showing thirty-one written is the defect.
	ui.Info("sealed generation {generation} ({chunks} chunks, {catalogs} catalogs written, "+
		"{carried} carried, {pruned} subtrees untouched, {packs} packs)",
		"generation", res.Superblock.Generation, "chunks", res.Stats.ChunksAdded,
		"catalogs", res.Stats.Catalogs, "carried", res.Stats.CatalogsReused,
		"pruned", res.Stats.SubtreesPruned, "packs", len(res.NewPacks))

	// The overlay's contents are now published, and it is pinned to the
	// generation it shadowed — which is no longer the head. Leaving it
	// would make this state directory single-use: the next mount would
	// refuse with a generation mismatch.
	g.ovMu.Lock()
	g.spent = true
	_ = g.ov.Close()
	g.ovMu.Unlock()
	exit.mark("overlay close")
	if err := g.retireDir(g.overlayDir); err != nil {
		ui.Warn("sealed, but the spent overlay at {overlay} could not be retired: {error}",
			"overlay", g.overlayDir, "error", err)
	}
	// The content store's journal describes extents of the generation just
	// superseded, and its ring holds nothing the seal did not publish. Both
	// are spent for exactly the reason the overlay is.
	if g.closeContent != nil {
		if err := g.closeContent(); err != nil {
			ui.Warn("the write path's content store did not close cleanly: {error}", "error", err)
		}
		if err := g.retireDir(filepath.Join(g.stateDir, "content")); err != nil {
			ui.Warn("sealed, but the spent content store could not be retired: {error}", "error", err)
		}
	}
	exit.mark("retire")
	exit.report(exit.sentence("sealed and retired the overlay"))
	return nil
}

// trashDirName is the state-directory subdirectory spent overlays are
// renamed into. It is deliberately NOT a name any mount opens: the only
// overlay a session ever resumes is <state-dir>/overlay.
const trashDirName = "trash"

// retireDir gets a spent scratch directory out of the way now and hands
// its bytes to whoever can afford to delete them, which is anyone but the
// user waiting on their shell.
//
// Two directories on the exit path are shaped alike: the spent overlay and
// the snapshot the seal froze it into. Both hold one file per dirty inode,
// so deleting either in place is tens of thousands of unlinks — and both
// were being deleted while the user waited. Correctness needs only that
// neither is ever REUSED, and a rename within the state directory (one
// atomic syscall, same filesystem) settles that immediately.
//
// The crash-safety argument, window by window:
//
//   - Before the rename: <state-dir>/overlay is intact and complete, but
//     pinned to a generation that is no longer the head. A later mount
//     opens it, finds the recorded base root does not match, and refuses
//     with overlay.ErrGeneration. It fails loudly; it never resumes stale
//     state. This window is one syscall wide, where the in-place delete
//     held it open for the whole unlink storm — and held it open around a
//     PARTIALLY deleted overlay, which is the genuinely dangerous state:
//     RemoveAll deletes in directory order, so a crash that took the
//     database but left the staging files would leave a directory that
//     overlay.Open happily initializes as EMPTY, silently inheriting a
//     tree of orphan staging files. (A snapshot directory has no such
//     hazard in either shape: nothing ever opens one by name.)
//   - After the rename: nothing named <state-dir>/overlay exists, so there
//     is nothing to resume at all; the next mount starts a fresh overlay.
//     The trash entry is inert data no code path opens.
//   - During the background delete, and after a crash in the middle of it:
//     a half-deleted trash entry is still just inert data, and RemoveAll
//     is idempotent, so the next sweep finishes the job.
//
// Names cannot collide: the trash name carries the session id (a
// timestamp, the hostname, and four random bytes) and the source
// directory's own name, which is unique within one session — snapshot
// scratch comes from MkdirTemp, and there is one overlay. A name that
// somehow did collide fails the rename onto a non-empty directory and
// takes the delete-in-place fallback, which is slow, never wrong.
//
// Garbage cannot accumulate without bound either: every mount over this
// state directory sweeps the trash (see sweepRetiredOverlays), so the
// standing worst case is what the sessions since the last mount left.
func (g *genSession) retireDir(dir string) error {
	trash := filepath.Join(g.stateDir, trashDirName)
	if err := os.MkdirAll(trash, 0700); err != nil {
		return err
	}
	spent := filepath.Join(trash, g.sessionID+"-"+filepath.Base(dir))
	if err := os.Rename(dir, spent); err != nil {
		// No rename means no cheap retirement, and leaving a spent overlay
		// in place would make the state directory single-use. Pay for the
		// slow path rather than break the next mount.
		return os.RemoveAll(dir)
	}
	g.reclaim(spent)
	return nil
}

// reclaim frees a retired directory's bytes without anyone waiting on it.
// Deliberately unwaited: whatever it finishes before the process exits is
// that much less for the next mount to sweep, and whatever it does not
// finish costs nothing but disk until then. Tests replace it to inspect
// what retirement left behind.
func (g *genSession) reclaim(dir string) {
	if g.reclaimFn != nil {
		g.reclaimFn(dir)
		return
	}
	go os.RemoveAll(dir) //nolint:errcheck
}

// sweepRetiredOverlays deletes the overlays previous sessions retired. It
// is the other half of retireOverlay: that side renames in constant time
// and exits, this side does the unlinking while a mount is up and nobody
// is waiting on it.
//
// It runs for read-only mounts too. A writable session that was killed
// leaves its trash behind, and the next mount of that state directory is
// the next chance to reclaim it whatever mode it is in.
func sweepRetiredOverlays(stateDir string) {
	trash := filepath.Join(stateDir, trashDirName)
	ents, err := os.ReadDir(trash)
	if err != nil {
		return
	}
	for _, e := range ents {
		_ = os.RemoveAll(filepath.Join(trash, e.Name()))
	}
}

// controlHooks exposes the session on the control socket. Writes land in
// the overlay's WAL and staging files as they happen; the only step that
// moves them to the federation is the seal behind Publish.
func (g *genSession) controlHooks() control.Hooks {
	h := control.Hooks{
		Status: func() map[string]any {
			st := map[string]any{
				"pid":        os.Getpid(),
				"engine":     "catalog-native",
				"prefix":     g.prefix,
				"mountpoint": g.mountpoint,
				"backend":    g.backend,
				"read_only":  !g.rw,
				"generation": g.gfs.Generation(),
				"started":    g.started.Format(time.RFC3339),
				"uptime_s":   int64(time.Since(g.started).Seconds()),
			}
			if g.tag != "" {
				st["tag"] = g.tag
			} else {
				st["branch"] = g.branch
			}
			if g.lease != nil {
				st["lease_held"] = true
				st["lease_conflict"] = g.lease.Conflicted()
			}
			return st
		},
		StatsJSON: func() ([]byte, error) {
			// The collector writes its file atomically on its own cadence
			// and on demand here; sample the live facts first so the
			// document served is current, not one tick old.
			g.refresh()
			if err := g.stats.Flush(); err != nil {
				return nil, err
			}
			return os.ReadFile(g.statsPath)
		},
		BugreportExtra: func() map[string][]byte {
			extra := make(map[string][]byte)
			if b, err := os.ReadFile(filepath.Join(g.stateDir, "refs", "volume.pub")); err == nil {
				extra["volume.pub"] = b
			}
			return extra
		},
	}
	if g.rw {
		h.Publish = g.checkpoint
	}
	return h
}

// startControl brings the control socket up; failure is loud but never
// fatal — a mount without a control socket beats no mount.
func (g *genSession) startControl() *control.Server {
	srv, err := control.Start(g.stateDir, g.controlHooks())
	if err != nil {
		ui.Warn("control socket unavailable: {error}", "error", err)
		return nil
	}
	return srv
}

// publishMountRecord makes the session discoverable by prefix, so
// `pelfs ctl`, `pelfs status`, and `pelfs umount` all find the session by
// prefix. It returns the retraction.
//
// A live record belonging to another session is never overwritten: two
// mount-gen sessions on one prefix are legitimate (a reader and a writer),
// and discovery by prefix can only name one of them. The state directory
// is always a valid `pelfs ctl` target for the other.
func (g *genSession) publishMountRecord() func() {
	noop := func() {}
	dir := volDir(g.prefix)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return noop
	}
	path := filepath.Join(dir, "mount.json")
	if info, err := readMountInfo(path); err == nil && info.PID != os.Getpid() && pidAlive(info.PID) {
		ui.Warn("{prefix} already has a live mount record (pid {pid}); reach this session with `pelfs ctl {statedir}`",
			"prefix", g.prefix, "pid", info.PID, "statedir", g.stateDir)
		return noop
	}
	data, err := json.MarshalIndent(&mountInfo{
		PID:        os.Getpid(),
		Prefix:     g.prefix,
		MountPoint: g.mountpoint,
		Session:    g.sessionID,
		StateDir:   g.stateDir,
		ReadOnly:   !g.rw,
		Started:    g.started,
	}, "", "  ")
	if err != nil {
		return noop
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return noop
	}
	return func() {
		if info, err := readMountInfo(path); err == nil && info.PID == os.Getpid() {
			_ = os.Remove(path)
		}
	}
}
