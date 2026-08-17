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
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/nfsmount"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
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
// optional write overlay, and the session-level facilities a v1 mount
// already has — statistics, the advisory write lease, and the control
// socket.
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
// unverified-read fallback both probe for such interfaces, and both were
// silently inert on this path because the probe stopped here.
func (s countedStore) Unwrap() pelicanobj.Store { return s.raw }

func (s countedStore) ListDir(ctx context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	return s.raw.ListDir(ctx, dir)
}

func (s countedStore) StatKey(ctx context.Context, key string) (*pelicanobj.KeyInfo, error) {
	return s.raw.StatKey(ctx, key)
}

// cmdMountGen mounts a published v2 generation through the catalog-native
// phase-3 stack — genfs + the raw FUSE binding, no JuiceFS anywhere.
// Linux/macFUSE only for --backend fuse; --backend nfs works anywhere the
// OS has an NFS client. Experimental.
// genArgs are the catalog-native mount knobs. `pelfs shell` fills them
// in too, so the primary workflow runs on exactly this path rather than
// a parallel copy of it.
type genArgs struct {
	branch, tag, pubkeyHex  string
	rw, noSeal, subshell    bool
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
	}
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
	// Probe access up front, exactly as a v1 session does. This is what
	// triggers the interactive flow once, for the read+create+modify
	// union a whole session needs, and it turns a missing or too-narrow
	// credential into one clear message here rather than an opaque
	// failure deep in the mount.
	if err := pelicanobj.Preflight(ctx, raw, prefix, !rw); err != nil {
		return fail(err)
	}
	// Every byte the phase-3 stack moves — pack range reads, catalog
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
		defer g.releaseLease()
	}

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
	defer g.gfs.Close() //nolint:errcheck
	g.stats.Update(func(sum *stats.Summary) { sum.Generation = sb.Generation })

	if err := g.runPrefetch(ctx, o.prefetch); err != nil {
		return fail(err)
	}

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
		g.ov, err = overlay.Open(g.overlayDir, g.gfs, overlay.Options{
			NextInode:      g.gfs.NextInode(),
			BaseRoot:       g.gfs.RootCatalog(),
			BaseGeneration: g.gfs.Generation(),
		})
		if err != nil {
			if errors.Is(err, overlay.ErrGeneration) {
				// The branch moved on while this overlay sat unsealed —
				// another writer, or a crash after a mid-session
				// checkpoint. The overlay's whiteouts and COW copies are
				// meaningful only over the generation they were recorded
				// against, so it cannot be replayed onto the new head.
				err = fmt.Errorf("%w\n"+
					"pelfs: the unsealed overlay at %s was recorded over an older generation of %s.\n"+
					"pelfs: its contents are intact but cannot be sealed onto the current head; move it aside to start a fresh overlay",
					err, g.overlayDir, branch)
			}
			return fail(fmt.Errorf("open overlay: %w", err))
		}
		defer g.ov.Close() //nolint:errcheck
	}
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
			defer nfsSrv.Close() //nolint:errcheck
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
	mode := "read-only"
	if rw {
		mode = "read-write (overlay; unmount seals)"
	}
	fmt.Fprintf(os.Stderr, "pelfs: generation %d mounted %s on %s (catalog-native)\n",
		sb.Generation, mode, mountpoint)

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	go g.stats.RunPeriodic(sessionCtx, statsInterval)
	// Nothing in the write path calls back, so overlay pressure and the
	// served generation are sampled on the same cadence.
	go g.sample(sessionCtx, statsInterval)

	if ctl := g.startControl(); ctl != nil {
		defer ctl.Close() //nolint:errcheck
	}

	// Seal on a cadence, not only at unmount. A session that sealed
	// nothing until exit pays for everything it did in one lump at the
	// end -- minutes of packing and uploading after the user has already
	// typed `exit` -- where v1 exited promptly because it had been
	// snapshotting all along. The checkpoint path is explicitly safe to
	// run under a live mount (it seals a frozen snapshot while writes
	// continue), so drive it on a timer.
	//
	// What each seal after the first costs is the DELTA in content: files
	// a previous generation already published are carried forward by
	// identity and never read back (internal/publish, ContentReuser). The
	// tree walk and the catalog rebuild are still whole-tree, so the cost
	// scales with the size of the namespace, not with the bytes in it.
	if rw && o.snapshotInterval > 0 {
		go g.checkpointPeriodically(sessionCtx, o.snapshotInterval)
		fmt.Fprintf(os.Stderr, "pelfs: checkpointing every %s (--snapshot-interval 0 disables)\n", o.snapshotInterval)
	}
	defer g.publishMountRecord()()

	// Live refresh: read-only mounts can follow the branch. Writable
	// mounts never do — the overlay is pinned to the generation it
	// shadows, and swapping underneath it would strand its dirty state.
	if poll > 0 && nfsSrv != nil {
		fmt.Fprintln(os.Stderr, "pelfs: --poll ignored with --backend nfs (NFS caching is client-driven; there is no invalidation channel to push to)")
	} else if poll > 0 && !rw && tag == "" {
		r := rawfuse.NewRefresher(g.gfs, srv, func(c context.Context) (*superblock.Superblock, error) {
			f, err := rstore.Fetch(c, branch)
			if err != nil {
				return nil, err
			}
			return f.Superblock, nil
		}, poll)
		go g.follow(sessionCtx, r, poll)
		fmt.Fprintf(os.Stderr, "pelfs: following %s, re-checking every %s\n", branch, poll)
	} else if poll > 0 {
		fmt.Fprintln(os.Stderr, "pelfs: --poll ignored (writable mounts and tags are pinned by design)")
	}

	code := 0
	var unmountErr error
	if subshell {
		// The payload owns the session: when it exits we unmount, and the
		// seal (with --rw) happens on the way out just as it does for a
		// signalled mount — a failing command still gets its teardown, and
		// still carries its status out.
		code = runInMount(o, prefix, mountpoint, command)
		if nfsSrv != nil {
			unmountErr = nfsmount.Unmount(mountpoint)
			if unmountErr != nil {
				fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", unmountErr)
			}
		} else {
			if unmountErr = srv.Unmount(); unmountErr != nil {
				fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", unmountErr)
			}
			srv.Wait()
		}
	} else {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
		if nfsSrv != nil {
			<-sigs
			if unmountErr = nfsmount.Unmount(mountpoint); unmountErr != nil {
				fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", unmountErr)
			}
		} else {
			go func() {
				<-sigs
				_ = srv.Unmount()
			}()
			srv.Wait()
		}
	}

	stopSession()
	sealErr := g.sealAtExit(ctx)
	if sealErr != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", sealErr)
		// A failing payload already reported a status; keep it rather than
		// flattening it to 1.
		if code == 0 {
			code = 1
		}
	}
	g.refresh()
	if err := g.stats.Finalize(code, unmountErr == nil && sealErr == nil); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: write stats file: %v\n", err)
	}
	return code
}

// acquireLease takes the advisory mount lease for a writable session, the
// same way a v1 write session does.
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
			fmt.Fprintf(os.Stderr,
				"pelfs: WARNING: another client took over this prefix: %s\n"+
					"pelfs: WARNING: concurrent writers WILL corrupt each other; stop one of them.\n"+
					"pelfs: WARNING: this session keeps running but no longer renews the lease;\n"+
					"pelfs: WARNING: the seal at unmount will be REFUSED if that client advanced the branch.\n",
				holder.Describe())
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
		fmt.Fprintf(os.Stderr, "pelfs: release lease: %v\n", err)
	}
	g.lease = nil
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
		fmt.Fprintln(os.Stderr, "pelfs: prefetching the generation into the local cache...")
		rep, err := g.gfs.Prefetch(ctx, pelicanobj.TransferWorkers())
		if err != nil {
			return fmt.Errorf("prefetch: %w", err)
		}
		record(rep, rep.Failed == 0)
		if rep.Failed > 0 {
			return fmt.Errorf("prefetch: %d chunk(s) could not be fetched (%v); refusing to mount",
				rep.Failed, rep.Sample)
		}
		fmt.Fprintf(os.Stderr, "pelfs: prefetched %d chunks (%d already cached) across %d files, %.1f MB\n",
			rep.Chunks, rep.Cached, rep.Files, float64(rep.Bytes)/1e6)
	case "background":
		go func() {
			// Half the transfer pool, so warming never starves the
			// interactive I/O the mount is serving.
			rep, err := g.gfs.Prefetch(ctx, max(1, pelicanobj.TransferWorkers()/2))
			if err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: background prefetch: %v\n", err)
				return
			}
			record(rep, rep.Failed == 0)
			fmt.Fprintf(os.Stderr, "pelfs: background prefetch done: %d chunks, %d failed\n",
				rep.Chunks, rep.Failed)
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
				fmt.Fprintf(os.Stderr, "pelfs: refresh: %v (still serving generation %d)\n",
					err, g.gfs.Generation())
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

func (g *genSession) reportSealCost(c sealCost) {
	wall := time.Since(c.wall)
	cpu := processCPU() - c.cpu
	var down, up int64
	g.stats.Update(func(sum *stats.Summary) {
		down, up = sum.Get.Bytes-c.get, sum.Put.Bytes-c.put
	})
	fmt.Fprintf(os.Stderr, "%s pelfs: seal took %s (%s CPU, %s downloaded, %s uploaded)\n",
		time.Now().Format("15:04:05"), wall.Round(time.Second), cpu.Round(time.Second),
		humanBytes(down), humanBytes(up))
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

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func (g *genSession) sealLocked(ctx context.Context) (*publish.Result, error) {
	keyPath := g.signingKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(g.stateDir, "v2-signing.key")
	}
	signingKey, err := loadOrCreateSigningKey(keyPath, g.sb)
	if err != nil {
		return nil, err
	}
	// Seal a FROZEN view, not the live overlay. A snapshot makes the
	// published generation correspond to an instant, which is the
	// precondition for handing those inodes back to the kernel as clean
	// afterwards: without it a write landing mid-walk could be published
	// half-observed, and an infinite TTL on that value would make the
	// mismatch permanent.
	snapDir, err := os.MkdirTemp(g.stateDir, "snapshot-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(snapDir) //nolint:errcheck
	snap, err := g.ov.Snapshot(snapDir)
	if err != nil {
		return nil, fmt.Errorf("snapshot the overlay: %w", err)
	}
	defer snap.Close() //nolint:errcheck

	cost := g.beginSealCost()
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap,
		Inner:           g.inner,
		SpoolDir:        g.stateDir,
		Branch:          g.branch,
		SigningKey:      signingKey,
		Prev:            g.sb,
		PrevRaw:         g.prevRaw,
		DEK:             g.dek,
		IdentityKey:     g.identityKey,
		KeyID:           g.keyID,
		KeyTable:        g.sb.KeyTable,
		DedupIndexPath:  filepath.Join(g.stateDir, "v2-dedup.db"),
	})
	if err != nil {
		return nil, err
	}
	g.reportSealCost(cost)
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
	// simply keeps paying zero TTLs for state that is already durable.
	if _, err := g.gfs.Swap(ctx, res.Superblock); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: sealed generation %d, but the mount could not follow it (%v); inodes stay dirty\n",
			res.Superblock.Generation, err)
	} else if rep, err := g.ov.Rebase(ctx, snap.Seq(), overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: sealed generation %d, but rebase failed (%v); inodes stay dirty\n",
			res.Superblock.Generation, err)
	} else {
		fmt.Fprintf(os.Stderr, "pelfs: %d inode(s) returned to clean; %d still dirty\n",
			len(rep.Clean), rep.Dirty)
		g.stats.Update(func(sum *stats.Summary) { sum.RebasedClean += int64(len(rep.Clean)) })
	}

	g.stats.Update(func(sum *stats.Summary) {
		sum.Seals++
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
// Nothing the mount holds changes, and that is what makes an in-place
// checkpoint safe. The served generation stays the one genfs opened, and
// the overlay keeps every dirty row: its merged base+dirty view IS what
// was just published, so every attribute and page the kernel has cached is
// still correct and there is nothing to invalidate. Only the seal anchor
// moves. The next seal therefore re-walks the same merged view over the
// generation it just produced — content-identical if nothing changed since
// (which costs a redundant generation, never a wrong one), and the union
// of old and new work if anything did.
//
// Two properties a caller must know:
//
//   - The walk is not atomic against writers inside the mount. The overlay
//     has no snapshot primitive (v1 gets one from VACUUM INTO), so a
//     checkpoint of a live tree captures what the walk saw, exactly like
//     tar over a live directory. The generation is always self-consistent
//     and signed; it just may not correspond to any instant.
//   - The branch head now names a generation the ON-DISK overlay does not
//     sit over. Everything up to the checkpoint is durable — the point of
//     the verb — but a crash before unmount strands the delta written
//     after it: overlay.Open refuses a base it was not recorded against.
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
	res, err := g.sealLocked(ctx)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "pelfs: checkpoint: sealed generation %d while mounted; the mount keeps serving\n",
		res.Superblock.Generation)
	return fmt.Sprintf("generation %d: %d chunks uploaded, %d catalogs, %d new packs",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks)), nil
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
func (g *genSession) checkpointPeriodically(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			summary, err := g.checkpoint(ctx)
			elapsed := time.Since(start)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil:
				fmt.Fprintf(os.Stderr,
					"pelfs: periodic checkpoint failed, retrying next interval (your changes remain safe in the overlay): %v\n", err)
			case elapsed > slowCheckpoint:
				fmt.Fprintf(os.Stderr, "pelfs: checkpoint took %s (%s)\n", elapsed.Round(time.Second), summary)
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
			fmt.Fprintf(os.Stderr, "pelfs: overlay kept at %s (--no-seal); remount to resume or seal\n", g.overlayDir)
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
		fmt.Fprintln(os.Stderr, "pelfs: nothing changed; no new generation")
		return nil
	}
	fmt.Fprintln(os.Stderr, "pelfs: sealing the overlay into the next generation...")
	res, err := g.sealLocked(ctx)
	if err != nil {
		ok := false
		g.stats.Update(func(sum *stats.Summary) { sum.SealOK = &ok })
		return fmt.Errorf("seal: %w (the overlay is intact at %s; remount to retry)", err, g.overlayDir)
	}
	ok := true
	g.stats.Update(func(sum *stats.Summary) { sum.SealOK = &ok })
	fmt.Fprintf(os.Stderr, "pelfs: sealed generation %d (%d chunks, %d catalogs, %d packs)\n",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks))

	// The overlay's contents are now published, and it is pinned to the
	// generation it shadowed — which is no longer the head. Leaving it
	// would make this state directory single-use: the next mount would
	// refuse with a generation mismatch.
	g.ovMu.Lock()
	g.spent = true
	_ = g.ov.Close()
	g.ovMu.Unlock()
	if err := os.RemoveAll(g.overlayDir); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: sealed, but the spent overlay at %s could not be removed: %v\n",
			g.overlayDir, err)
	}
	return nil
}

// controlHooks exposes the session on the control socket. Flush stays nil
// (404 on purpose): phase 3 has no staging tier to drain — writes land in
// the overlay's WAL and staging files as they happen, and the only step
// that moves them to the federation is the seal behind Publish.
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
		fmt.Fprintf(os.Stderr, "pelfs: control socket unavailable: %v\n", err)
		return nil
	}
	return srv
}

// publishMountRecord makes the session discoverable by prefix, so
// `pelfs ctl`, `pelfs status`, and `pelfs umount` reach a phase-3 mount the
// same way they reach a v1 one. It returns the retraction.
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
		fmt.Fprintf(os.Stderr, "pelfs: %s already has a live mount record (pid %d); reach this session with `pelfs ctl %s`\n",
			g.prefix, info.PID, g.stateDir)
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
