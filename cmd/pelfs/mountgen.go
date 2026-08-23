package main

import (
	"bytes"
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

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/nfsmount"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/scratch"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// statsInterval is how often a live session rewrites its statistics file.
const statsInterval = 30 * time.Second

// dedupIndexName is the publish dedup sidecar inside a state directory.
// Named once because three call sites need the same file: the seal writes
// it, and both repack paths carry it across the generation they publish.
const dedupIndexName = "v2-dedup.db"

// nfsMaxResident bounds residency on the loopback-NFS backend. That
// frontend re-descends from the root on every operation, so an evicted
// entry costs a re-descent and nothing else, and the cap is a genuine
// working-set bound.
const nfsMaxResident = 100_000

// fuseMaxResident bounds residency on the FUSE backend, and it is a
// BACKSTOP rather than a working set — which is why it is twenty times
// the NFS number.
//
// Under FUSE the kernel owns inode lifetime. It hands out a nodeid at
// LOOKUP and releases it with FORGET, and between those two points it is
// entitled to send operations for that inode; genfs answering ErrStale
// for one becomes ESTALE in the application (internal/rawfuse). So a cap
// that fires during ordinary work is a correctness regression, not a
// memory saving, and residency must be allowed to track whatever the
// kernel's dcache is holding. That is why this was zero.
//
// Zero is still the wrong answer, because "track the kernel" has no
// bound at all: a descent over a very large tree — a find(1) over a
// hundred million inodes, or a seal walking one — grows the map at about
// 110 B/inode with nothing to stop it, and the process dies. Between an
// ESTALE and the OOM killer, the ESTALE is recoverable and the kill is
// not: the killed mount takes the unsealed overlay's session with it.
//
// 2,000,000 entries is ~220 MB, which is where that trade tips on a
// laptop. It is far above any dcache a kernel keeps for a working set
// (the kernel evicts under its own memory pressure long before this, and
// sends the FORGETs that free these entries the correct way), so on real
// workloads it never fires — genfs.Residency reports whether it ever did,
// and the session statistics publish that, so an ESTALE seen in the field
// has a number to check rather than a theory.
const fuseMaxResident = 2_000_000

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
	prefix   string
	branch   string
	tag      string
	stateDir string
	// stateRoot is the root this invocation's flags select — the same
	// answer cmdOpts.stateRoot gives — and it is where the mount record
	// goes. It is a FIELD rather than a call to defaultStateRoot() from
	// publishMountRecord because that call was the bug: a session pointed
	// entirely at a temp directory still created a vol-<id> directory in
	// the user's home for its record. Empty in a session built without
	// one (a test); publishMountRecord then falls back to stateDir, never
	// to the home directory.
	stateRoot  string
	mountpoint string
	backend    string
	sessionID  string
	started    time.Time
	rw         bool
	noSeal     bool

	overlayDir string
	inner      pelicanobj.Store // counted transport; see countedStore
	// repacking is set while a background repack is between its sweep and
	// its flip, so the periodic checkpoint can stand aside. Guarded by mu.
	repacking bool
	// lastCollect is when this session last ran the sweep, which is what
	// the collection floor is measured from. Session-scoped on purpose: a
	// sweep publishes nothing, so there is nowhere in the volume to record
	// it, and a mount that has just started is itself decent evidence that
	// nobody has collected lately. Guarded by mu.
	lastCollect time.Time
	// refs is the verified ref store this session reads and flips through.
	// Kept on the session because background maintenance publishes too
	// (autorepack.go), and a second store would keep a second key pin.
	refs *refs.Store
	gfs  *genfs.FS
	ov   *overlay.FS // nil unless --rw

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

	// The periodic checkpointer's lifecycle, so the exit path can JOIN it
	// instead of racing it. Stopping is two signals rather than one:
	// checkpointStop tells the loop to stop TICKING, and a checkpoint
	// already running seals on a context nothing here cancels, so it runs
	// to completion. Cutting one off mid-seal is not untidiness — the
	// generation it was building goes unpublished, and a batch wrapper is
	// entitled to delete the state directory the instant this process
	// exits, taking the unsealed overlay with it.
	//
	// ckMu guards checkpointStop alone, and it is its own mutex rather than
	// g.mu because the two paths that stop the ticker are a lease conflict
	// (on the renewal goroutine, which may fire before the checkpointer is
	// even started) and a refused seal (which is holding g.mu already).
	ckMu           sync.Mutex
	checkpointStop context.CancelFunc
	checkpointWG   sync.WaitGroup
	// drainOnce keeps the join single: the exit path calls it explicitly
	// so the wait is timed where it belongs, and a defer registered at
	// startup calls it on every other way out of runMountGen.
	drainOnce sync.Once

	// content is the write path's store, when this session has one. The
	// checkpoint policy asks it how far behind the uplink is.
	content *memtable.Store

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
	// finder makes the mount a Finder-visible macOS volume, and
	// volumeName is what it should be called (cmd/pelfs/finder.go). Both
	// are inert everywhere else: the default mount is deliberately
	// invisible, because that is what every script, every gate and every
	// Linux user has always got.
	finder     bool
	volumeName string
	// background is set only by the `pelfs mount` daemon child, and it
	// decides ONE thing: where the mount record goes. See registryRoot.
	background bool
}

// registerFinderFlags puts --finder and --volume-name on a command that
// mounts. Per command rather than in registerFlags, because they mean
// nothing to `pelfs gc` or `pelfs tag` -- and not on `pelfs shell` at all,
// which mounts on a temporary directory it deletes at exit: a volume in
// the Finder sidebar whose name is pelfs-mnt-1234567 and which vanishes
// when a subshell exits is not the thing this flag is for.
func registerFinderFlags(fs *flag.FlagSet, a *genArgs) {
	fs.BoolVar(&a.finder, "finder", false, "macOS only: mount a browsable volume that shows up in the Finder sidebar under "+
		"a chosen name, refusing the Finder's own bookkeeping files; ejecting it in the Finder seals and ends the session")
	fs.StringVar(&a.volumeName, "volume-name", "", "with --finder, the name the volume answers to (default: the last component of the prefix)")
}

// FOREGROUND, AND THE TRAILING -f APPTAINER ADDS.
//
// `pelfs mount-gen` has always run in the foreground: it serves in this
// process, does not fork, does not re-exec, and holds the terminal until
// the mount goes away (`pelfs mount` is the one that daemonizes). That is
// exactly what a `--fusemount` driver must do — apptainer waits on the
// process it started and treats its exit as the mount going away — so the
// flag it passes to say so, `-f`, is accepted and is a no-op rather than
// an error.
//
// It is accepted AFTER the positional arguments as well as before, because
// apptainer's command line is `<driver> /dev/fd/N -f` and Go's flag
// package stops parsing at the first non-flag argument: without hoisting,
// the `-f` arrives as a third positional and the run dies on the arity
// check with a message about argument counts.
func hoistForeground(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "-f", "--f", "-foreground", "--foreground":
			continue
		default:
			out = append(out, a)
		}
	}
	if len(out) == len(args) {
		return args
	}
	return append([]string{"-foreground"}, out...)
}

func cmdMountGen(args []string) int {
	a := genArgs{branch: "main"}
	head, tail, hasTail := splitCommandTail(args)
	if hasTail {
		args = append(hoistForeground(head), append([]string{"--"}, tail...)...)
	} else {
		args = hoistForeground(head)
	}
	o, pos, command, err := parseArgsWithCommand("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&a.branch, "branch", "main", "branch to mount")
		fs.StringVar(&a.tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&a.pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&a.rw, "rw", false, "mount read-write through a local overlay; unmount SEALS the changes into the next generation")
		fs.BoolVar(&a.noSeal, "no-seal", false, "with --rw, keep the overlay at unmount instead of publishing it (resume by remounting)")
		fs.BoolVar(&a.noMemtable, "no-memtable", false, "with --rw, keep written content in staging files and chunk it all at the seal, instead of packing and uploading during the session")
		fs.BoolVar(&a.subshell, "subshell", false, "run a subshell in the mount and unmount (sealing, with --rw) when it exits; a trailing `-- command [args...]` runs that instead of a shell and implies this flag")
		fs.DurationVar(&a.poll, "poll", 0, "read-only: re-check the branch head this often and swap generations live (0 = pinned, the reproducible-batch default)")
		fs.StringVar(&a.signingKeyPath, "signing-key", "", signingKeyUsage)
		fs.Bool("foreground", false, "no-op: mount-gen always serves in the foreground. Accepted, before or after the mountpoint, because apptainer passes `-f` to a --fusemount driver")
		registerFinderFlags(fs, &a)
	})
	if err != nil {
		return exitErr(err)
	}
	if len(command) > 0 {
		a.subshell = true
	}
	if fusePassedFD(pos[1]) {
		if a.subshell {
			return exitErr(fmt.Errorf("a passed /dev/fuse descriptor (%s) has no path to run a command in: "+
				"the parent that opened it owns the mountpoint, and this process never learns where it is. "+
				"Run the command in the container the mount is for", pos[1]))
		}
		if a.backend, err = passedFDBackend(o); err != nil {
			return exitErr(err)
		}
	} else {
		if a.finder {
			finderBackend(o)
		}
		if a.backend, err = resolveBackend(o); err != nil {
			return exitErr(err)
		}
	}
	if a.finder {
		if err := checkFinder(a.backend); err != nil {
			return exitErr(err)
		}
	}
	return runMountGen(o, pos[0], pos[1], command, a)
}

// passedFDBackend is resolveBackend for a mountpoint that is already a
// mounted /dev/fuse descriptor.
//
// The usability probe is skipped deliberately: the mount EXISTS — someone
// else opened the device and called mount(2) — so opening /dev/fuse
// ourselves answers a question nobody asked, and on a host that permits
// FUSE only through that parent (a container with no /dev/fuse of its own,
// which is the whole point of being handed a descriptor) it answers it
// wrongly and refuses a mount that would have worked.
//
// The NFS backend cannot serve a descriptor at all: it attaches by calling
// mount(2) on a directory, so it is refused here rather than failing later
// with an error about a path that is not a path.
func passedFDBackend(o *cmdOpts) (string, error) {
	switch o.backend {
	case "", "auto", "fuse":
		return "fuse", nil
	default:
		return "", fmt.Errorf("--backend %s cannot serve a passed /dev/fuse descriptor: "+
			"the mount already exists and only the fuse backend can attach to it", o.backend)
	}
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
		// The one refusal recovery still has is the one a user cannot act on
		// without being told where the state directory is and what is still
		// intact, and this is the layer that knows both. Everything through
		// the last checkpoint IS published: a checkpoint signs a generation
		// and any client can mount it, so the escape below costs only what
		// was written after it.
		var stuck *memtable.UnresolvedAdoptionsError
		if errors.As(err, &stuck) {
			return nil, fmt.Errorf("%w\n"+
				"these extents were taken from a published generation by reference, and this "+
				"state directory does not say which chunks they are — a mount that has just "+
				"started cannot ask the generation, and serving the files without them would "+
				"mean writing zeros over content that still exists.\n"+
				"what is still yours: every generation this volume ever published, including "+
				"the last checkpoint's. Mount without --rw to read it, or `pelfs fsck` it.\n"+
				"to write again: move %s and %s aside (a fresh --state-dir does the same). "+
				"That discards what was written after the last checkpoint, and nothing else",
				err, filepath.Join(g.stateDir, "content"), g.overlayDir)
		}
		return nil, fmt.Errorf("open the write path's content store: %w", err)
	}
	// Recovery is allowed to lose content — a mount is tied to a job, and
	// a crashed job usually discards its state — but it is never allowed
	// to lose it quietly.
	if rep.Loss() {
		ui.Warn("the previous session left content that could not be recovered:\n{report}", "report", rep.String())
	} else if recs := recoveredExtents(rep); recs > 0 {
		// Said out loud even when nothing was lost. A silent recovery
		// leaves a user watching a mount behave differently — reading
		// through a location map it rebuilt, finishing a session it did
		// not start — with no account of why.
		ui.Info("recovered {extents} extents from the previous session; its unsealed changes are still here",
			"extents", recs)
	}
	if packs, bytes := store.CacheAdopted(); packs > 0 {
		ui.Info("{packs} packs are already on local disk ({bytes}); reads of them cost nothing",
			"packs", packs, "bytes", ui.ByteCount(bytes))
	}
	// Once-only: the seal at exit closes it as soon as the last thing that
	// reads it is done, and the teardown defer closes it on every other
	// path. Both must be able to call it.
	g.closeContent = sync.OnceValue(closeStore)
	g.content = store
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

// uploadBacklog is how much this session has cut into packs and not yet
// sent, or zero when its content is in staging files.
func (g *genSession) uploadBacklog() int64 {
	if g.content == nil {
		return 0
	}
	return g.content.Stats().UploadBacklog
}

// recoveredExtents totals what a recovery found across its buffers.
func recoveredExtents(rep *memtable.Report) int {
	n := 0
	for _, b := range rep.Buffers {
		n += b.Records
	}
	return n
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

	// Where a Finder volume goes, and what it is called, is decided before
	// anything else happens: the mountpoint it resolves to is the one the
	// session records, reports and mounts on. An empty mountpoint means
	// "choose one", which only `pelfs mount --finder` passes.
	var vol finderVolume
	if a.finder {
		var err error
		if vol, err = finderMount(prefix, a.volumeName, mountpoint); err != nil {
			return exitErr(err)
		}
		mountpoint = vol.MountPoint
	} else if mountpoint == "" {
		// Unreachable through either command -- `mount-gen` requires the
		// path and `pelfs mount` defaults it -- and asserted rather than
		// assumed, because an empty mountpoint reaches os.MkdirAll and
		// mount_nfs as the current directory.
		return exitErr(errors.New("no mountpoint: only a --finder mount may leave the choice to pelfs"))
	}

	g := &genSession{
		prefix:         prefix,
		branch:         branch,
		tag:            tag,
		stateDir:       stateDir,
		stateRoot:      registryRoot(o, a.background),
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
	g.refs = rstore
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
	// so its residency can be bounded as a WORKING set; a FUSE binding's
	// cannot, because the kernel owns those lifetimes and tells us when to
	// drop them (see fuseMaxResident).
	maxResident := fuseMaxResident
	if backend == "nfs" {
		maxResident = nfsMaxResident
	}
	cacheBytes, err := o.cacheBudget()
	if err != nil {
		return fail(err)
	}
	g.gfs, err = genfs.Open(ctx, genfs.Options{
		Inner:       g.inner,
		SB:          sb,
		DEK:         g.dek,
		CacheDir:    filepath.Join(stateDir, "gencache"),
		MaxResident: maxResident,
		// One budget over the whole gencache — decoded chunks, spilled
		// catalogs, trailers and whole packs — because three of those four
		// directories used to have no bound at all, and a day of reading
		// filled the disk (genfs/gencache.go). `pelfs cache` shows what it
		// holds; --cache-size moves the number.
		CacheBytes: cacheBytes,
		// PackCacheBytes is left at its default: the whole-pack cache lives
		// under the state directory's gencache and outlives the session
		// deliberately, because packs are immutable and content-addressed —
		// remounting a volume must not re-fetch what the last mount already
		// pulled down.
	})
	if err != nil {
		return fail(err)
	}
	// Once, and only on a state directory that had one: v0.1.0 kept a flat
	// gencache/chunks/ with a plaintext file per chunk it had ever read,
	// and this build has just deleted it. A user who watches a gigabyte
	// come back is entitled to know what took it.
	if n, b := g.gfs.LegacyChunksSwept(); n > 0 {
		ui.Info("swept {files} decoded-chunk files ({bytes}) left by an older pelfs; "+
			"the decoded cache is one mmap'd arena now",
			"files", n, "bytes", ui.ByteCount(b))
	}
	defer g.down.timed("gencache", func() { g.gfs.Close() }) //nolint:errcheck
	startup.mark("root catalog")
	g.stats.Update(func(sum *stats.Summary) { sum.Generation = sb.Generation })

	if err := g.runPrefetch(ctx, o.prefetch); err != nil {
		return fail(err)
	}
	startup.mark("prefetch")

	// A passed descriptor is not a directory to create, and MkdirAll on
	// `/dev/fd/3` is `ENOTDIR` — which is exactly how a --fusemount driver
	// used to die before it ever reached the mount (docs/design-apptainer.md,
	// W1).
	passedFD := fusePassedFD(mountpoint)
	if !passedFD {
		if err := os.MkdirAll(mountpoint, 0755); err != nil {
			return fail(err)
		}
	}

	var srv fuseServer
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
		nfsSrv, err = nfsmount.Serve(bfs, nfsmount.ServeOptions{HideFinderFiles: a.finder})
		if err == nil {
			defer g.down.timed("server", func() { nfsSrv.Close() }) //nolint:errcheck
			err = nfsSrv.Mount(mountpoint, nfsmount.MountOptions{
				VolumeName: vol.Name,
				Browsable:  a.finder,
			})
		}
	case "fuse", "":
		if rw {
			srv, err = fuseMountRW(mountpoint, g.ov, o.debug)
		} else {
			srv, err = fuseMount(mountpoint, g.gfs, o.debug)
		}
	default:
		return fail(fmt.Errorf("unknown --backend %q (want fuse or nfs)", backend))
	}
	if err != nil {
		// The usual advice ("pelfs mounts with FUSE and has no fallback")
		// is about attaching a mount, and on a passed descriptor the mount
		// already exists: what failed is the FUSE handshake on somebody
		// else's fd, so say that instead of sending the reader to install
		// a package.
		advice := mountAdvice(backend)
		if passedFD {
			advice = fmt.Sprintf(" (the FUSE handshake on the descriptor %s names; "+
				"it has to be an OPEN /dev/fuse whose mount(2) the parent has already done)", mountpoint)
		}
		return fail(fmt.Errorf("mount: %w%s", err, advice))
	}
	startup.mark("mount")
	// Reported after the mount, not after the generation opens: "ready to
	// serve" is not true until the kernel can reach the tree, and the steps
	// in between (opening the overlay, standing up the frontend, the OS
	// mount itself) are exactly the ones nobody could attribute before.
	startup.report("ready to serve in {total} ({packs} packs; discovery {discovery}, "+
		"access {access}, lease {lease}, head {head}, root catalog {root catalog}, "+
		"prefetch {prefetch}, overlay {overlay}, mount {mount})",
		// From the mount rather than the superblock: a generation's packs
		// may be named by a manifest instead of listed inline, and the FS
		// is the thing that has already resolved which.
		"packs", g.gfs.PackCount())
	mode := "read-only"
	if rw {
		mode = "read-write (overlay; unmount seals)"
	}
	ui.Info("generation {generation} mounted {mode} on {mountpoint} (catalog-native)",
		"generation", sb.Generation, "mode", mode, "mountpoint", mountpoint)
	if a.finder {
		reportFinderVolume(vol, rw)
	}
	if passedFD {
		// Said out loud because both halves are surprising: the mount
		// options this process asked for went nowhere (the parent's
		// mount(2) already happened), so pelfs is applying the mode bits
		// itself; and there is nothing here to unmount at exit.
		ui.Info("serving a /dev/fuse descriptor the parent opened: the mountpoint is theirs, " +
			"pelfs enforces file permissions itself (the mount's own options were never ours to set), " +
			"and exit seals and releases rather than unmounting")
	}

	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	go g.stats.RunPeriodic(sessionCtx, statsInterval)
	// Reclaiming what earlier sessions retired belongs here, behind a live
	// mount, and not on either the startup path or the exit path: it is
	// pure unlinking, and both of those are times a user is waiting.
	go sweepRetiredOverlays(stateDir)
	// The same argument for the scratch a KILLED session could not clean
	// up: the spool of a seal that never returned, which is the case that
	// strands gigabytes.
	go sweepStateScratch(stateDir)
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
		g.startCheckpointer(sessionCtx, o.snapshotInterval)
		// Registered AFTER the overlay's close defer, so LIFO runs it
		// BEFORE: no path out of this function may close the overlay with
		// a checkpoint still sealing into it. The exit path below calls it
		// explicitly too, to time the wait where a reader can see it.
		defer g.drainCheckpoints()
		if !o.noAutoRepack {
			// Background maintenance, on the same session context: it holds
			// the lease already and knows when the volume is idle, which a
			// cron job has neither of. The sweep rides the same loop —
			// condemning without collecting frees nothing, and a repack is
			// what makes a sweep worth running.
			go g.maintainPeriodically(sessionCtx, repack.AutoPolicy{}, !o.noAutoGC)
		}
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
		r := srv.NewRefresher(g.gfs, func(c context.Context) (*superblock.Superblock, error) {
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
			// THE EJECT PATH. A signal is not the only way a Finder volume
			// ends: the volume has an eject button, and pressing it is how
			// a Mac user says they are done. Eject detaches the mount and
			// tells the server nothing — we are the server, and a client
			// that has unmounted simply stops sending RPCs — so without a
			// watch on the mount table this select would sit here forever
			// with the session's unsealed overlay in it. The user would
			// have every reason to think they had finished, and the next
			// reboot or `kill` would strand the generation.
			//
			// Ejecting therefore means exactly what `pelfs umount` means:
			// stop serving, seal, exit. The watch runs only for a
			// browsable mount, because that is the only kind with an eject
			// button; an outside `umount` of an ordinary mount still waits
			// for its signal, as it always has.
			var ejected <-chan struct{}
			if a.finder {
				ejected = nfsmount.WatchUnmount(sessionCtx, mountpoint)
			}
			select {
			case <-sigs:
			case <-ejected:
				ui.Info("{mountpoint} is no longer mounted (ejected in the Finder, or unmounted from outside): "+
					"sealing and exiting, the same as `pelfs umount`", "mountpoint", mountpoint)
			}
			g.beginTeardown()
			if unmountErr = nfsmount.Unmount(mountpoint); unmountErr != nil {
				ui.Error("unmount: {error}", "error", unmountErr)
			}
		} else if passedFD {
			// Nothing to unmount: the mount belongs to whoever opened the
			// descriptor, go-fuse refuses a magic mountpoint by design
			// (Server.Unmount), and this process does not even know the
			// path. So there are exactly two ways out, and both end here.
			//
			// The ORDINARY one is the connection going away — apptainer
			// closes its copy of the fd, or the container's mount
			// namespace dies with it. The device then answers ENODEV, the
			// serve loop exits, and Wait returns; the seal that follows
			// runs with no server left to race it. That is the path a job
			// takes every time, including a job that is killed.
			//
			// The other is a signal, and it is why this is a select rather
			// than a Wait. A blocked read(2) on /dev/fuse cannot be
			// interrupted from userspace — neither close nor dup2 wakes it,
			// which is why libfuse unmounts or writes the kernel's abort
			// file instead — so a signalled driver cannot stop its own
			// serve loop. Sealing while it still runs is the same
			// concurrency a mid-session checkpoint already handles; what
			// must not happen is exiting WITHOUT sealing, which would
			// strand the generation.
			served := make(chan struct{})
			go func() { srv.Wait(); close(served) }()
			select {
			case <-served:
			case <-sigs:
				ui.Info("signalled: sealing and releasing (the mount goes away with this process)")
			}
			g.beginTeardown()
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
	// Stopping the session told the checkpointer to stop ticking; this
	// waits for the one that may already be sealing. It marks its own
	// phase, so a user who exits into a slow checkpoint reads WHY exit
	// took time instead of finding it buried in the seal.
	g.drainCheckpoints()
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

// acquireLease takes the advisory write lease for a writable session.
//
// THE LEASE IS THE BRANCH's, not the volume's. g.branch is the only ref
// this session can move, so it is the only thing it needs to hold, and a
// writable mount is never a tag (runMountGen refuses that a few lines
// below the call). A second writable mount of the same volume on a
// different branch now runs alongside this one instead of being refused.
//
// The lease is read and written through a DIRECT-READ store: it is a
// mutable object, and a federation cache serving a stale copy would either
// hide a live holder or resurrect a dead one. It never goes through the
// statistics wrapper's sibling encryption layers either — a client with
// the wrong volume key must still see that the branch is busy.
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
		Store:             metaStore,
		Session:           g.sessionID,
		Branch:            g.branch,
		Steal:             o.stealLease,
		IgnoreVolumeLease: o.ignoreVolumeLease,
		OnConflict: func(holder *lease.Info) {
			g.stats.Update(func(sum *stats.Summary) { sum.LeaseConflictObserved = true })
			// STOP CHECKPOINTING. Every seal from here on is refused by
			// fenceSeal, and a periodic checkpointer that keeps ticking
			// would freeze the overlay, walk the dirty set and upload packs
			// on its interval, forever, to be told each time what it was
			// told the first time. The work is not lost by stopping — it
			// stays in the overlay, which is where a refused seal leaves it
			// anyway.
			g.haltCheckpointer()
			// "this branch", not "this prefix": another writer on another
			// branch is now ordinary, and only a writer on OURS is the
			// emergency this warning is for.
			ui.Warn("another client took over branch {branch}: {holder}\n"+
				"concurrent writers on one branch WILL corrupt each other; stop one of them.\n"+
				"this session keeps serving but will no longer PUBLISH: checkpointing is stopped and\n"+
				"the seal at unmount will be REFUSED, keeping this session's work in its overlay.\n"+
				"remount to take a fresh lease and reseal on top of whatever that client published.",
				"branch", g.branch, "holder", holder.Describe())
		},
	})
	if err != nil {
		return nil, err
	}
	g.stats.Update(func(sum *stats.Summary) {
		sum.LeaseHeld = true
		sum.LeaseKey = l.Key()
	})
	return l, nil
}

// fenceSeal refuses to publish when this session can no longer show that it
// holds the branch. Called by sealLocked, so it covers the checkpoint, the
// seal at unmount, and anything else that reaches a flip through it.
//
// WHAT IT IS FOR is the mount that went to sleep. A lease is kept alive by a
// renewal loop, and a suspended process runs no loop: a lid closed for three
// hours wakes past every TTL, with no tick having fired and nothing on the
// seal path that ever asked. In that window another writer is ENTITLED to
// take the branch — the lease says so, by expiring — and if it takes it,
// seals and releases, it leaves no trace but a moved head.
//
// The refusal is worth more than it looks, because of WHEN it happens. The
// flip's compare-and-swap would catch most of this at the very end, after a
// freeze, a walk and however many gigabytes of packs; and it would catch
// none of the case where the head has NOT moved yet because the usurper has
// not published yet, which is precisely the interleaving that ends with two
// writers clobbering each other inside the check-then-put window.
//
// --no-lease sessions are unaffected: g.lease is nil, Fence returns nil, and
// they keep exactly the behaviour they have always had (the flip's own CAS,
// and nothing else). The flag's help says so.
//
// The caller holds g.mu, which is what makes reading the anchor safe here
// and what obliges the guard below not to take it again.
func (g *genSession) fenceSeal(ctx context.Context) error {
	anchor := g.prevRaw
	err := g.lease.Fence(ctx, func(ctx context.Context) (bool, error) {
		return g.headIs(ctx, anchor)
	})
	if err == nil {
		return nil
	}
	g.stats.Update(func(sum *stats.Summary) { sum.LeaseConflictObserved = true })
	// No new checkpoint should start after this: every one of them would
	// spend the same work to be refused by the same check.
	g.haltCheckpointer()
	return fmt.Errorf("refusing to publish: %w\n"+
		"the overlay is intact at %s and nothing in it has been lost", err, g.overlayDir)
}

// headIs reports whether refs/<branch> still holds exactly the bytes the
// caller's next flip is anchored on.
//
// It reads the raw object and compares bytes rather than going through
// refs.Fetch, for two reasons. Fetch VERIFIES and PINS — it would record a
// usurper's generation as this client's last accepted one on the way to
// telling us we had lost the branch, which is a trust-state change made on
// behalf of a question. And byte equality is the exact question: the flip's
// own guard compares the same two things (publish.flip), so a guard that
// agreed with the head on anything looser could pass a seal the flip will
// then refuse.
//
// Read through the direct-read variant, as every read of a mutable object
// in this codebase is: a cached copy of a ref that just moved reports the
// head we are trying to detect a change in.
func (g *genSession) headIs(ctx context.Context, anchor []byte) (bool, error) {
	if len(anchor) == 0 {
		return false, errors.New("this session has no recorded head to compare the branch against")
	}
	inner := g.inner
	if d, ok := pelicanobj.AsDirectReader(inner); ok {
		inner = d.DirectVariant()
	}
	cur, err := pelicanobj.ReadMutable(ctx, inner, publish.RefPrefix+g.branch)
	if err != nil {
		return false, err
	}
	return bytes.Equal(cur, anchor), nil
}

// haltCheckpointer stops the ticker WITHOUT waiting for a checkpoint in
// flight, which is what separates it from drainCheckpoints.
//
// It exists for the conflict path, and the distinction is the whole reason
// it is a second function: it is called from the renewal goroutine and from
// inside a seal, both of which would deadlock on a join — the seal it would
// be waiting for is the caller. Stopping the ticker is all that is wanted
// anyway: a checkpoint already running finishes or is refused on its own,
// and no new one starts.
func (g *genSession) haltCheckpointer() {
	g.ckMu.Lock()
	stop := g.checkpointStop
	g.ckMu.Unlock()
	if stop != nil {
		stop()
	}
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
	// The field is NOT cleared. Release is idempotent, and the statistics
	// sampler and the control socket both read the lease's state from their
	// own goroutines: clearing it here would race them to save nothing.
	// A federation round trip on the exit path, so it belongs in the
	// teardown breakdown rather than in whatever phase it lands next to.
	g.down.mark("lease release")
}

// runPrefetch honors the shared --prefetch flag's three modes.
//
// What a prefetch moves is PACKS, not decoded chunks (genfs/prefetch.go):
// a pack is the unit of transfer and everything a read needs comes out of
// one, so "the data is local" and "the packs are local" are the same
// statement, and the second costs no decode.
func (g *genSession) runPrefetch(ctx context.Context, mode string) error {
	record := func(rep *genfs.PrefetchReport, complete bool) {
		g.stats.Update(func(sum *stats.Summary) {
			sum.PrefetchPacks = int64(rep.Packs + rep.Cached)
			sum.PrefetchBytes = rep.Bytes
			sum.PrefetchFetchedBytes = rep.Fetched
			sum.PrefetchFailed = int64(rep.Failed)
			sum.PrefetchComplete = complete
		})
		_ = g.stats.Flush()
	}
	switch mode {
	case "", "none":
	case "all":
		ui.Info("prefetching the generation's packs into the local cache...")
		rep, err := g.gfs.Prefetch(ctx, pelicanobj.TransferWorkers())
		if err != nil {
			// A generation larger than the cache budget is the one refusal
			// worth spelling out: nothing is wrong with the volume or with
			// the federation, the disk is simply too small for what was
			// asked, and the two numbers say so.
			var budget *genfs.PrefetchBudgetError
			if errors.As(err, &budget) {
				return fmt.Errorf("prefetch: refusing to mount: the generation is %s in %d packs and the local cache budget is %s; "+
					"raise --cache-size, or use --prefetch none and read from the federation",
					ui.ByteCount(budget.Need), budget.Packs, ui.ByteCount(budget.Budget))
			}
			return fmt.Errorf("prefetch: %w", err)
		}
		record(rep, rep.Failed == 0)
		if rep.Failed > 0 {
			return fmt.Errorf("prefetch: %d pack(s) could not be made local (%v); refusing to mount",
				rep.Failed, rep.Sample)
		}
		ui.Info("prefetched {packs} packs ({cached} already cached) across {files} files, {bytes} local ({fetched} transferred)",
			"packs", rep.Packs, "cached", rep.Cached, "files", rep.Files,
			"bytes", ui.ByteCount(rep.Bytes), "fetched", ui.ByteCount(rep.Fetched))
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
			ui.Info("background prefetch done: {packs} packs, {failed} failed, {fetched} transferred",
				"packs", rep.Packs, "failed", rep.Failed, "fetched", ui.ByteCount(rep.Fetched))
		}()
	default:
		return fmt.Errorf("unknown --prefetch %q (want none, all, or background)", mode)
	}
	return nil
}

// follow drives the live-refresh poller and counts the swaps it applied.
// The frontend's own Run does the polling but reports only to the log; the
// swap count belongs in the session statistics.
func (g *genSession) follow(ctx context.Context, r fuseRefresher, every time.Duration) {
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
	cache := cacheStats(g.gfs)
	write := writeStats(g.content)
	resident, evicted := g.gfs.Residency()
	var st overlay.Stats
	var live bool
	g.ovMu.RLock()
	if g.ov != nil && !g.spent {
		var err error
		st, err = g.ov.Stats()
		live = err == nil
	}
	g.ovMu.RUnlock()
	// The lease's fencing state is sampled here rather than pushed from the
	// lease package, for the reason the overlay pressure is: the interesting
	// values are the ones a session ends with, and a callback per transition
	// would have to fire from the renewal goroutine into the collector.
	ls := g.lease.State()
	g.stats.Update(func(sum *stats.Summary) {
		sum.Generation = gen
		sum.Cache = cache
		if ls.WasInterrupted {
			sum.LeaseInterrupted = true
		}
		if !ls.RevalidatedAt.IsZero() {
			sum.LeaseRevalidatedAt = ls.RevalidatedAt
		}
		sum.ResidentInodes = int64(resident)
		sum.ResidencyEvicted = evicted
		if write != nil {
			sum.Write = write
		}
		if !live {
			return
		}
		sum.OverlayDirtyNodes = int64(st.DirtyNodes)
		sum.OverlayDirtyEdges = int64(st.DirtyEdges)
		sum.OverlayStagedFiles = int64(st.StagedFiles)
		sum.OverlayStagedBytes = st.StagedBytes
	})
}

// writeStats publishes the write path's backpressure counters. They were
// all being kept and none of them was reachable from a running mount:
// Store.Stats had one caller, which read one field of it. Without these a
// session pacing against a slow uplink and a session that has hung are the
// same observation from outside the process.
func writeStats(store *memtable.Store) *stats.WriteStats {
	if store == nil {
		return nil
	}
	st := store.Stats()
	return &stats.WriteStats{
		BlockedWrites:  st.BlockedWrites,
		UploadBacklog:  st.UploadBacklog,
		RingUsed:       st.RingUsed,
		RingFree:       st.RingFree,
		Packs:          st.Packs,
		UploadedBytes:  st.UploadedBytes,
		UploadedChunks: st.UploadedChunks,
		DedupedChunks:  st.DedupedChunks,

		BaseDedupedChunks: st.BaseDedupedChunks,
		BaseDedupedBytes:  st.BaseDedupedBytes,
	}
}

// cacheStats converts what the generation cache reports into the shape
// the statistics file publishes. It is sampled on the same tick as the
// overlay pressure because it answers the same kind of question — what is
// this mount consuming on the machine it runs on — and because the walk
// behind it is amortized against exactly that interval (genfs.CacheUsage).
func cacheStats(fs *genfs.FS) *stats.CacheStats {
	if fs == nil {
		return nil
	}
	u := fs.CacheUsage()
	ck := fs.ChunkStats()
	cs := &stats.CacheStats{
		Bytes:        u.Bytes,
		Files:        u.Files,
		Limit:        fs.CacheLimit(),
		EvictedFiles: u.EvictedFiles,
		EvictedBytes: u.EvictedBytes,
		Pinned:       u.Pinned,
		ChunkHits:    ck.Hits,
		ChunkMisses:  ck.Misses,
		Dirs:         make(map[string]int64, len(u.Dirs)),
	}
	for _, d := range u.Dirs {
		cs.Dirs[d.Name] = d.Bytes
	}
	return cs
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

// sealLocked publishes the overlay as the next generation. follow says
// whether the MOUNT should then be moved onto what was published: true
// for a mid-session checkpoint, which keeps serving afterwards, and false
// at unmount, where nothing will read the result.
func (g *genSession) sealLocked(ctx context.Context, follow bool) (*publish.Result, error) {
	// FENCE FIRST, before anything is frozen, walked or uploaded.
	//
	// It is here rather than in checkpoint() and sealAtExit() separately so
	// that every path which publishes a generation is covered by
	// construction — including whatever the next one turns out to be. The
	// cost on a healthy session is zero: a lease renewed within its TTL and
	// undisputed answers out of memory (lease.Fence).
	if err := g.fenceSeal(ctx); err != nil {
		return nil, err
	}
	signingKey, err := loadOrCreateSigningKey(g.signingKeyFile(), g.sb)
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
		snapDir, err := scratch.Make(g.stateDir, scratch.Snapshot)
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

	// MEMORY BUDGET of the seal below, documented here because this is
	// where its input is chosen and there is no knob for it.
	//
	// publish holds one `rec` per inode in the walked set for the whole
	// seal — node attrs, xattrs, symlink target, chunk refs, and any
	// INLINE body verbatim (internal/publish, pipeline.recs). The audit
	// measured ~266 B/file plus inline bodies, and the set is O(dirty
	// subtree), not O(volume): a seal walks what changed.
	//
	// So the bound on this is the bound on the dirty set, and that is
	// checkpointInodes: at 200,000 dirty inodes the recs map is ~53 MB,
	// plus inline bodies for the small files among them. A session that
	// ingests a whole tree in one go — first seal, nothing published yet —
	// is the case with no ceiling but the tree's own size, and it is the
	// one a streaming walk would fix. Not today: restructuring the walk is
	// a change to the format's producer, and the number above is small
	// enough that the trigger, not the walk, is the honest lever for now.
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
		DedupIndexPath: filepath.Join(g.stateDir, dedupIndexName),
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
		sum.SealedDedupedChunks = int64(res.Stats.ChunksDeduped)
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
// The number is much larger than it was, because the reason for the old
// one has gone. It was 128 MiB when a session's content sat in staging
// files until the seal: checkpointing often was the only way to get bytes
// out before the user typed exit. The write path uploads continuously, so
// that job is done by the ring's aging rule, and what a checkpoint adds
// is a published NAMESPACE and inodes returned to clean.
//
// Those are worth having, and they are not worth having every 128 MiB. On
// a kernel-tree extraction the old threshold fired six checkpoints costing
// 108s, about 110s of which was the whole regression against the staging
// path — and half of that was the follow phase, with the mount blocked.
const checkpointBytes = 1 << 30

// checkpointInodes is how many dirty inodes trigger a checkpoint
// regardless of bytes or clock.
//
// Bytes are the wrong meter for a metadata-heavy session, and the failure
// is the mirror image of the one that put the byte trigger here. A tree of
// small files can dirty a million inodes without ever staging a gigabyte,
// so neither of the other two triggers fires — and per-inode session state
// grows the whole time: modSeq and the dirty set in the overlay, prov,
// genfs residency, the memtable's location map, and, at the seal, an edge
// map of the whole namespace. The audit measured about 600 B per file
// across those, unbounded between checkpoints.
//
// A checkpoint is the only thing that gives that memory back: rebase drops
// the overlay rows, modSeq, the dirty set and the provenance of every
// inode it returns to clean, and the content store drops the extents those
// rows named. So the trigger belongs where the memory does.
//
// 200,000 is ~120 MB at the measured per-inode cost — a fifth of what a
// million-file session was carrying — and it is deliberately well above
// the ~90k-file kernel tree the byte and time triggers already handle, so
// no workload that checkpoints sensibly today starts checkpointing more
// often because of this. It is the metadata equivalent of checkpointBytes:
// pressure, not the clock, decides.
const checkpointInodes = 200_000

// checkpointDue reports whether what the overlay is holding justifies a
// checkpoint on its own, without waiting for the interval. Either meter
// alone is enough: they measure different resources — the uplink and the
// machine's memory — and a session can sit at the limit of one while
// nowhere near the other.
func checkpointDue(staged int64, nodes int) bool {
	return staged >= checkpointBytes || nodes >= checkpointInodes
}

// checkpointBacklogHold skips a pressure checkpoint while the uplink is
// still working through what the session already produced.
//
// A checkpoint under those conditions is the wrong thing twice: it drains
// the queue before it can freeze, so it waits for exactly the backlog it
// found, and it then blocks the mount through publish and rebase. The
// content is going out either way. Better to let it, and checkpoint when
// the session has caught up or the interval comes round.
const checkpointBacklogHold = 64 << 20

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

// pressure reports what the overlay is holding that a checkpoint would
// publish: staged content bytes, and dirty inodes. Both are -1 when the
// overlay cannot be sampled (it is being sealed, or is gone).
//
// The two are sampled together, from one Stats call, because they are two
// meters on the same thing and a session can be at the limit of either
// without approaching the other: a video file is bytes without inodes, an
// unpacked source tree is inodes without bytes.
func (g *genSession) pressure() (bytes int64, nodes int) {
	g.ovMu.RLock()
	defer g.ovMu.RUnlock()
	if g.ov == nil || g.spent {
		return -1, -1
	}
	st, err := g.ov.Stats()
	if err != nil {
		return -1, -1
	}
	return st.StagedBytes, st.DirtyNodes
}

// checkpointDrainNotice is how long the exit path waits for a checkpoint
// in flight before saying out loud that it is waiting. Below it the join
// is invisible, which is right: the common case is a session with nothing
// in flight, and it must not narrate a wait it did not do.
const checkpointDrainNotice = 250 * time.Millisecond

// startCheckpointer runs the periodic checkpointer under a lifecycle the
// exit path can join, which is the only reason it is not a bare `go`.
//
// The cancel is the session's own, derived from the session context: the
// drain must be able to stop the loop by itself, because it also runs
// from a defer, and defers unwind in an order that puts it BEFORE the
// deferred stopSession it would otherwise be waiting on.
func (g *genSession) startCheckpointer(ctx context.Context, every time.Duration) {
	ckCtx, stop := context.WithCancel(ctx)
	g.ckMu.Lock()
	g.checkpointStop = stop
	g.ckMu.Unlock()
	g.checkpointWG.Add(1)
	go func() {
		defer g.checkpointWG.Done()
		g.checkpointPeriodically(ckCtx, every)
	}()
}

// drainCheckpoints stops the checkpointer and waits for it, and it is the
// step that must come before anything closes the overlay.
//
// The nil-map panic that used to come out of a checkpoint's Rebase was
// made survivable in internal/overlay — a checkpoint caught by teardown
// now reports a failed rebase instead of crashing — but survivable is not
// the same as done. The work is still abandoned: the seal that was in
// flight publishes nothing, and the changes it was publishing stay in an
// overlay whose state directory a batch-system wrapper may wipe as soon
// as the process exits. Waiting is correctness.
//
// A second Ctrl+C during the wait is answered with a line, not with an
// abort. There is no force-abort here on purpose: the only thing an abort
// could do is throw away the seal this is waiting for.
func (g *genSession) drainCheckpoints() {
	g.drainOnce.Do(func() {
		g.ckMu.Lock()
		stop := g.checkpointStop
		g.ckMu.Unlock()
		if stop == nil {
			return // no checkpointer: read-only, or --snapshot-interval 0
		}
		stop()
		done := make(chan struct{})
		go func() {
			g.checkpointWG.Wait()
			close(done)
		}()
		select {
		case <-done:
			g.down.mark("checkpoint drain")
			return
		case <-time.After(checkpointDrainNotice):
		}
		ui.Info("waiting for the checkpoint in flight to finish sealing before unmounting; " +
			"stopping it here would publish nothing and leave the work in the overlay")
		// Absorbed rather than acted on, and only for as long as the wait
		// lasts. In `pelfs shell` the subshell's handler has already been
		// removed by the time teardown runs, so without this a keyboard
		// interrupt during the drain kills the process mid-seal — the
		// exact outcome the drain exists to prevent.
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigs)
		for {
			select {
			case <-done:
				g.down.mark("checkpoint drain")
				return
			case s := <-sigs:
				ui.Warn("{signal} while a checkpoint is still sealing; still waiting, "+
					"because interrupting it now would lose the generation it is publishing",
					"signal", s)
			}
		}
	})
}

func (g *genSession) checkpointPeriodically(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	// A checkpoint that has STARTED runs on a context the session's stop
	// does not reach. Cancelling mid-seal would abandon uploads that are
	// already on the wire and leave the branch where it was, which is the
	// one outcome worse than exit taking a few seconds longer.
	sealCtx := context.WithoutCancel(ctx)
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
			// A ready timer and a cancelled context are both ready cases,
			// and select picks between them at random. Re-checking here is
			// what makes "no NEW checkpoint starts after the stop" a
			// property rather than a coin toss the exit path pays for.
			if ctx.Err() != nil {
				return
			}
			staged, nodes := g.pressure()
			if !checkpointDue(staged, nodes) {
				continue
			}
			if backlog := g.uploadBacklog(); backlog > checkpointBacklogHold {
				// Already pushing. A checkpoint here would wait for this
				// backlog and then block the mount besides.
				continue
			}
			if time.Now().Before(retryAfter) {
				continue
			}
			start := time.Now()
			summary, err := g.checkpoint(sealCtx)
			// Whatever it did, it FINISHED, so it gets reported: this is
			// the checkpoint the exit path may have just spent seconds
			// waiting for, and a silent return would leave the "checkpoint
			// started" line above as the last word.
			stopping := ctx.Err() != nil
			switch {
			case err != nil && stopping:
				ui.Warn("the checkpoint that was running when the session ended failed "+
					"(your changes remain safe in the overlay, and the seal at exit publishes them): {error}",
					"error", err)
			case err != nil:
				backoff = min(max(2*backoff, pressureSampleInterval(every)), every)
				retryAfter = time.Now().Add(backoff)
				ui.Warn("checkpoint under write pressure failed, retrying in {backoff} "+
					"(your changes remain safe in the overlay): {error}",
					"backoff", backoff.Round(time.Second), "error", err)
			default:
				backoff, retryAfter = 0, time.Time{}
				// Which meter tripped is worth saying: a checkpoint that
				// fired on inodes with almost nothing staged reads as
				// pointless work unless the line names the reason.
				ui.Info("checkpointed {staged} of staged content across {inodes} in {duration} ({summary})",
					"staged", ui.ByteCount(staged), "inodes", ui.Count(nodes, "dirty inode"),
					"duration", time.Since(start).Round(time.Millisecond),
					"summary", summary)
			}
			if stopping {
				return
			}
		case <-t.C:
			if ctx.Err() != nil {
				return
			}
			// A background repack publishes generations too, and by the
			// time it flips it has already paid for a whole reachability
			// sweep and a rewrite. A checkpoint landing in the middle
			// costs the repack all of that — it refuses on a moved head —
			// while costing itself one interval. So the periodic one gives
			// way; write PRESSURE does not, because the alternative there
			// is an unbounded overlay, and a repack is worth less than
			// that.
			if g.repackInFlight() {
				continue
			}
			start := time.Now()
			summary, err := g.checkpoint(sealCtx)
			elapsed := time.Since(start)
			stopping := ctx.Err() != nil
			switch {
			case err != nil && stopping:
				ui.Warn("the checkpoint that was running when the session ended failed "+
					"(your changes remain safe in the overlay, and the seal at exit publishes them): {error}",
					"error", err)
			case err != nil:
				ui.Warn("periodic checkpoint failed, retrying next interval "+
					"(your changes remain safe in the overlay): {error}", "error", err)
			// Reported when it was slow, and always when the exit path was
			// waiting on it: there the duration IS the explanation for the
			// drain phase in the teardown line.
			case elapsed > slowCheckpoint || stopping:
				ui.Info("checkpoint took {duration} ({summary})", "duration", elapsed, "summary", summary)
			}
			if stopping {
				return
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

// scratchSpools are the directories a state directory holds per-run
// scratch in: its own root, where a seal, a checkpoint and a repack spool,
// and the merge spool, which is a second parent a publish runs under
// (merge.go). Both are swept by the same rules.
func scratchSpools(stateDir string) []string {
	return []string{stateDir, filepath.Join(stateDir, "merge")}
}

// sweepStateScratch reclaims the spools of runs that died before they
// could clean up after themselves — the seal that was killed mid-pack, the
// checkpoint that never got to retire its snapshot, the repack that was
// interrupted. Retired OVERLAYS are the neighbouring sweep's business
// (sweepRetiredOverlays); this one is about the state directory's root,
// which nothing collected at all.
//
// It runs at mount time, for read-only mounts too, for the same reason the
// trash sweep does: the process that made the mess is by definition not
// coming back, and the next mount is the next chance anyone has. Which
// directories it may take, and why a live sibling's spool is not among
// them, is internal/scratch's decision — it asks whether the owning
// process is still running rather than whether the lease looks free.
//
// It says what it took. Silence would make this the one part of the
// system that deletes gigabytes without a record, and "where did my disk
// go" is the question a state directory has to be able to answer.
func sweepStateScratch(stateDir string) {
	var total scratch.Reclaimed
	for _, spool := range scratchSpools(stateDir) {
		got, err := scratch.Sweep(spool, scratch.Options{})
		if err != nil {
			ui.Warn("some scratch left by an earlier session under {dir} could not be reclaimed: {error}",
				"dir", spool, "error", err)
		}
		total.Dirs += got.Dirs
		total.Bytes += got.Bytes
		total.Names = append(total.Names, got.Names...)
	}
	if total.Dirs == 0 {
		return
	}
	ui.Info("reclaimed {bytes} of scratch that an earlier session left behind, in {dirs} spool "+
		"directories: {names}",
		"bytes", ui.ByteCount(total.Bytes), "dirs", total.Dirs,
		"names", strings.Join(total.Names, ", "))
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
			// When this volume last collected, and what it got back. The
			// status socket is where someone looks when they suspect a mount
			// is not maintaining itself, and "the sweep has never run in
			// this session" is an answer that only shows up as an ABSENCE
			// otherwise.
			g.mu.Lock()
			lastCollect := g.lastCollect
			g.mu.Unlock()
			if !lastCollect.IsZero() {
				st["last_gc_at"] = lastCollect.Format(time.RFC3339)
			}
			g.stats.Update(func(sum *stats.Summary) {
				if sum.Maintenance == nil {
					return
				}
				st["reclaimed_bytes"] = sum.Maintenance.ReclaimedBytes
				st["reclaimed_objects"] = sum.Maintenance.ReclaimedObjects
				if !sum.Maintenance.LastRepackAt.IsZero() {
					st["last_repack_at"] = sum.Maintenance.LastRepackAt.Format(time.RFC3339)
				}
				if sum.Maintenance.LastCollectionError != "" {
					st["last_gc_error"] = sum.Maintenance.LastCollectionError
				}
			})
			if g.lease != nil {
				st["lease_held"] = true
				// Which object, for the same reason `pelfs status` says
				// it: the lease is one branch's, so "held" alone no longer
				// describes what is excluded.
				st["lease_key"] = g.lease.Key()
				ls := g.lease.State()
				// lease_state, not a pile of booleans. "held", "stale",
				// "interrupted" and "lost" are four different answers to
				// "can this mount still publish", and a reader who has to
				// assemble them from two flags gets it wrong in the
				// direction of believing a dead session is fine.
				st["lease_state"] = ls.Name()
				st["lease_age_seconds"] = ls.Age.Seconds()
				st["lease_conflict"] = ls.Conflicted
				st["lease_interrupted"] = ls.Interrupted
				if !ls.RevalidatedAt.IsZero() {
					st["lease_revalidated_at"] = ls.RevalidatedAt.Format(time.RFC3339)
				}
				if ls.Holder != nil {
					st["lease_taken_by"] = ls.Holder.Describe()
				}
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

// recordRoot is where this session's mount record goes: the root its own
// invocation selected, and never a directory nothing on its command line
// named. A session assembled without a root (a test) records beside its
// own state, which is somewhere the test already owns.
func (g *genSession) recordRoot() string {
	if g.stateRoot != "" {
		return g.stateRoot
	}
	return g.stateDir
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
	dir := volDirIn(g.recordRoot(), g.prefix)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return noop
	}
	path := filepath.Join(dir, "mount.json")
	if info, err := readMountInfo(path); err == nil && info.PID != os.Getpid() && pidAlive(info.PID) {
		ui.Warn("{prefix} already has a live mount record (pid {pid}); reach this session with `pelfs ctl {statedir}`",
			"prefix", g.prefix, "pid", info.PID, "statedir", g.stateDir)
		return noop
	}
	rec := &mountInfo{
		PID:        os.Getpid(),
		Prefix:     g.prefix,
		MountPoint: g.mountpoint,
		Session:    g.sessionID,
		StateDir:   g.stateDir,
		ReadOnly:   !g.rw,
		Started:    g.started,
	}
	if g.rw {
		rec.Branch = g.branch
		if g.lease != nil {
			rec.LeaseKey = g.lease.Key()
		}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return noop
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return noop
	}
	return func() {
		if info, err := readMountInfo(path); err == nil && info.PID == os.Getpid() {
			_ = os.Remove(path)
			// And the directory, if this session's record was the only
			// thing in it. Leaving it behind is how the state root filled
			// up with empty vol-<id> directories, one per run of a
			// harness: os.Remove refuses a non-empty directory, so a
			// volume whose state really does live here is untouched.
			_ = os.Remove(dir)
		}
	}
}

// signingKeyFile is where this session's volume signing key lives:
// --signing-key when given, and the state directory's copy otherwise.
// Shared by the seal and by background maintenance, which both publish.
func (g *genSession) signingKeyFile() string {
	return signingKeyFileIn(g.stateDir, g.signingKeyPath)
}
