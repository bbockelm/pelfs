// Command pelfs mounts a JuiceFS filesystem whose blocks and metadata
// snapshots live in a Pelican federation.
//
//	pelfs shell  <prefix>            mount + subshell; exit to unmount
//	pelfs mount  <prefix> [mnt]      mount in the background (daemon)
//	pelfs umount <prefix|mnt>        stop a background mount cleanly
//	pelfs status                     list background mounts
//	pelfs gc     [--delete] <prefix> find (remove) leaked block objects
//	pelfs fsck   <prefix>            verify all referenced blocks exist
//
// On hosts that cannot mount FUSE (e.g. macOS without macFUSE), `shell`
// re-launches itself inside a Docker container.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/dockerrun"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/mountfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/snapshot"
	"github.com/bbockelm/pelfs/internal/stats"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "shell":
		code = cmdShell(os.Args[2:])
	case "mount":
		code = cmdMount(os.Args[2:])
	case "umount", "unmount":
		code = cmdUmount(os.Args[2:])
	case "status":
		code = cmdStatus(os.Args[2:])
	case "gc":
		code = cmdGC(os.Args[2:])
	case "fsck":
		code = cmdFsck(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		code = 2
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintf(os.Stderr, `pelfs — a locally mountable filesystem stored in a Pelican federation

Usage:
  pelfs shell  [flags] pelican://<federation>/<prefix>   mount + subshell
  pelfs mount  [flags] <prefix> [mountpoint]             background mount
  pelfs umount <prefix-or-mountpoint>                    stop a background mount
  pelfs status                                           list background mounts
  pelfs gc     [flags] [--delete] <prefix>               collect leaked blocks
  pelfs fsck   [flags] <prefix>                          verify referenced blocks

Common flags:
`)
	fs := flag.NewFlagSet("pelfs", flag.ContinueOnError)
	registerFlags(fs, &cmdOpts{})
	fs.PrintDefaults()
}

type cmdOpts struct {
	token            string
	stateDir         string
	keepState        bool
	snapshotInterval time.Duration
	keepSessions     int
	cacheSizeMiB     int64
	blockSizeKiB     int
	writeback        bool
	volume           string
	readOnly         bool
	compress         string
	encryptKeyPath   string
	noRestore        bool
	noLease          bool
	stealLease       bool
	noAcquireToken   bool
	insecure         bool
	debug            bool
	forceDocker      bool
	noDocker         bool
	dockerImage      string
	shellPath        string
	gcDelete         bool
	prefetch         string
	statsFile        string
	flushTimeout     time.Duration
	cacheFreeRatio   float64
}

func registerFlags(fs *flag.FlagSet, o *cmdOpts) {
	fs.StringVar(&o.token, "token", "", "path to a bearer-token file (default: Pelican client token discovery)")
	fs.StringVar(&o.stateDir, "state-dir", "", "directory for local state (metadata db + block cache); default: temp dir (shell), persistent per-prefix dir (mount)")
	fs.BoolVar(&o.keepState, "keep-state", false, "keep a temporary state directory on exit")
	fs.DurationVar(&o.snapshotInterval, "snapshot-interval", 5*time.Minute, "how often to upload a metadata snapshot (0 disables periodic snapshots)")
	fs.IntVar(&o.keepSessions, "keep-sessions", 5, "prune snapshot directories beyond this many past sessions at shutdown")
	fs.Int64Var(&o.cacheSizeMiB, "cache-size", 10240, "local block cache size limit, in MiB")
	fs.IntVar(&o.blockSizeKiB, "block-size", 4096, "object block size, in KiB (fixed at volume creation)")
	fs.BoolVar(&o.writeback, "writeback", false, "upload blocks asynchronously (faster writes, weaker durability)")
	fs.StringVar(&o.volume, "volume", "pelfs", "JuiceFS volume name")
	fs.BoolVar(&o.readOnly, "ro", false, "mount read-only: no writes, no snapshots, no session state uploaded")
	fs.StringVar(&o.compress, "compress", "none", "block compression: none or zstd (fixed at volume creation)")
	fs.StringVar(&o.encryptKeyPath, "encrypt-key", "", "PEM private key enabling client-side encryption of blocks AND metadata snapshots (required again on every later mount)")
	fs.BoolVar(&o.noRestore, "no-restore", false, "do not restore the latest metadata snapshot from the federation")
	fs.BoolVar(&o.noLease, "no-lease", false, "do not take or check the advisory mount lease (concurrent writers will NOT be detected)")
	fs.BoolVar(&o.stealLease, "steal-lease", false, "take over a live lease held by another client (use only when that client is known dead)")
	fs.BoolVar(&o.noAcquireToken, "no-acquire-token", false, "never run interactive token-acquisition flows; rely on discovered tokens only")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification (test federations only)")
	fs.BoolVar(&o.debug, "debug", false, "verbose logging")
	fs.BoolVar(&o.forceDocker, "docker", false, "shell only: force running inside a Docker container")
	fs.BoolVar(&o.noDocker, "no-docker", false, "never fall back to Docker; fail if FUSE is unavailable")
	fs.StringVar(&o.dockerImage, "docker-image", dockerrun.DefaultImage, "container image for the Docker fallback")
	fs.StringVar(&o.shellPath, "shell", "", "shell to launch (default: $SHELL, else /bin/sh)")
	fs.StringVar(&o.prefetch, "prefetch", "none", "download all blocks into the local cache at startup: none, all (blocking; refuse to start on any failure), or background")
	fs.StringVar(&o.statsFile, "stats-file", "", "write a JSON session-statistics summary to this path (default: <state-dir>/pelfs-stats.json)")
	fs.DurationVar(&o.flushTimeout, "flush-timeout", 0, "with --writeback, how long to wait at exit for staged blocks to finish uploading (0 = wait forever)")
	fs.Float64Var(&o.cacheFreeRatio, "cache-free-ratio", 0.05, "minimum free space/inode fraction the block cache preserves on its filesystem")
}

func parseArgs(name string, args []string, minPos, maxPos int, extra func(*flag.FlagSet, *cmdOpts)) (*cmdOpts, []string, error) {
	o := &cmdOpts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	registerFlags(fs, o)
	if extra != nil {
		extra(fs, o)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if fs.NArg() < minPos || fs.NArg() > maxPos {
		return nil, nil, fmt.Errorf("expected %d-%d positional arguments, got %d", minPos, maxPos, fs.NArg())
	}
	if o.compress != "none" && o.compress != "zstd" {
		return nil, nil, fmt.Errorf("--compress must be none or zstd")
	}
	if o.prefetch != "none" && o.prefetch != "all" && o.prefetch != "background" {
		return nil, nil, fmt.Errorf("--prefetch must be none, all, or background")
	}
	return o, fs.Args(), nil
}

// session holds everything a command needs to talk to one prefix.
type session struct {
	o          *cmdOpts
	prefix     string
	stateDir   string
	tempState  bool
	metaPath   string
	cacheDir   string
	mountPoint string

	store      pelicanobj.Store     // raw transport (immutable blocks; cache-served reads)
	data       object.ObjectStorage // block bytes; encrypted + stats wrappers applied
	metaStore  pelicanobj.Store     // direct-read transport for MUTABLE objects (lease, snapshot listings/ETags)
	metaData   object.ObjectStorage // snapshot bytes over metaStore; encrypted + stats wrappers applied
	encryptPEM string

	sessionID string
	lease     *lease.Lease // held for write sessions unless --no-lease
	stats     *stats.Collector
}

// newSession builds the store, wraps encryption, runs the preflight access
// check, sets up local state, and restores the latest metadata snapshot.
func newSession(ctx context.Context, o *cmdOpts, prefix string, needWrite bool) (*session, error) {
	s := &session{o: o, prefix: prefix, sessionID: snapshot.NewSessionID()}

	if o.stateDir != "" {
		s.stateDir = o.stateDir
		if err := os.MkdirAll(s.stateDir, 0700); err != nil {
			return nil, err
		}
	} else {
		var err error
		if s.stateDir, err = os.MkdirTemp("", "pelfs-*"); err != nil {
			return nil, err
		}
		s.tempState = true
	}
	s.metaPath = filepath.Join(s.stateDir, "meta.db")
	s.cacheDir = filepath.Join(s.stateDir, "cache")
	s.mountPoint = filepath.Join(s.stateDir, "mnt")
	if err := os.MkdirAll(s.mountPoint, 0700); err != nil {
		return nil, err
	}

	statsPath := o.statsFile
	if statsPath == "" {
		statsPath = filepath.Join(s.stateDir, "pelfs-stats.json")
	}
	s.stats = stats.New(prefix, s.sessionID, statsPath)
	s.stats.Update(func(sum *stats.Summary) {
		sum.MountPoint = s.mountPoint
		sum.PrefetchMode = o.prefetch
	})

	store, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		AcquireToken: !o.noAcquireToken,
		Insecure:     o.insecure,
	})
	if err != nil {
		return nil, err
	}
	s.store = store
	s.data = store

	// Mutable objects (the mount lease, snapshot current.db and its ETag
	// checks, restore listings) must never be read through federation
	// caches: a stale cached copy breaks read-after-write — e.g. lease
	// acquisition would read an old holder record and refuse to mount.
	// This second store forces origin reads (?directread). Immutable
	// chunks stay on the cache-served store above.
	metaStore, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		AcquireToken: !o.noAcquireToken,
		Insecure:     o.insecure,
		DirectRead:   true,
	})
	if err != nil {
		return nil, err
	}
	s.metaStore = metaStore
	s.metaData = metaStore

	if o.encryptKeyPath != "" {
		pem, err := os.ReadFile(o.encryptKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read --encrypt-key: %w", err)
		}
		s.encryptPEM = string(pem)
		if s.data, err = pelicanobj.WrapEncrypted(store, pem); err != nil {
			return nil, err
		}
		if s.metaData, err = pelicanobj.WrapEncrypted(metaStore, pem); err != nil {
			return nil, err
		}
	}
	// Count every data-path operation (blocks and snapshots) for the
	// session statistics summary.
	s.data = stats.WrapStorage(s.data, s.stats)
	s.metaData = stats.WrapStorage(s.metaData, s.stats)

	if err := pelicanobj.Preflight(ctx, store, prefix, !needWrite); err != nil {
		s.cleanupTemp()
		return nil, err
	}

	// Write sessions hold an advisory lease so a second client on the same
	// prefix is detected up front (and we notice if one appears later).
	// The lease uses the direct-read store, never the encryption wrapper:
	// even a client with a wrong volume key must see the prefix is busy,
	// and a cached stale copy must not fake or hide a holder. Acquired
	// before the snapshot restore so we never restore state another
	// writer is changing.
	if needWrite && !o.readOnly && !o.noLease {
		l, err := lease.Acquire(ctx, lease.Options{
			Store:   metaStore,
			Session: s.sessionID,
			Steal:   o.stealLease,
			OnConflict: func(holder *lease.Info) {
				s.stats.Update(func(sum *stats.Summary) { sum.LeaseConflictObserved = true })
				fmt.Fprintf(os.Stderr,
					"pelfs: WARNING: another client took over this prefix: %s\n"+
						"pelfs: WARNING: concurrent writers WILL corrupt each other; stop one of them.\n"+
						"pelfs: WARNING: this session keeps running but no longer renews the lease.\n",
					holder.Describe())
			},
		})
		if err != nil {
			s.cleanupTemp()
			return nil, err
		}
		s.lease = l
	}

	if !o.noRestore {
		if _, err := os.Stat(s.metaPath); os.IsNotExist(err) {
			key, err := snapshot.Restore(ctx, s.metaStore, s.metaData, s.metaPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: no metadata snapshot restored (%v); starting fresh\n", err)
			} else if key != "" {
				fmt.Fprintf(os.Stderr, "pelfs: restored metadata from %s\n", key)
			}
		}
	}
	return s, nil
}

// releaseLease stops renewals and removes the lease object. Idempotent and
// nil-safe; runs last in shutdown so the lease covers the full write window
// (flush + final snapshot).
func (s *session) releaseLease() {
	if s.lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.lease.Release(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: release lease: %v\n", err)
	}
	s.lease = nil
}

func (s *session) cleanupTemp() {
	s.releaseLease()
	if s.tempState && !s.o.keepState {
		os.RemoveAll(s.stateDir)
		return
	}
	// Inside the Docker fallback the state dies with the container anyway;
	// telling the user it was "kept" would be misleading.
	if os.Getenv("PELFS_IN_DOCKER") != "1" {
		fmt.Fprintf(os.Stderr, "pelfs: local state kept in %s\n", s.stateDir)
	}
}

func (s *session) newSnapshotManager() *snapshot.Manager {
	return &snapshot.Manager{
		MetaPath: s.metaPath,
		Meta:     s.metaStore,
		Data:     s.metaData,
		Session:  s.sessionID,
		OnSnapshot: func(key string, when time.Time) {
			s.stats.Update(func(sum *stats.Summary) { sum.SnapshotsUploaded++ })
		},
		OnError: func(err error) {
			s.stats.Update(func(sum *stats.Summary) { sum.SnapshotErrors++ })
		},
	}
}

// runPrefetch performs the --prefetch policy after a successful mount. In
// "all" mode it blocks and returns an error when any block could not be
// downloaded (the caller refuses to continue); in "background" mode it
// returns immediately and records the outcome in the statistics.
func (s *session) runPrefetch(ctx context.Context, mnt *mountfs.Mounted) error {
	record := func(rep *mountfs.PrefetchReport, err error) {
		s.stats.Update(func(sum *stats.Summary) {
			sum.PrefetchSlices = int64(rep.Slices)
			sum.PrefetchFailed = int64(rep.Failed)
			sum.PrefetchComplete = err == nil && rep.Failed == 0
		})
		_ = s.stats.Flush()
	}
	switch s.o.prefetch {
	case "all":
		fmt.Fprintln(os.Stderr, "pelfs: prefetching all blocks into the local cache...")
		rep, err := mnt.Prefetch(ctx, 16)
		if rep != nil {
			record(rep, err)
		}
		if err != nil {
			return fmt.Errorf("prefetch: %w", err)
		}
		if rep.Failed > 0 {
			return fmt.Errorf("prefetch incomplete: %d of %d slices failed (first error: %v)", rep.Failed, rep.Slices, rep.FirstErr)
		}
		fmt.Fprintf(os.Stderr, "pelfs: prefetched %d slices\n", rep.Slices)
	case "background":
		go func() {
			rep, err := mnt.Prefetch(ctx, 8)
			if rep != nil {
				record(rep, err)
				if err != nil || rep.Failed > 0 {
					fmt.Fprintf(os.Stderr, "pelfs: background prefetch incomplete: %d of %d slices failed\n", rep.Failed, rep.Slices)
				}
			}
		}()
	}
	return nil
}

// fuseUsable reports whether this host can plausibly mount FUSE.
func fuseUsable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat("/Library/Filesystems/macfuse.fs")
		return err == nil
	case "linux":
		_, err := os.Stat("/dev/fuse")
		return err == nil
	default:
		return false
	}
}

// resolveTokenPath finds a token file on the host to hand to a container.
func resolveTokenPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("BEARER_TOKEN_FILE"); p != "" {
		return p
	}
	btName := fmt.Sprintf("bt_u%d", os.Getuid())
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, btName)); err == nil {
			return filepath.Join(dir, btName)
		}
	}
	if _, err := os.Stat("/tmp/" + btName); err == nil {
		return "/tmp/" + btName
	}
	return ""
}

func exitErr(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	return 1
}
