package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/dockerrun"
	"github.com/bbockelm/pelfs/internal/mountfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/snapshot"
	"github.com/bbockelm/pelfs/internal/stats"
)

func cmdShell(args []string) int {
	o, pos, err := parseArgs("shell", args, 1, 1, nil)
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]

	backend, err := resolveBackend(o)
	if err != nil {
		return exitErr(err)
	}
	if backend == "docker" {
		return runInDocker(o, prefix)
	}
	o.mountBackend = backend
	code, err := runShellNative(o, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	}
	return code
}

func runShellNative(o *cmdOpts, prefix string) (int, error) {
	ctx := context.Background()
	s, err := newSession(ctx, o, prefix, !o.readOnly)
	if err != nil {
		return 1, err
	}

	fmt.Fprintf(os.Stderr, "pelfs: mounting %s on %s\n", prefix, s.mountPoint)
	mnt, err := mountfs.Mount(mountOptions(s))
	if err != nil {
		_ = s.stats.Finalize(1, false)
		s.cleanupTemp()
		return 1, fmt.Errorf("mount: %w", err)
	}

	// Strict prefetch runs before the subshell: refuse to start when any
	// block could not be downloaded.
	if err := s.runPrefetch(ctx, mnt); err != nil {
		_ = mnt.Close()
		_ = s.stats.Finalize(1, false)
		s.cleanupTemp()
		return 1, err
	}

	statsCtx, stopStats := context.WithCancel(ctx)
	go s.stats.RunPeriodic(statsCtx, 30*time.Second)

	if ctl := s.startControl(time.Now(), o.readOnly, s.mountPoint); ctl != nil {
		defer ctl.Close() //nolint:errcheck
	}

	var mgr *snapshot.Manager
	snapCtx, stopSnaps := context.WithCancel(ctx)
	snapsDone := make(chan struct{})
	// Accumulate sessions never take v1 snapshots: a snapshot would
	// reference staged blocks that exist nowhere in the federation. The
	// v2 publish at exit is the durability step.
	if !o.readOnly && !o.accumulate {
		mgr = s.newSnapshotManager()
		go func() {
			defer close(snapsDone)
			if o.snapshotInterval > 0 {
				mgr.Run(snapCtx, o.snapshotInterval)
			}
		}()
	} else {
		close(snapsDone)
	}

	code := launchSubshell(o, prefix, s.mountPoint)

	stopSnaps()
	<-snapsDone
	fmt.Fprintln(os.Stderr, "pelfs: unmounting and flushing data to the federation...")
	// Close unmounts, flushes delayed writes, and (with --writeback) waits
	// for staged blocks to finish uploading: the "final upload at exit".
	closeErr := mnt.Close()
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", closeErr)
		if code == 0 {
			code = 1
		}
	}
	if o.writeback {
		drained := closeErr == nil
		s.stats.Update(func(sum *stats.Summary) {
			sum.StagingDrained = &drained
			if !drained {
				sum.StagingBlocksLeft = mnt.StagingBlocks()
			}
		})
	}
	finalOK := true
	if o.accumulate {
		fmt.Fprintln(os.Stderr, "pelfs: accumulate mode: publishing the session as a v2 generation...")
		if res, err := publishCore(ctx, s, "main", ""); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: MANDATORY final publish FAILED — session output is only in %s: %v\n", s.stateDir, err)
			finalOK = false
			if code == 0 {
				code = 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "pelfs: published generation %d (%d chunks, %d catalogs)\n",
				res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs)
		}
		s.stats.Update(func(sum *stats.Summary) { sum.FinalSnapshotOK = &finalOK })
	}
	if mgr != nil {
		if err := mgr.Snapshot(ctx, true); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: final metadata snapshot failed: %v\n", err)
			finalOK = false
			if code == 0 {
				code = 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "pelfs: final metadata snapshot uploaded (session %s)\n", mgr.Session)
			if err := mgr.PruneSessions(ctx, o.keepSessions); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: prune old snapshots: %v\n", err)
			}
		}
		s.stats.Update(func(sum *stats.Summary) { sum.FinalSnapshotOK = &finalOK })
	}
	stopStats()
	if err := s.stats.Finalize(code, closeErr == nil && finalOK); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: write stats file: %v\n", err)
	}
	s.cleanupTemp()
	return code, nil
}

func mountOptions(s *session) mountfs.Options {
	return mountfs.Options{
		VolumeName:     s.o.volume,
		MetaPath:       s.metaPath,
		MountPoint:     s.mountPoint,
		CacheDir:       s.cacheDir,
		PrefixURL:      s.prefix,
		Blob:           s.data,
		BlockSizeKiB:   s.o.blockSizeKiB,
		CacheSizeMiB:   s.o.cacheSizeMiB,
		Writeback:      s.o.writeback,
		Accumulate:     s.o.accumulate,
		IORetries:      s.o.ioRetries,
		ReadOnly:       s.o.readOnly,
		Debug:          s.o.debug,
		Compression:    s.o.compress,
		EncryptKeyPEM:  s.encryptPEM,
		FlushTimeout:   s.o.flushTimeout,
		FlushPacks:     s.packs.Flush,
		CacheFreeRatio: s.o.cacheFreeRatio,
		Backend:        s.o.mountBackend,
	}
}

func runInDocker(o *cmdOpts, prefix string) int {
	// Run the access preflight on the HOST before launching the container:
	// any interactive token acquisition (device flow, wallet password)
	// happens where the user's browser and existing credential store live,
	// and the resulting credentials are shared into the container via the
	// ~/.pelican bind mount. This also surfaces scope problems immediately
	// instead of from inside the container. Direct http(s) test prefixes
	// are skipped: they may only resolve inside the container (e.g.
	// host.docker.internal).
	if strings.HasPrefix(prefix, "pelican://") || strings.HasPrefix(prefix, "osdf://") {
		ctx := context.Background()
		store, err := pelicanobj.New(ctx, pelicanobj.Config{
			PrefixURL:    prefix,
			TokenPath:    o.token,
			AcquireToken: !o.noAcquireToken,
			Insecure:     o.insecure,
		})
		if err != nil {
			return exitErr(err)
		}
		if err := pelicanobj.Preflight(ctx, store, prefix, o.readOnly); err != nil {
			return exitErr(err)
		}
	}

	extra := []string{
		"--snapshot-interval", o.snapshotInterval.String(),
		"--keep-sessions", fmt.Sprint(o.keepSessions),
		"--cache-size", fmt.Sprint(o.cacheSizeMiB),
		"--block-size", fmt.Sprint(o.blockSizeKiB),
		"--volume", o.volume,
		"--io-retries", fmt.Sprint(o.ioRetries),
		"--compress", o.compress,
		"--prefetch", o.prefetch,
		"--flush-timeout", o.flushTimeout.String(),
		"--cache-free-ratio", fmt.Sprint(o.cacheFreeRatio),
		"--pack-size", fmt.Sprint(o.packSizeMiB),
		"--no-docker", // never recurse
	}
	if o.encryptKeyPath != "" {
		// dockerrun bind-mounts the key at this fixed path.
		extra = append(extra, "--encrypt-key", "/run/pelfs/encrypt-key")
	}
	// The stats file must survive the container: resolve a host path
	// (default: ./pelfs-stats.json), bind-mount its directory, and point
	// the in-container pelfs at the mounted location.
	hostStats := o.statsFile
	if hostStats == "" {
		if cwd, err := os.Getwd(); err == nil {
			hostStats = filepath.Join(cwd, "pelfs-stats.json")
		}
	}
	if hostStats != "" {
		extra = append(extra, "--stats-file", "/run/pelfs/stats/"+filepath.Base(hostStats))
	}
	for flagName, set := range map[string]bool{
		"--writeback":        o.writeback,
		"--ro":               o.readOnly,
		"--no-restore":       o.noRestore,
		"--no-lease":         o.noLease,
		"--no-pack":          o.noPack,
		"--steal-lease":      o.stealLease,
		"--no-acquire-token": o.noAcquireToken,
		"--insecure":         o.insecure,
		"--debug":            o.debug,
	} {
		if set {
			extra = append(extra, flagName)
		}
	}
	code, err := dockerrun.Run(dockerrun.Options{
		PrefixURL:      prefix,
		TokenPath:      resolveTokenPath(o.token),
		EncryptKeyPath: o.encryptKeyPath,
		StatsPath:      hostStats,
		Image:          o.dockerImage,
		ExtraArgs:      extra,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	}
	return code
}

func launchSubshell(o *cmdOpts, prefix, mountPoint string) int {
	shellPath := o.shellPath
	if shellPath == "" {
		shellPath = os.Getenv("SHELL")
	}
	if shellPath == "" {
		shellPath = "/bin/sh"
	}

	fmt.Fprintf(os.Stderr, "pelfs: starting %s in %s (exit the shell to unmount)\n", shellPath, mountPoint)
	cmd := exec.Command(shellPath)
	cmd.Dir = mountPoint
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"PELFS_MOUNT="+mountPoint,
		"PELFS_PREFIX="+prefix,
	)

	// Ctrl-C belongs to the subshell (same foreground process group); make
	// sure it doesn't kill us mid-cleanup. SIGTERM/SIGHUP terminate the
	// shell so cleanup can run.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	signal.Ignore(syscall.SIGINT)
	defer signal.Reset(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: launch shell %s: %v\n", shellPath, err)
		return 1
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	close(sigs)
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "pelfs: shell: %v\n", err)
	return 1
}
