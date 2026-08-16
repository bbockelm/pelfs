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
	o, pos, command, err := parseArgsWithCommand("shell", args, 1, 1, nil)
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]

	backend, err := resolveBackend(o)
	if err != nil {
		return exitErr(err)
	}
	if backend == "docker" {
		// dockerrun appends the prefix after the forwarded flags, so there
		// is no position left in the container's argv where a `--` tail
		// could not be mistaken for the prefix.
		if len(command) > 0 {
			return exitErr(errors.New("the Docker fallback cannot run a `-- command`; start the container shell and run it there"))
		}
		return runInDocker(o, prefix)
	}
	o.mountBackend = backend
	code, err := runShellNative(o, prefix, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	}
	return code
}

// runShellNative mounts the prefix and runs the session's payload in it: an
// interactive subshell, or `command` when the caller gave a `-- ...` tail.
// Teardown — unmount, drain, final snapshot — runs whatever the payload's
// exit status was; only the status is carried out.
func runShellNative(o *cmdOpts, prefix string, command []string) (int, error) {
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

	code := runInMount(o, prefix, s.mountPoint, command)

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

// mountEnv is the environment the payload runs with: the caller's, plus the
// mount's location. PWD is rewritten because the child starts in the mount,
// and an inherited PWD naming the invoking directory is simply wrong there.
func mountEnv(prefix, mountPoint string) []string {
	env := os.Environ()
	kept := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "PWD=") || strings.HasPrefix(kv, "OLDPWD=") {
			continue
		}
		kept = append(kept, kv)
	}
	return append(kept,
		"PELFS_MOUNT="+mountPoint,
		"PELFS_PREFIX="+prefix,
		"PWD="+mountPoint,
	)
}

// runInMount runs the session's payload with the mount as its working
// directory and returns its exit status. With no command it is an
// interactive subshell (exit to unmount); with one — the trailing `-- ...`
// form — it is exactly that command, so scripts can branch on the status
// pelfs exits with.
func runInMount(o *cmdOpts, prefix, mountPoint string, command []string) int {
	argv := command
	if len(argv) == 0 {
		shellPath := o.shellPath
		if shellPath == "" {
			shellPath = os.Getenv("SHELL")
		}
		if shellPath == "" {
			shellPath = "/bin/sh"
		}
		argv = []string{shellPath}
		fmt.Fprintf(os.Stderr, "pelfs: starting %s in %s (exit the shell to unmount)\n", shellPath, mountPoint)
	} else {
		fmt.Fprintf(os.Stderr, "pelfs: running %s in %s\n", strings.Join(argv, " "), mountPoint)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = mountPoint
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = mountEnv(prefix, mountPoint)
	// Deliberately NO Setpgid: the child stays in pelfs's process group,
	// which is the terminal's foreground group, so the tty driver delivers
	// Ctrl+C/Ctrl+\/Ctrl+Z to it. A new group would receive none of them
	// until it was also made the foreground group with tcsetpgrp — a
	// job-control implementation (plus SIGTTOU handling and restoring the
	// old foreground group at exit) that buys nothing here, because an
	// interactive child sets up its own job control from the controlling
	// terminal it inherits.

	// For as long as the child runs it owns the terminal, so pelfs does not
	// act on the keyboard signals the tty driver sends to the whole
	// foreground group — the system(3) convention. Acting on SIGINT here
	// would start tearing the mount down under a shell the user is still
	// using. SIGTERM/SIGHUP are aimed at pelfs itself (`pelfs umount`, a
	// closed terminal) and are forwarded so the child ends and teardown runs.
	//
	// This MUST be signal.Notify and not signal.Ignore: signal.Ignore sets
	// the disposition to SIG_IGN, which execve PRESERVES, so the shell and
	// everything it spawns would inherit an un-interruptible SIGINT — the
	// reason `sleep 5m` inside `pelfs shell` used to survive Ctrl+C. A
	// notified signal leaves a handler installed here, and execve resets
	// handlers to SIG_DFL in the child.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: run %s: %v\n", argv[0], err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return 127 // shell convention: command not found
		}
		return 1
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case s := <-sigs:
				switch s {
				case syscall.SIGINT, syscall.SIGQUIT:
					// The terminal already delivered these to the child.
				default:
					_ = cmd.Process.Signal(s)
				}
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	return waitStatus(err)
}

// waitStatus turns a cmd.Wait error into the status pelfs exits with. A
// child killed by a signal reports 128+signum, the convention every shell
// uses (130 for an interrupted command) — exec.ExitError.ExitCode() would
// report -1, which os.Exit turns into a meaningless 255.
func waitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "pelfs: wait: %v\n", err)
	return 1
}
