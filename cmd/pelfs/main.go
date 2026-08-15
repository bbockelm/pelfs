// Command pelfs mounts a JuiceFS filesystem whose blocks and metadata
// snapshots live in a Pelican federation, then drops the user into a
// subshell with the filesystem mounted. On hosts that cannot mount FUSE
// (e.g. macOS without macFUSE) it re-launches itself inside a Docker
// container instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/dockerrun"
	"github.com/bbockelm/pelfs/internal/mountfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/snapshot"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "shell":
		os.Exit(runShell(os.Args[2:]))
	case "mount":
		fmt.Fprintln(os.Stderr, "pelfs mount (async, no subshell) is not implemented yet; use `pelfs shell`")
		os.Exit(2)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `pelfs — a locally mountable filesystem stored in a Pelican federation

Usage:
  pelfs shell [flags] pelican://<federation>/<prefix>

Mounts the filesystem on a temporary mountpoint and launches a subshell
there; exiting the shell unmounts, flushes data to the federation, and
uploads a final metadata snapshot.

Flags:
`)
	shellFlags(flag.NewFlagSet("shell", flag.ContinueOnError)).PrintDefaults()
}

type shellOpts struct {
	token            string
	stateDir         string
	keepState        bool
	snapshotInterval time.Duration
	cacheSizeMiB     int64
	blockSizeKiB     int
	writeback        bool
	volume           string
	noRestore        bool
	noAcquireToken   bool
	insecure         bool
	debug            bool
	forceDocker      bool
	noDocker         bool
	dockerImage      string
	shellPath        string
}

func shellFlags(fs *flag.FlagSet) *flag.FlagSet {
	// Definitions only; results are bound in parseShellFlags.
	fs.String("token", "", "path to a bearer-token file (default: WLCG bearer-token discovery)")
	fs.String("state-dir", "", "directory for local state (metadata db + block cache); default: a fresh temp dir")
	fs.Bool("keep-state", false, "keep the local state directory on exit")
	fs.Duration("snapshot-interval", 5*time.Minute, "how often to upload a metadata snapshot (0 disables periodic snapshots)")
	fs.Int64("cache-size", 10240, "local block cache size limit, in MiB")
	fs.Int("block-size", 4096, "object block size, in KiB (fixed at volume creation)")
	fs.Bool("writeback", false, "upload blocks asynchronously (faster writes, weaker durability)")
	fs.String("volume", "pelfs", "JuiceFS volume name")
	fs.Bool("no-restore", false, "do not restore the latest metadata snapshot from the federation")
	fs.Bool("no-acquire-token", false, "never run interactive token-acquisition flows; rely on discovered tokens only")
	fs.Bool("insecure", false, "skip TLS verification (test federations only)")
	fs.Bool("debug", false, "verbose logging")
	fs.Bool("docker", false, "force running inside a Docker container")
	fs.Bool("no-docker", false, "never fall back to Docker; fail if FUSE is unavailable")
	fs.String("docker-image", dockerrun.DefaultImage, "container image for the Docker fallback")
	fs.String("shell", "", "shell to launch (default: $SHELL, else /bin/sh)")
	return fs
}

func parseShellFlags(args []string) (*shellOpts, string, error) {
	o := &shellOpts{}
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.StringVar(&o.token, "token", "", "")
	fs.StringVar(&o.stateDir, "state-dir", "", "")
	fs.BoolVar(&o.keepState, "keep-state", false, "")
	fs.DurationVar(&o.snapshotInterval, "snapshot-interval", 5*time.Minute, "")
	fs.Int64Var(&o.cacheSizeMiB, "cache-size", 10240, "")
	fs.IntVar(&o.blockSizeKiB, "block-size", 4096, "")
	fs.BoolVar(&o.writeback, "writeback", false, "")
	fs.StringVar(&o.volume, "volume", "pelfs", "")
	fs.BoolVar(&o.noRestore, "no-restore", false, "")
	fs.BoolVar(&o.noAcquireToken, "no-acquire-token", false, "")
	fs.BoolVar(&o.insecure, "insecure", false, "")
	fs.BoolVar(&o.debug, "debug", false, "")
	fs.BoolVar(&o.forceDocker, "docker", false, "")
	fs.BoolVar(&o.noDocker, "no-docker", false, "")
	fs.StringVar(&o.dockerImage, "docker-image", dockerrun.DefaultImage, "")
	fs.StringVar(&o.shellPath, "shell", "", "")
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	if fs.NArg() != 1 {
		return nil, "", errors.New("exactly one prefix URL is required, e.g. pelican://osg-htc.org/my/scratch/space")
	}
	return o, fs.Arg(0), nil
}

func runShell(args []string) int {
	o, prefix, err := parseShellFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
		return 2
	}

	if o.forceDocker || (!o.noDocker && !fuseUsable()) {
		return runInDocker(o, prefix)
	}
	if !fuseUsable() {
		fmt.Fprintln(os.Stderr, "pelfs: FUSE is not available on this host (and --no-docker was given)")
		return 1
	}
	code, err := runShellNative(o, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	}
	return code
}

// fuseUsable reports whether this host can plausibly mount FUSE.
func fuseUsable() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := os.Stat("/Library/Filesystems/macfuse.fs")
		return err == nil
	case "linux":
		if _, err := os.Stat("/dev/fuse"); err == nil {
			return true
		}
		return false
	default:
		return false
	}
}

func runInDocker(o *shellOpts, prefix string) int {
	extra := []string{
		"--snapshot-interval", o.snapshotInterval.String(),
		"--cache-size", fmt.Sprint(o.cacheSizeMiB),
		"--block-size", fmt.Sprint(o.blockSizeKiB),
		"--volume", o.volume,
		"--no-docker", // never recurse
	}
	if o.writeback {
		extra = append(extra, "--writeback")
	}
	if o.noRestore {
		extra = append(extra, "--no-restore")
	}
	if o.noAcquireToken {
		extra = append(extra, "--no-acquire-token")
	}
	if o.insecure {
		extra = append(extra, "--insecure")
	}
	if o.debug {
		extra = append(extra, "--debug")
	}
	code, err := dockerrun.Run(dockerrun.Options{
		PrefixURL: prefix,
		TokenPath: resolveTokenPath(o.token),
		Image:     o.dockerImage,
		ExtraArgs: extra,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: %v\n", err)
	}
	return code
}

// resolveTokenPath finds a token file on the host to hand to the container.
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

func runShellNative(o *shellOpts, prefix string) (int, error) {
	ctx := context.Background()

	// Local state layout: <state>/meta.db, <state>/cache, <state>/mnt
	stateDir := o.stateDir
	tempState := false
	if stateDir == "" {
		var err error
		stateDir, err = os.MkdirTemp("", "pelfs-*")
		if err != nil {
			return 1, err
		}
		tempState = true
	} else if err := os.MkdirAll(stateDir, 0700); err != nil {
		return 1, err
	}
	metaPath := filepath.Join(stateDir, "meta.db")
	cacheDir := filepath.Join(stateDir, "cache")
	mountPoint := filepath.Join(stateDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		return 1, err
	}

	store, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		AcquireToken: !o.noAcquireToken,
		Insecure:     o.insecure,
	})
	if err != nil {
		return 1, err
	}

	// Restore the newest metadata snapshot unless we already have local
	// state or the user opted out.
	if !o.noRestore {
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			key, err := snapshot.Restore(ctx, store, metaPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: no metadata snapshot restored (%v); starting fresh\n", err)
			} else if key != "" {
				fmt.Fprintf(os.Stderr, "pelfs: restored metadata from %s\n", key)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "pelfs: mounting %s on %s\n", prefix, mountPoint)
	mnt, err := mountfs.Mount(mountfs.Options{
		VolumeName:   o.volume,
		MetaPath:     metaPath,
		MountPoint:   mountPoint,
		CacheDir:     cacheDir,
		PrefixURL:    prefix,
		Blob:         store,
		BlockSizeKiB: o.blockSizeKiB,
		CacheSizeMiB: o.cacheSizeMiB,
		Writeback:    o.writeback,
		Debug:        o.debug,
	})
	if err != nil {
		return 1, fmt.Errorf("mount: %w", err)
	}

	// Periodic metadata snapshots.
	mgr := &snapshot.Manager{MetaPath: metaPath, Store: store, Session: snapshot.NewSessionID()}
	snapCtx, stopSnaps := context.WithCancel(ctx)
	snapsDone := make(chan struct{})
	go func() {
		defer close(snapsDone)
		if o.snapshotInterval > 0 {
			mgr.Run(snapCtx, o.snapshotInterval)
		}
	}()

	code := launchSubshell(o, prefix, mountPoint)

	// Shutdown: stop periodic snapshots, unmount + flush, then upload the
	// final metadata snapshot (the database is quiescent after Close).
	stopSnaps()
	<-snapsDone
	fmt.Fprintln(os.Stderr, "pelfs: unmounting and flushing data to the federation...")
	if err := mnt.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	if err := mgr.Snapshot(ctx, true); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: final metadata snapshot failed: %v\n", err)
		if code == 0 {
			code = 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "pelfs: final metadata snapshot uploaded (session %s)\n", mgr.Session)
	}

	if tempState && !o.keepState {
		os.RemoveAll(stateDir)
	} else {
		fmt.Fprintf(os.Stderr, "pelfs: local state kept in %s\n", stateDir)
	}
	return code, nil
}

func launchSubshell(o *shellOpts, prefix, mountPoint string) int {
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
