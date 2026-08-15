package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/mountfs"
	"github.com/bbockelm/pelfs/internal/stats"
)

const daemonEnv = "PELFS_MOUNT_DAEMON"

// mountInfo is the state file a background mount maintains at
// <stateRoot>/vol-<id>/mount.json.
type mountInfo struct {
	PID          int       `json:"pid"`
	Prefix       string    `json:"prefix"`
	MountPoint   string    `json:"mountpoint"`
	Session      string    `json:"session,omitempty"`
	ReadOnly     bool      `json:"read_only,omitempty"`
	Started      time.Time `json:"started"`
	LastSnapshot time.Time `json:"last_snapshot,omitempty"`
	LastSnapKey  string    `json:"last_snapshot_key,omitempty"`
	// LeaseConflict is set when another client overwrote our mount lease:
	// a second writer is (or was) active on the same prefix.
	LeaseConflict bool `json:"lease_conflict,omitempty"`
}

func stateRoot() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "pelfs")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "pelfs-state")
	}
	return filepath.Join(home, ".local", "state", "pelfs")
}

func volDir(prefix string) string {
	sum := sha256.Sum256([]byte(prefix))
	return filepath.Join(stateRoot(), "vol-"+hex.EncodeToString(sum[:6]))
}

// cmdMount mounts in the background: the parent re-execs itself as a
// detached daemon child, waits for the mount to become visible, and returns.
func cmdMount(args []string) int {
	o, pos, err := parseArgs("mount", args, 1, 2, nil)
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]
	backend, err := resolveBackend(o)
	if err != nil {
		return exitErr(err)
	}
	if backend == "docker" {
		return exitErr(errors.New("pelfs mount requires a native backend (fuse or nfs); the Docker fallback only applies to `pelfs shell`"))
	}
	o.mountBackend = backend

	dir := volDir(prefix)
	if o.stateDir == "" {
		o.stateDir = dir // background mounts default to persistent state
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return exitErr(err)
	}
	infoPath := filepath.Join(dir, "mount.json")

	if os.Getenv(daemonEnv) == "1" {
		return runMountDaemon(o, prefix, pos, infoPath)
	}

	if info, err := readMountInfo(infoPath); err == nil && pidAlive(info.PID) {
		return exitErr(fmt.Errorf("%s is already mounted on %s (pid %d); use `pelfs umount` first", prefix, info.MountPoint, info.PID))
	}

	exe, err := os.Executable()
	if err != nil {
		return exitErr(err)
	}
	logPath := filepath.Join(dir, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return exitErr(err)
	}
	defer logFile.Close()

	child := exec.Command(exe, os.Args[1:]...)
	child.Env = append(os.Environ(), daemonEnv+"=1")
	child.Stdin = nil
	child.Stdout = logFile
	child.Stderr = logFile
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		return exitErr(fmt.Errorf("spawn daemon: %w", err))
	}
	pid := child.Process.Pid
	_ = child.Process.Release()

	// Wait for the daemon to publish its mount info (or die).
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := readMountInfo(infoPath); err == nil && info.PID == pid {
			fmt.Printf("pelfs: mounted %s on %s (pid %d, log %s)\n", prefix, info.MountPoint, pid, logPath)
			return 0
		}
		if !pidAlive(pid) {
			return exitErr(fmt.Errorf("mount daemon exited during startup; see %s", logPath))
		}
		time.Sleep(200 * time.Millisecond)
	}
	return exitErr(fmt.Errorf("timed out waiting for the mount daemon; see %s", logPath))
}

// runMountDaemon is the detached child: mount, publish state, snapshot
// until signaled, then unmount and finalize.
func runMountDaemon(o *cmdOpts, prefix string, pos []string, infoPath string) int {
	ctx := context.Background()
	s, err := newSession(ctx, o, prefix, !o.readOnly)
	if err != nil {
		return exitErr(err)
	}
	if len(pos) > 1 {
		s.mountPoint = pos[1]
		if err := os.MkdirAll(s.mountPoint, 0700); err != nil {
			return exitErr(err)
		}
	}

	mnt, err := mountfs.Mount(mountOptions(s))
	if err != nil {
		_ = s.stats.Finalize(1, false)
		s.cleanupTemp()
		return exitErr(fmt.Errorf("mount: %w", err))
	}

	// Strict prefetch refuses to publish the mount when incomplete.
	if err := s.runPrefetch(ctx, mnt); err != nil {
		_ = mnt.Close()
		_ = s.stats.Finalize(1, false)
		s.cleanupTemp()
		return exitErr(err)
	}

	statsCtx, stopStats := context.WithCancel(ctx)
	go s.stats.RunPeriodic(statsCtx, 30*time.Second)

	info := &mountInfo{
		PID:        os.Getpid(),
		Prefix:     prefix,
		MountPoint: s.mountPoint,
		ReadOnly:   o.readOnly,
		Started:    time.Now(),
	}
	writeInfo := func() {
		data, _ := json.MarshalIndent(info, "", "  ")
		_ = os.WriteFile(infoPath, data, 0600)
	}

	snapCtx, stopSnaps := context.WithCancel(ctx)
	snapsDone := make(chan struct{})
	mgr := s.newSnapshotManager()
	if o.readOnly {
		mgr = nil
		close(snapsDone)
	} else {
		info.Session = mgr.Session
		prevOnSnapshot := mgr.OnSnapshot // keep the stats-counting hook
		mgr.OnSnapshot = func(key string, when time.Time) {
			if prevOnSnapshot != nil {
				prevOnSnapshot(key, when)
			}
			info.LastSnapshot = when
			info.LastSnapKey = key
			writeInfo()
		}
		go func() {
			defer close(snapsDone)
			if o.snapshotInterval > 0 {
				mgr.Run(snapCtx, o.snapshotInterval)
			}
		}()
	}
	writeInfo()

	// Surface lease conflicts in mount.json even when snapshots are off.
	leaseWatch := time.NewTicker(30 * time.Second)
	defer leaseWatch.Stop()
	go func() {
		for range leaseWatch.C {
			if s.lease != nil && s.lease.Conflicted() && !info.LeaseConflict {
				info.LeaseConflict = true
				writeInfo()
			}
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	sig := <-sigs
	fmt.Fprintf(os.Stderr, "pelfs: received %s, unmounting %s\n", sig, s.mountPoint)

	stopSnaps()
	<-snapsDone
	code := 0
	closeErr := mnt.Close()
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", closeErr)
		code = 1
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
	if mgr != nil {
		if err := mgr.Snapshot(ctx, true); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: final metadata snapshot failed: %v\n", err)
			finalOK = false
			code = 1
		} else if err := mgr.PruneSessions(ctx, o.keepSessions); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: prune old snapshots: %v\n", err)
		}
		s.stats.Update(func(sum *stats.Summary) { sum.FinalSnapshotOK = &finalOK })
	}
	stopStats()
	if err := s.stats.Finalize(code, closeErr == nil && finalOK); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: write stats file: %v\n", err)
	}
	_ = os.Remove(infoPath)
	return code
}

func cmdUmount(args []string) int {
	if len(args) != 1 {
		return exitErr(errors.New("usage: pelfs umount <prefix-or-mountpoint>"))
	}
	target := args[0]
	infos, err := listMounts()
	if err != nil {
		return exitErr(err)
	}
	for _, e := range infos {
		if e.info.Prefix != target && filepath.Clean(e.info.MountPoint) != filepath.Clean(target) {
			continue
		}
		if !pidAlive(e.info.PID) {
			fmt.Fprintf(os.Stderr, "pelfs: mount daemon (pid %d) is gone; removing stale record\n", e.info.PID)
			_ = os.Remove(e.path)
			return 0
		}
		if err := syscall.Kill(e.info.PID, syscall.SIGTERM); err != nil {
			return exitErr(fmt.Errorf("signal pid %d: %w", e.info.PID, err))
		}
		fmt.Fprintf(os.Stderr, "pelfs: waiting for %s to unmount and flush...\n", e.info.MountPoint)
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			if !pidAlive(e.info.PID) {
				fmt.Printf("pelfs: unmounted %s\n", e.info.MountPoint)
				return 0
			}
			time.Sleep(250 * time.Millisecond)
		}
		return exitErr(fmt.Errorf("mount daemon (pid %d) did not exit within 120s", e.info.PID))
	}
	return exitErr(fmt.Errorf("no background mount found for %q (try `pelfs status`)", target))
}

func cmdStatus(args []string) int {
	if len(args) != 0 {
		return exitErr(errors.New("usage: pelfs status"))
	}
	infos, err := listMounts()
	if err != nil {
		return exitErr(err)
	}
	if len(infos) == 0 {
		fmt.Println("no background mounts")
		return 0
	}
	for _, e := range infos {
		state := "alive"
		if !pidAlive(e.info.PID) {
			state = "DEAD (stale record)"
		}
		mode := "rw"
		if e.info.ReadOnly {
			mode = "ro"
		}
		fmt.Printf("%s\n  mountpoint: %s (%s)\n  pid: %d (%s), up since %s\n",
			e.info.Prefix, e.info.MountPoint, mode, e.info.PID, state,
			e.info.Started.Format(time.RFC3339))
		if !e.info.LastSnapshot.IsZero() {
			fmt.Printf("  last snapshot: %s (%s)\n",
				e.info.LastSnapshot.Format(time.RFC3339), e.info.LastSnapKey)
		}
		if e.info.LeaseConflict {
			fmt.Printf("  LEASE CONFLICT: another client took over this prefix; concurrent writers corrupt each other\n")
		}
	}
	return 0
}

type mountEntry struct {
	path string
	info mountInfo
}

func listMounts() ([]mountEntry, error) {
	matches, err := filepath.Glob(filepath.Join(stateRoot(), "vol-*", "mount.json"))
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	for _, p := range matches {
		info, err := readMountInfo(p)
		if err != nil {
			continue
		}
		out = append(out, mountEntry{path: p, info: *info})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.Prefix < out[j].info.Prefix })
	return out, nil
}

func readMountInfo(path string) (*mountInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info mountInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
