package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

const daemonEnv = "PELFS_MOUNT_DAEMON"

// mountInfo is the state file a background mount maintains at
// <stateRoot>/vol-<id>/mount.json.
type mountInfo struct {
	PID        int    `json:"pid"`
	Prefix     string `json:"prefix"`
	MountPoint string `json:"mountpoint"`
	Session    string `json:"session,omitempty"`
	// StateDir is where the session's control socket and local state
	// live. It is NOT always the directory holding this record: a mount
	// started with --state-dir puts state elsewhere, and `pelfs ctl`
	// must follow the session, not the record.
	StateDir string `json:"state_dir,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
	// Branch is what a writable mount will seal onto, and LeaseKey is the
	// lease object it holds while doing so (meta/lease-<branch>.json).
	// Both empty for a read-only mount; LeaseKey alone empty under
	// --no-lease.
	//
	// They are in the record, and printed by `pelfs status`, because the
	// exclusion is per-branch now: "there is a writable mount on this
	// prefix" no longer answers "will MY writable mount be refused", and
	// the branch does.
	Branch   string    `json:"branch,omitempty"`
	LeaseKey string    `json:"lease_key,omitempty"`
	Started  time.Time `json:"started"`
}

// daemonLogCap is the size at which daemon.log is rolled aside. It is the
// mount's only voice — checkpoint-failure warnings land nowhere else — so
// it must survive a long absence, and it lives in a state dir a user is
// entitled to assume does not grow without end.
//
// 10 MiB is where those two meet. A checkpoint failing every 5 minutes
// writes on the order of 40 KB a day, so a cap of 10 MiB holds most of a
// year of the worst case pelfs has, while two generations of it are a
// rounding error beside the 4 GiB pack cache in the same directory.
const daemonLogCap = 10 << 20

// openDaemonLog opens <dir>/daemon.log as the detached daemon's stdout and
// stderr, rolling the existing log aside first if it has reached the cap.
//
// One generation of history, bounded at 2x the cap, and the whole policy
// runs at open: a mount that is already running owns its descriptor, and
// renaming the file under it would neither free the bytes nor move the
// writer. That leaves a single session able to exceed the cap, which is
// the right trade for a single-user tool — a session that talkative is a
// bug to read, not a file to truncate — and every remount collects it.
func openDaemonLog(dir string) (*os.File, string, error) {
	path := filepath.Join(dir, "daemon.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() >= daemonLogCap {
		// The .1 this replaces belongs to the mount before last. Rotation
		// is best-effort: failing to rename is no reason to refuse to
		// mount, but the user should know their log is about to be longer
		// than they were promised.
		if err := os.Rename(path, path+".1"); err != nil {
			ui.Warn("could not rotate {log} ({error}); it will keep growing", "log", path, "error", err)
		} else {
			// Silent on a normal run: a user reading their own log to find
			// out why a mount failed does not need to be told about
			// housekeeping. Someone wondering where the older half of the
			// log went does.
			ui.Debug("rotated {log} at {size}; the previous log is now {rolled}",
				"log", path, "size", ui.ByteCount(fi.Size()), "rolled", path+".1")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, path, err
	}
	return f, path, nil
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
	a := genArgs{branch: "main"}
	o, pos, err := parseArgs("mount", args, 1, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&a.branch, "branch", "main", "branch to mount")
		fs.StringVar(&a.tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&a.pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&a.rw, "rw", false, "mount read-write through a local overlay; `pelfs umount` SEALS the changes into the next generation")
		fs.BoolVar(&a.noSeal, "no-seal", false, "with --rw, keep the overlay at unmount instead of publishing it (resume by remounting)")
		fs.BoolVar(&a.noMemtable, "no-memtable", false, "with --rw, keep written content in staging files and chunk it all at the seal, instead of packing and uploading during the session")
		fs.DurationVar(&a.poll, "poll", 0, "read-only: re-check the branch head this often and swap generations live (0 = pinned)")
		fs.StringVar(&a.signingKeyPath, "signing-key", "", signingKeyUsage)
	})
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]
	if a.backend, err = resolveBackend(o); err != nil {
		return exitErr(err)
	}

	dir := volDir(prefix)
	if o.stateDir == "" {
		o.stateDir = dir // background mounts default to persistent state
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return exitErr(err)
	}
	infoPath := filepath.Join(dir, "mount.json")

	if os.Getenv(daemonEnv) == "1" {
		mountpoint := filepath.Join(o.stateDir, "mnt")
		if len(pos) > 1 {
			mountpoint = pos[1]
		}
		// The daemon child IS the mount: runMountGen publishes the record
		// this command's parent is waiting on, serves until SIGTERM, and
		// seals on the way out.
		ui.Debug("mount daemon (pid {pid}) starting: {prefix} on {mountpoint}, state {statedir}, backend {backend}",
			"pid", os.Getpid(), "prefix", prefix, "mountpoint", mountpoint,
			"statedir", o.stateDir, "backend", a.backend)
		return runMountGen(o, prefix, mountpoint, nil, a)
	}

	if info, err := readMountInfo(infoPath); err == nil && pidAlive(info.PID) {
		return exitErr(fmt.Errorf("%s is already mounted on %s (pid %d); use `pelfs umount` first", prefix, info.MountPoint, info.PID))
	}

	exe, err := os.Executable()
	if err != nil {
		return exitErr(err)
	}
	logFile, logPath, err := openDaemonLog(dir)
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
	// The two facts a startup timeout is diagnosed from: which process to
	// look at, and which file it must write before this command believes
	// it. Both are gone by the time the timeout is reported.
	ui.Debug("spawned mount daemon (pid {pid}); waiting for {record}", "pid", pid, "record", infoPath)

	// Wait for the daemon to publish its mount info (or die).
	start := time.Now()
	deadline := start.Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := readMountInfo(infoPath); err == nil && info.PID == pid {
			ui.Debug("mount daemon published its record after {duration}", "duration", time.Since(start))
			ui.Info("mounted {prefix} on {mountpoint} (pid {pid}, log {log})",
				"prefix", prefix, "mountpoint", info.MountPoint, "pid", pid, "log", logPath)
			return 0
		}
		if !pidAlive(pid) {
			return exitErr(fmt.Errorf("mount daemon exited during startup; see %s", logPath))
		}
		time.Sleep(200 * time.Millisecond)
	}
	return exitErr(fmt.Errorf("timed out waiting for the mount daemon; see %s", logPath))
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
			ui.Warn("mount daemon (pid {pid}) is gone; removing stale record", "pid", e.info.PID)
			_ = os.Remove(e.path)
			return 0
		}
		if err := syscall.Kill(e.info.PID, syscall.SIGTERM); err != nil {
			return exitErr(fmt.Errorf("signal pid %d: %w", e.info.PID, err))
		}
		ui.Info("waiting for {mountpoint} to unmount and flush...", "mountpoint", e.info.MountPoint)
		// A umount that hangs is a seal that is still uploading, and the
		// log to read is the daemon's own, not this command's.
		ui.Debug("sent SIGTERM to pid {pid}; its own log is under {statedir}",
			"pid", e.info.PID, "statedir", e.info.StateDir)
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			if !pidAlive(e.info.PID) {
				ui.Info("unmounted {mountpoint}", "mountpoint", e.info.MountPoint)
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
		if e.info.Branch != "" {
			mode += " on " + e.info.Branch
		}
		fmt.Printf("%s\n  mountpoint: %s (%s)\n  pid: %d (%s), up since %s\n",
			e.info.Prefix, e.info.MountPoint, mode, e.info.PID, state,
			e.info.Started.Format(time.RFC3339))
		// Which OBJECT, not just "yes": a reader deciding whether their
		// own writable mount will be refused needs the key, since two
		// writable mounts of one volume on different branches are now
		// ordinary rather than a conflict. A writable mount with no line
		// here took --no-lease and is detecting nothing.
		if e.info.LeaseKey != "" {
			fmt.Printf("  lease: %s\n", e.info.LeaseKey)
		} else if !e.info.ReadOnly {
			fmt.Printf("  lease: none (--no-lease)\n")
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
