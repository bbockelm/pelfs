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
	StateDir string    `json:"state_dir,omitempty"`
	ReadOnly bool      `json:"read_only,omitempty"`
	Started  time.Time `json:"started"`
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
		fs.DurationVar(&a.poll, "poll", 0, "read-only: re-check the branch head this often and swap generations live (0 = pinned)")
		fs.StringVar(&a.signingKeyPath, "signing-key", "", "hex Ed25519 volume signing key file to seal with (default: <state-dir>/v2-signing.key)")
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
		return runMountGen(o, prefix, mountpoint, nil, a)
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
		fmt.Printf("%s\n  mountpoint: %s (%s)\n  pid: %d (%s), up since %s\n",
			e.info.Prefix, e.info.MountPoint, mode, e.info.PID, state,
			e.info.Started.Format(time.RFC3339))
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
