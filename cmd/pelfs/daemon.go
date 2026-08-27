package main

import (
	"context"
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
	"time"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/ui"
)

const daemonEnv = "PELFS_MOUNT_DAEMON"

// mountInfo is the state file a session maintains at
// <registry root>/vol-<id>/mount.json, where the registry root is the
// machine-wide default for a background `pelfs mount` and the session's own
// --state-dir for a foreground one. See registryRoot.
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

// defaultStateRoot is where pelfs keeps per-prefix state when nothing on
// the command line says otherwise: $XDG_STATE_HOME/pelfs, else
// ~/.local/state/pelfs.
//
// It is the DEFAULT and not "the state root": every path pelfs creates has
// to be reachable from the flags of the invocation that creates it, which
// is what cmdOpts.stateRoot is for. Calling this function from a code path
// that has a *cmdOpts in scope is the bug fixed in this file's history —
// see stateRoot below.
func defaultStateRoot() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "pelfs")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "pelfs-state")
	}
	return filepath.Join(home, ".local", "state", "pelfs")
}

// registryRoot is where a session publishes its mount record, and the two
// answers are the two verbs' contracts rather than a preference.
//
// A FOREGROUND session — `pelfs shell`, `pelfs mount-gen`, `pelfs browse` —
// records under its own root, so --state-dir covers it like everything
// else. Nobody has to find such a session by name: the person who started
// it is looking at it, and `pelfs ctl <state-dir> <verb>` reaches it.
//
// A BACKGROUND MOUNT is a detached daemon whose entire purpose is to be
// found later by prefix — `pelfs status`, `pelfs umount <prefix>`,
// `pelfs ctl <prefix> publish` — and that registry is machine-scoped by
// nature, like a pid file. Putting it under a --state-dir the reader was
// never told about would mean a live mount that cannot be stopped by name,
// which is a worse failure than a directory in the state root that the
// retraction now removes when it empties.
func registryRoot(o *cmdOpts, background bool) string {
	if background {
		return defaultStateRoot()
	}
	return o.stateRoot()
}

// stateRoot is the root of everything THIS invocation may create, and
// --state-dir wins.
//
// WHY THIS EXISTS. --state-dir used to cover the session's own state — the
// overlay, the caches, the control socket, the signing key — while the
// mount-record registry was derived from the default root independently of
// the flag (publishMountRecord called volDir, which called stateRoot).
// So a run pointed entirely at a temp directory still created
// <home>/.local/state/pelfs/vol-<id>/, wrote mount.json into it, and left
// the empty directory behind when the record was retracted at exit. That
// was measured, not theorised: scripts/webui-playwright.sh's run counter
// and the developer's state root went up together, one directory per run,
// and the harness had to export XDG_STATE_HOME to work around it.
//
// The consequence of fixing it, stated because it is a behaviour change: a
// FOREGROUND session started with --state-dir registers itself UNDER that
// directory, so `pelfs status` and `pelfs umount` need the same --state-dir
// (or the same XDG_STATE_HOME) to see it, and both take the flag for
// exactly this reason. `pelfs ctl <state-dir> <verb>` already reached such
// a session and still does. A background `pelfs mount` is the one
// exception, and registryRoot says why.
func (o *cmdOpts) stateRoot() string {
	if o.stateDir != "" {
		return o.stateDir
	}
	return defaultStateRoot()
}

// volDir is the per-prefix state directory in the DEFAULT root. Callers
// use it only for the "--state-dir was not given" branch, where the two
// are the same directory by construction.
func volDir(prefix string) string {
	return volDirIn(defaultStateRoot(), prefix)
}

// volDirIn is the per-prefix directory under an explicit root: the mount
// record lives at <root>/vol-<id>/mount.json, whatever the root is, so one
// glob finds every record any session in that root published.
func volDirIn(root, prefix string) string {
	sum := sha256.Sum256([]byte(prefix))
	return filepath.Join(root, "vol-"+hex.EncodeToString(sum[:6]))
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
		registerFinderFlags(fs, &a)
	})
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]
	if a.finder {
		finderBackend(o)
	}
	if a.backend, err = resolveBackend(o); err != nil {
		return exitErr(err)
	}
	// Checked in the PARENT, before anything is spawned. The daemon child's
	// only voice is daemon.log, so a --finder that cannot work here must
	// say so on the terminal that asked for it -- otherwise a user who
	// wanted a volume in the Finder gets a background process that exited
	// and no reason why.
	if a.finder {
		if err := checkFinder(a.backend); err != nil {
			return exitErr(err)
		}
	}

	// The registry directory for a BACKGROUND mount, which is the default
	// root even under --state-dir: see registryRoot for why this one verb
	// is machine-scoped. The daemon's startup log lives beside its record,
	// because a mount that failed to start has no state directory worth
	// looking in and `pelfs mount` prints this path.
	dir := volDirIn(registryRoot(o, true), prefix)
	if o.stateDir == "" {
		o.stateDir = dir // background mounts default to persistent state
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return exitErr(err)
	}
	infoPath := filepath.Join(dir, "mount.json")

	if os.Getenv(daemonEnv) == "1" {
		// A --finder mount with no mountpoint of its own is left EMPTY for
		// runMountGen to fill in: where a Finder volume lands is chosen
		// from the volume's name and what is available in /Volumes
		// (cmd/pelfs/finder.go), and <state-dir>/mnt -- a path whose last
		// component is the word "mnt" -- is precisely the name it must not
		// have.
		mountpoint := ""
		if len(pos) > 1 {
			mountpoint = pos[1]
		} else if !a.finder {
			mountpoint = filepath.Join(o.stateDir, "mnt")
		}
		// The daemon child IS the mount: runMountGen publishes the record
		// this command's parent is waiting on, serves until SIGTERM, and
		// seals on the way out. It is the ONE session that registers
		// machine-globally rather than under its own state root — the
		// parent is about to return to a shell that will look for it by
		// prefix.
		a.background = true
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
	child.SysProcAttr = daemonSysProcAttr()
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

// registryFlags parses the one flag a record READER needs: which root to
// look in. It is not registerFlags — `pelfs status` has no use for
// --token or --prefetch and offering them would be noise — but it is the
// same flag by the same name, because a session started with
// `--state-dir X` publishes its record under X (see cmdOpts.stateRoot) and
// the reader has to be able to say so.
func registryFlags(name string, args []string, maxPos int) (root string, pos []string, err error) {
	o := &cmdOpts{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&o.stateDir, "state-dir", "",
		"look for sessions registered under this directory (the --state-dir they were started with); default: $XDG_STATE_HOME/pelfs or ~/.local/state/pelfs")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	if fs.NArg() > maxPos {
		return "", nil, fmt.Errorf("expected at most %d positional arguments, got %d", maxPos, fs.NArg())
	}
	return o.stateRoot(), fs.Args(), nil
}

func cmdUmount(args []string) int {
	root, pos, err := registryFlags("umount", args, 1)
	if err != nil {
		return exitErr(err)
	}
	if len(pos) != 1 {
		return exitErr(errors.New("usage: pelfs umount [--state-dir dir] <prefix-or-mountpoint>"))
	}
	target := pos[0]
	infos, err := listMounts(root)
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
		if err := signalStop(e.info.PID); err != nil {
			return exitErr(err)
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
	root, pos, err := registryFlags("status", args, 0)
	if err != nil {
		return exitErr(err)
	}
	if len(pos) != 0 {
		return exitErr(errors.New("usage: pelfs status [--state-dir dir]"))
	}
	infos, err := listMounts(root)
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
			fmt.Printf("  lease: %s%s\n", e.info.LeaseKey, leaseStateSuffix(e))
		} else if !e.info.ReadOnly {
			fmt.Printf("  lease: none (--no-lease); seals are not fenced\n")
		}
	}
	return 0
}

// leaseStateSuffix asks a live mount what its lease is actually DOING, and
// says so on the same line as the key.
//
// The record on disk can only say which object was taken at mount time. The
// question an operator has when they run this is a different one — "is this
// mount still able to publish?" — and it has four answers, not two: held,
// stale (past its TTL, so the next publish will stop and recheck),
// interrupted (the object went missing under it), and lost (another client
// has the branch; nothing further will be published and the work is sitting
// in an overlay). The last two are emergencies that used to be visible only
// as a boolean buried in `pelfs ctl status`.
//
// Best effort by construction: a mount that does not answer in a moment gets
// no suffix rather than an error, because this command's job is to list
// mounts and it must keep working on one that is wedged.
func leaseStateSuffix(e mountEntry) string {
	if !pidAlive(e.info.PID) || e.info.StateDir == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, err := control.NewClient(e.info.StateDir).Do(ctx, "GET", "/v1/status")
	if err != nil {
		return ""
	}
	var st struct {
		State   string  `json:"lease_state"`
		Age     float64 `json:"lease_age_seconds"`
		TakenBy string  `json:"lease_taken_by"`
	}
	if json.Unmarshal(body, &st) != nil || st.State == "" {
		return ""
	}
	switch st.State {
	case "held":
		return " (held)"
	case "stale":
		return fmt.Sprintf(" (STALE: not renewed for %s; the next publish will recheck it first)",
			time.Duration(st.Age*float64(time.Second)).Round(time.Second))
	case "interrupted":
		return " (INTERRUPTED: the lease object vanished under this mount; the next publish will " +
			"check the branch head before publishing anything)"
	case "lost":
		who := st.TakenBy
		if who == "" {
			who = "another client"
		}
		return fmt.Sprintf(" (LOST to %s: this mount will publish NOTHING further; its work is in "+
			"its overlay, and remounting takes a fresh lease)", who)
	}
	return ""
}

type mountEntry struct {
	path string
	info mountInfo
}

// listMounts reads every mount record in one root. The root is a parameter
// rather than a call to defaultStateRoot because a session started with
// --state-dir registers itself there (see cmdOpts.stateRoot), so the reader
// has to be told where to look.
func listMounts(root string) ([]mountEntry, error) {
	matches, err := filepath.Glob(filepath.Join(root, "vol-*", "mount.json"))
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
