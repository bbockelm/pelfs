package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/ui"
)

func cmdShell(args []string) int {
	var branch, signingKey string
	o, pos, command, err := parseArgsWithCommand("shell", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch to mount")
		fs.StringVar(&signingKey, "signing-key", "", signingKeyUsage)
	})
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]

	backend, err := resolveBackend(o)
	if err != nil {
		return exitErr(err)
	}

	kind, err := classifyVolume(o, prefix, branch)
	if err != nil {
		return exitErr(fmt.Errorf("classify %s: %w", prefix, err))
	}
	switch kind {
	case volumeLegacy:
		return exitErr(legacyVolumeError(prefix))
	case volumeEmpty:
		// The default grace window, deliberately: this path creates a volume
		// as a side effect of being asked to mount one, and a `--grace` here
		// would be a flag that silently does nothing on every prefix that
		// already holds a volume. Choosing the window is `pelfs init`'s job,
		// which is the command whose whole purpose is creation.
		if err := initVolumeAt(o, prefix, branch, signingKey, 0); err != nil {
			return exitErr(fmt.Errorf("create volume: %w", err))
		}
	}

	mountpoint, err := os.MkdirTemp("", "pelfs-mnt-*")
	if err != nil {
		return exitErr(err)
	}
	defer os.RemoveAll(mountpoint) //nolint:errcheck
	return runMountGen(o, prefix, mountpoint, command, genArgs{
		branch:         branch,
		rw:             !o.readOnly,
		subshell:       true,
		backend:        backend,
		signingKeyPath: signingKey,
	})
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
//
// takeDown is how `--on-mount-error=hold` reaches the payload: a reason
// arriving on it means the mount has handed this process an I/O error it
// could not explain, and the payload is to be stopped rather than left
// to produce plausible garbage. Nil in every other mode, and nil is the
// ordinary case — see mountErrorPolicy for why the aggressive behaviour
// is opt-in.
func runInMount(o *cmdOpts, prefix, mountPoint string, command []string, takeDown <-chan string) int {
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
		ui.Info("starting {shell} in {mountpoint} (exit the shell to unmount)",
			"shell", shellPath, "mountpoint", mountPoint)
	} else {
		ui.Info("running {command} in {mountpoint}",
			"command", strings.Join(argv, " "), "mountpoint", mountPoint)
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
	// everything it spawns would inherit an un-interruptible SIGINT, which
	// is what lets a `sleep 5m` inside `pelfs shell` survive Ctrl+C. A
	// notified signal leaves a handler installed here, and execve resets
	// handlers to SIG_DFL in the child.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		ui.Error("run {command}: {error}", "command", argv[0], "error", err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return 127 // shell convention: command not found
		}
		return 1
	}
	done := make(chan struct{})
	// stopped is closed by the signal goroutine as it returns, and this
	// function JOINS on it. Without that join the goroutine can still be
	// inside a Signal call after Wait has reaped the child -- which is
	// how a stale pid gets signalled once the operating system has handed
	// it to somebody else.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// The grace timer for a take-down lives in this select rather
		// than in a time.AfterFunc callback, so that EVERY path that can
		// signal the child is this one goroutine: once it has returned,
		// nothing can signal a reaped pid at all.
		var grace *time.Timer
		var killAt <-chan time.Time
		defer func() {
			if grace != nil {
				grace.Stop()
			}
		}()
		for {
			select {
			case <-done:
				return
			case reason := <-takeDown:
				ui.Error("stopping the payload: {reason} (--on-mount-error=hold)", "reason", reason)
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					ui.Warn("could not signal the payload: {error}", "error", err)
					continue
				}
				// A grace period rather than an immediate kill: a payload
				// that flushes on SIGTERM should get to, and the mount is
				// still serving everything that has not failed.
				grace = time.NewTimer(takeDownGrace)
				killAt = grace.C
			case <-killAt:
				killAt = nil
				ui.Warn("the payload did not stop within {grace}; killing it", "grace", takeDownGrace)
				_ = cmd.Process.Kill()
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
	<-stopped
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
	ui.Error("wait: {error}", "error", err)
	return 1
}

// volumeKind distinguishes the three things a prefix can be.
type volumeKind int

const (
	volumeEmpty  volumeKind = iota // nothing there yet
	volumeLegacy                   // block-and-snapshot metadata, no generation
	volumeOK                       // a published generation
)

// legacyMetaDir is the key-space directory a retired block-and-snapshot
// volume kept its metadata in. It is still probed so such a volume is
// recognized and reported instead of being mistaken for an empty prefix
// and overwritten with a new one.
//
// It is also where the write leases live, which is why the sweep below
// asks lease.IsLeaseObject rather than comparing against one name.
const legacyMetaDir = lease.Dir

// legacyVolumeError explains a prefix this pelfs cannot serve. Refusing is
// the whole point: the alternative — treating unrecognized metadata as an
// empty prefix — would initialize a new volume on top of somebody's data.
func legacyVolumeError(prefix string) error {
	// The newlines survive into the message: ui re-prefixes every
	// continuation line, so a three-line refusal stays attributable to
	// pelfs on a terminal and collapses to one record in a log.
	return fmt.Errorf("%s holds a retired block-and-snapshot volume, which this pelfs cannot read.\n"+
		"copy it out with a pelfs release that still had that engine, into a fresh prefix served by this one;\n"+
		"nothing here has been modified", prefix)
}

// classifyVolume asks the federation what kind of volume a prefix holds.
// A published ref means a volume this pelfs serves; otherwise retired
// metadata under meta/ means a volume it must refuse; neither means the
// prefix is empty and a new volume should be created.
func classifyVolume(o *cmdOpts, prefix, branch string) (volumeKind, error) {
	has, err := volumeHasGeneration(o, prefix, branch)
	if err != nil {
		return volumeLegacy, err // conservative: never overwrite what may exist
	}
	if has {
		return volumeOK, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken, DirectRead: true,
	})
	if err != nil {
		return volumeLegacy, err
	}
	entries, err := inner.ListDir(ctx, legacyMetaDir)
	if err != nil {
		if isNotFoundErr(err) {
			return volumeEmpty, nil
		}
		return volumeLegacy, err
	}
	// meta/ alone is not proof: the write leases live there
	// (meta/lease-<branch>.json, and meta/lease.json from v0.1.0), so a
	// writable mount of a current volume creates that directory too.
	// Anything else under it is a snapshot session directory.
	//
	// GETTING THIS WRONG INITIALIZES A NEW VOLUME OVER SOMEBODY'S DATA in
	// one direction and refuses a perfectly good prefix in the other, so
	// the rule lives in the lease package beside the naming it must track.
	// It used to compare against one filename, which the per-branch key
	// would have turned into "every writable mount looks retired".
	for _, e := range entries {
		if lease.IsLeaseObject(e.Name) {
			continue
		}
		return volumeLegacy, nil
	}
	return volumeEmpty, nil
}

// volumeHasGeneration reports whether the prefix already holds a
// published generation on the branch. It reads the ref through the
// direct-read transport (the superblock is the one mutable object) and
// treats a missing ref as "no".
func volumeHasGeneration(o *cmdOpts, prefix, branch string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken, DirectRead: true,
	})
	if err != nil {
		return false, err
	}
	if _, err := inner.StatKey(ctx, refs.RefDirKey+"/"+branch); err != nil {
		if isNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
