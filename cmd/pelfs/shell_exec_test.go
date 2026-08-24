//go:build !windows

package main

// The half of the payload-launcher tests that needs a Unix. Every one of
// them either runs /bin/sh, or puts a child in its own PROCESS GROUP and
// signals the group the way a tty driver does — which is the whole point
// of the interrupt tests and has no Windows spelling: there are no process
// groups to signal, SIGQUIT and SIGTERM are never delivered, and
// runInMount's shell fallback is /bin/sh (see the audit note in
// docs/TODO.md). The argument-parsing tests, which are pure functions,
// stay in shell_test.go and run everywhere.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunInMountCommand runs the real payload launcher over a plain
// directory standing in for a mountpoint: the mount itself is a kernel
// facility this test cannot have, but everything runInMount is responsible
// for — argv, working directory, environment, exit status — is real here.
func TestRunInMountCommand(t *testing.T) {
	dir := t.TempDir()
	o := &cmdOpts{}

	if code := runInMount(o, "pelican://fed/pfx", dir, []string{"/bin/sh", "-c", "exit 7"}, nil); code != 7 {
		t.Errorf("exit status = %d, want 7", code)
	}
	if code := runInMount(o, "pelican://fed/pfx", dir, []string{"/bin/sh", "-c", "true"}, nil); code != 0 {
		t.Errorf("exit status = %d, want 0", code)
	}
	if code := runInMount(o, "pelican://fed/pfx", dir, []string{"/nonexistent/pelfs-no-such-command"}, nil); code != 127 {
		t.Errorf("missing command status = %d, want 127", code)
	}

	// The command runs IN the mount, with the session environment.
	script := `pwd > where; printf '%s\n%s\n%s\n' "$PELFS_MOUNT" "$PELFS_PREFIX" "$PWD" > env`
	if code := runInMount(o, "pelican://fed/pfx", dir, []string{"/bin/sh", "-c", script}, nil); code != 0 {
		t.Fatalf("environment probe exited %d", code)
	}
	where, err := os.ReadFile(filepath.Join(dir, "where"))
	if err != nil {
		t.Fatalf("the command did not run with the mount as its cwd: %v", err)
	}
	// macOS hands out /var/... symlinked from /private/var; compare resolved.
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(string(where)))
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Errorf("cwd = %s, want %s", got, want)
	}
	env, err := os.ReadFile(filepath.Join(dir, "env"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(env)), "\n")
	if len(lines) != 3 || lines[0] != dir || lines[1] != "pelican://fed/pfx" || lines[2] != dir {
		t.Errorf("PELFS_MOUNT/PELFS_PREFIX/PWD = %q, want %s, pelican://fed/pfx, %s", lines, dir, dir)
	}
}

// TestRunInMountInterrupt gates keyboard-signal handling. It re-executes
// this test binary as a helper in its OWN process group, then signals that
// whole group the way a terminal signals its foreground group on Ctrl+C.
// The payload must die and pelfs must survive to run teardown.
func TestRunInMountInterrupt(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  syscall.Signal
		want int
	}{
		// Ctrl+C: the child is interrupted, pelfs keeps going. Ignoring
		// SIGINT here instead of notifying on it would leave the child with
		// an inherited SIG_IGN across execve, and `sleep` would run to
		// completion.
		{"sigint", syscall.SIGINT, 130},
		// Ctrl+\: same convention, different signal.
		{"sigquit", syscall.SIGQUIT, 131},
		// `pelfs umount` sends SIGTERM to pelfs itself; that must still end
		// the payload and reach teardown.
		{"sigterm", syscall.SIGTERM, 143},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, elapsed := runInterruptHelper(t, tc.sig)
			if !hasLine(out, "HELPER-TEARDOWN") {
				t.Fatalf("pelfs did not survive %v to run teardown; output:\n%s", tc.sig, out)
			}
			// HELPER-STATUS=0 with a full-length elapsed is the signature of
			// an uninterruptible payload: it inherited SIG_IGN and slept the
			// signal out.
			if want := fmt.Sprintf("HELPER-STATUS=%d", tc.want); !hasLine(out, want) {
				t.Errorf("want %s; output:\n%s", want, out)
			}
			if elapsed > 15*time.Second {
				t.Errorf("the payload took %s to die; %v did not reach it", elapsed, tc.sig)
			}
		})
	}
}

// hasLine reports whether the helper printed marker as a line of its own.
// A substring match would also hit pelfs's own echo of the payload's argv,
// which names every marker the payload can print.
func hasLine(out, marker string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimRight(line, "\r") == marker {
			return true
		}
	}
	return false
}

const helperEnv = "PELFS_TEST_RUN_IN_MOUNT"

// runInterruptHelper starts the helper below in a fresh process group, waits
// for its payload to be running, and signals the GROUP (not the process):
// that is what a tty driver does, and the distinction is the whole bug —
// pelfs and its child both receive the signal.
func runInterruptHelper(t *testing.T, sig syscall.Signal) (string, time.Duration) {
	t.Helper()
	helper := exec.Command(os.Args[0], "-test.run=TestRunInMountHelper", "-test.timeout=90s")
	helper.Env = append(os.Environ(), helperEnv+"=1")
	helper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pipe, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	helper.Stderr = helper.Stdout
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	ready := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		br := bufio.NewReader(pipe)
		for {
			line, err := br.ReadString('\n')
			out.WriteString(line)
			// Prefix, not substring: pelfs echoes the payload's argv, and
			// matching that would signal the group before the payload has
			// been started at all.
			if strings.HasPrefix(line, "HELPER-READY") {
				select {
				case <-ready:
				default:
					close(ready)
				}
			}
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(&out, "read: %v\n", err)
				}
				return
			}
		}
	}()
	defer func() {
		_ = helper.Wait()
		<-drained
	}()

	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		_ = helper.Process.Kill()
		t.Fatalf("helper never reported its payload as running; output:\n%s", out.String())
	}
	pgid, err := syscall.Getpgid(helper.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid == syscall.Getpgrp() {
		t.Fatal("the helper shares this process group; signalling it would kill the test run")
	}
	start := time.Now()
	if err := syscall.Kill(-pgid, sig); err != nil {
		t.Fatalf("kill group: %v", err)
	}
	<-drained
	return out.String(), time.Since(start)
}

// TestRunInMountHelper is not a test: it is the child half of
// TestRunInMountInterrupt, and skips unless re-executed by it.
func TestRunInMountHelper(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("child half of TestRunInMountInterrupt")
	}
	// The payload announces itself so the launcher signals a group that is
	// really running it. `exec` matters: it leaves exactly one process in
	// the group besides pelfs, so a signal can never kill the shell while
	// leaving an orphaned sleep behind. Cores are off because one of the
	// signals under test is SIGQUIT.
	code := runInMount(&cmdOpts{}, "pelican://fed/pfx", t.TempDir(),
		[]string{"/bin/sh", "-c", "ulimit -c 0; echo HELPER-READY; exec sleep 30"}, nil)
	// Reaching this point at all is the assertion: pelfs was not killed by
	// the signal that the terminal also delivered to it, so a real session
	// would go on to unmount and seal.
	fmt.Printf("HELPER-STATUS=%d\nHELPER-TEARDOWN\n", code)
}
