package main

// The mount-time sweep of a state directory's scratch.
//
// A killed seal cannot clean up after itself, so its spool — the packs it
// was building, which for a real volume is gigabytes — sits in the state
// directory until somebody notices. Nothing noticed: the only sweeper a
// mount ran emptied `trash`, and the three scratch families live in the
// state directory's root.
//
// These tests run against the real defaults, including the real liveness
// check, because the wiring is the thing being tested. They work in
// t.TempDir() only: a test in this file must never be able to name a
// directory that holds anybody's data.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/scratch"
	"github.com/bbockelm/pelfs/internal/ui"
)

// deadPID is a pid that has run and been reaped, which is the state a
// killed mount's pid is in by the time the next mount looks at it.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run a child process to reap: %v", err)
	}
	pid := cmd.Process.Pid
	if scratch.PIDAlive(pid) {
		t.Skip("the reaped child's pid was recycled immediately; this run cannot pose the question")
	}
	return pid
}

// strand builds the scratch a killed run leaves: a directory named for its
// owner, holding bytes.
func strand(t *testing.T, parent, family string, pid, size int) string {
	t.Helper()
	dir := filepath.Join(parent, family+"-"+strconv.Itoa(pid)+"-9f3a2b")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p-0001.pack"), make([]byte, size), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A `kill -9` mid-seal leaves a state directory that a later mount cleans
// up. All three families, and the merge spool as well, since a merge runs
// a publish under a second parent.
func TestAMountReclaimsTheScratchAKilledSessionLeft(t *testing.T) {
	stateDir := t.TempDir()
	dead := deadPID(t)
	if err := os.MkdirAll(filepath.Join(stateDir, "merge"), 0700); err != nil {
		t.Fatal(err)
	}
	stranded := []string{
		strand(t, stateDir, scratch.Publish, dead, 1<<20),
		strand(t, stateDir, scratch.Snapshot, dead, 4096),
		strand(t, stateDir, scratch.Repack, dead, 8192),
		strand(t, filepath.Join(stateDir, "merge"), scratch.Publish, dead, 2048),
	}
	// The state directory's real contents, which the sweep must not touch.
	live := []string{"overlay", "content", "gencache", "refs", trashDirName}
	for _, name := range live {
		if err := os.MkdirAll(filepath.Join(stateDir, name, "inner"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stateDir, dedupIndexName), []byte("sidecar"), 0600); err != nil {
		t.Fatal(err)
	}

	sweepStateScratch(stateDir)

	for _, dir := range stranded {
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%s survived the mount sweep; a killed seal's spool is never reclaimed by anything else",
				dir)
		}
	}
	for _, name := range append(live, dedupIndexName, "merge") {
		if _, err := os.Stat(filepath.Join(stateDir, name)); err != nil {
			t.Errorf("the sweep took %s, which is not scratch: %v", name, err)
		}
	}
}

// THE OTHER DIRECTION, and the one that would be a disaster: a second
// mount of the same state directory is mid-seal right now. Its spool is
// named for a process that is running — this one — and the sweep leaves it
// alone. A stale lease could not have told these apart; only the process
// can.
func TestAMountLeavesALiveSessionsSpoolAlone(t *testing.T) {
	stateDir := t.TempDir()
	mine := strand(t, stateDir, scratch.Publish, os.Getpid(), 4096)
	dead := strand(t, stateDir, scratch.Publish, deadPID(t), 4096)

	sweepStateScratch(stateDir)

	if _, err := os.Stat(mine); err != nil {
		t.Fatalf("the sweep deleted the spool of a running process: %v", err)
	}
	if _, err := os.Stat(dead); err == nil {
		t.Fatal("the dead session's spool survived")
	}
}

// Reclaiming gigabytes silently is how a state directory becomes
// unexplainable. The sweep says what it took.
func TestTheMountSweepSaysWhatItReclaimed(t *testing.T) {
	stateDir := t.TempDir()
	strand(t, stateDir, scratch.Publish, deadPID(t), 3<<20)

	var buf bytes.Buffer
	restore := ui.SetOutput(&buf, ui.Plain)
	sweepStateScratch(stateDir)
	restore()

	said := buf.String()
	for _, want := range []string{"reclaimed", "3.0 MiB", scratch.Publish} {
		if !strings.Contains(said, want) {
			t.Fatalf("the sweep reported %q, which does not mention %q", strings.TrimSpace(said), want)
		}
	}
}

// A mount whose state directory holds no scratch says nothing at all. A
// line on every mount would be noise, and noise is what stops the line
// above from being read when it matters.
func TestTheMountSweepIsSilentWhenThereIsNothingToReclaim(t *testing.T) {
	stateDir := t.TempDir()
	var buf bytes.Buffer
	restore := ui.SetOutput(&buf, ui.Plain)
	sweepStateScratch(stateDir)
	restore()
	if s := strings.TrimSpace(buf.String()); s != "" {
		t.Fatalf("an empty state directory produced %q", s)
	}
}

// The seal path names its spool the way the sweep expects. If these two
// ever disagree the leak comes back silently, so the agreement is asserted
// rather than assumed — this is the same call the checkpoint makes.
func TestTheSnapshotScratchAMountMakesIsSweepable(t *testing.T) {
	stateDir := t.TempDir()
	dir, err := scratch.Make(stateDir, scratch.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	pid, owned := scratch.Owner(filepath.Base(dir))
	if !owned || pid != os.Getpid() {
		t.Fatalf("a checkpoint's snapshot scratch %q is owned by %d/%v, want this process",
			filepath.Base(dir), pid, owned)
	}
	// And an old release's unowned name still goes, once it is old enough
	// that nothing can still be using it.
	legacy := filepath.Join(stateDir, "repack")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(legacy, when, when); err != nil {
		t.Fatal(err)
	}
	sweepStateScratch(stateDir)
	if _, err := os.Stat(legacy); err == nil {
		t.Fatal("the fixed `repack` directory an older release left is still there")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the sweep took this process's own scratch: %v", err)
	}
}
