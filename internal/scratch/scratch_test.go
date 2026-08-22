package scratch_test

// What a sweep of a state directory may take, and — the half that matters
// more — what it may not.
//
// Every test here works in t.TempDir(). Nothing in this package may ever
// be pointed at a real volume's state directory by a test: the code under
// test deletes directories, and the only safe way to develop it is for the
// suite to be incapable of naming a directory somebody's data is in.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/scratch"
)

// aliveOnly is a liveness oracle for a fixed set of pids, so that a test
// can describe "the owner is still running" without starting a process
// and hoping the scheduler cooperates.
func aliveOnly(pids ...int) func(int) bool {
	set := make(map[int]bool, len(pids))
	for _, p := range pids {
		set[p] = true
	}
	return func(p int) bool { return set[p] }
}

// mkScratch creates a scratch directory owned by pid, holding one file of
// n bytes, and backdates the whole thing by idle.
func mkScratch(t *testing.T, root, family string, pid int, n int, idle time.Duration) string {
	t.Helper()
	name := family + "-" + strconv.Itoa(pid) + "-abc123"
	dir := filepath.Join(root, name)
	mkDirWithFile(t, dir, n, idle)
	return name
}

func mkDirWithFile(t *testing.T, dir string, n int, idle time.Duration) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		if err := os.WriteFile(filepath.Join(dir, "pack.tmp"), make([]byte, n), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if idle > 0 {
		when := time.Now().Add(-idle)
		if err := os.Chtimes(dir, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}

// The name is the ownership record, and it is written by the same syscall
// that creates the directory — so there is no instant at which a scratch
// directory exists without saying who made it. A stamp file could not
// promise that: a crash between the mkdir and the write would leave a
// directory nobody could attribute.
func TestAScratchDirectoryNamesItsOwnerFromTheMomentItExists(t *testing.T) {
	root := t.TempDir()
	dir, err := scratch.Make(root, scratch.Publish)
	if err != nil {
		t.Fatal(err)
	}
	pid, owned := scratch.Owner(filepath.Base(dir))
	if !owned || pid != os.Getpid() {
		t.Fatalf("Owner(%q) = %d, %v; want this process (%d)", filepath.Base(dir), pid, owned, os.Getpid())
	}
	if filepath.Dir(dir) != root {
		t.Fatalf("scratch landed in %s, want a child of %s", dir, root)
	}
}

// THE CRASH CASE. A seal that was killed leaves its spool behind — this is
// the gigabytes case — and the next mount is the only chance anyone has to
// notice. It is collected immediately, with no age guard, because a pid
// that is gone is not coming back and making the user wait a day for their
// disk is a policy nobody would choose.
func TestScratchOfADeadOwnerIsCollected(t *testing.T) {
	root := t.TempDir()
	dead := os.Getpid() + 1
	names := []string{
		mkScratch(t, root, scratch.Publish, dead, 4096, 0),
		mkScratch(t, root, scratch.Snapshot, dead, 512, 0),
		mkScratch(t, root, scratch.Repack, dead, 1024, 0),
	}
	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	if got.Dirs != 3 {
		t.Fatalf("reclaimed %d directories, want all 3 (%v)", got.Dirs, got.Names)
	}
	if got.Bytes != 4096+512+1024 {
		t.Fatalf("reported %d bytes reclaimed, want %d", got.Bytes, 4096+512+1024)
	}
	for _, n := range names {
		if exists(t, filepath.Join(root, n)) {
			t.Fatalf("%s survived a sweep although its owner is dead", n)
		}
	}
}

// THE CASE THAT MUST NOT HAPPEN. A second mount of the same state
// directory is mid-seal, packing into its spool, when a new mount comes up
// and sweeps. Deleting that spool would destroy a running seal's work —
// which is why the question the sweep asks is about the process, not about
// the lease.
func TestScratchOfALiveSiblingIsNotCollected(t *testing.T) {
	root := t.TempDir()
	sibling := os.Getpid() + 1
	live := mkScratch(t, root, scratch.Publish, sibling, 8192, 0)
	dead := mkScratch(t, root, scratch.Publish, os.Getpid()+2, 8192, 0)

	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly(sibling)})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(t, filepath.Join(root, live)) {
		t.Fatal("the sweep deleted the spool of a process that is still running; a live seal just lost its packs")
	}
	if exists(t, filepath.Join(root, dead)) {
		t.Fatalf("%s survived although its owner is dead", dead)
	}
	if got.Dirs != 1 || got.Kept != 1 {
		t.Fatalf("reclaimed %d and kept %d, want 1 and 1", got.Dirs, got.Kept)
	}
}

// A LIVE SIBLING'S SPOOL STAYS SAFE FOR AS LONG AS THE SEAL RUNS. The
// guard is not a race won by luck: a spool whose owner is running is left
// alone whether it is a second old or most of a week, which is the length
// of the longest seal anybody could have.
func TestALiveOwnersScratchIsSafeForDays(t *testing.T) {
	root := t.TempDir()
	sibling := os.Getpid() + 1
	name := mkScratch(t, root, scratch.Publish, sibling, 16, 5*24*time.Hour)
	if _, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly(sibling)}); err != nil {
		t.Fatal(err)
	}
	if !exists(t, filepath.Join(root, name)) {
		t.Fatal("a five-day-old spool whose owner is still running was collected")
	}
}

// The one hole in pid ownership: pids are reused, and freely so across a
// reboot, so a stranded directory can inherit a live number and be
// protected by it forever. A week untouched settles it — no real seal or
// repack goes a week without writing to its own spool.
func TestPidReuseCannotProtectStrandedScratchForever(t *testing.T) {
	root := t.TempDir()
	impostor := os.Getpid() + 1
	name := mkScratch(t, root, scratch.Publish, impostor, 64, 8*24*time.Hour)
	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly(impostor)})
	if err != nil {
		t.Fatal(err)
	}
	if exists(t, filepath.Join(root, name)) {
		t.Fatal("scratch untouched for eight days survived because some process holds its number")
	}
	if got.Dirs != 1 {
		t.Fatalf("reclaimed %d directories, want 1", got.Dirs)
	}
}

// Names from earlier releases carry no pid — `publish-1234567` from
// os.MkdirTemp, and the fixed `repack` directory nothing ever removed.
// Nobody can be asked about them, so they wait out the age guard, and
// then they go.
func TestUnownedScratchWaitsOutTheAgeGuardAndThenGoes(t *testing.T) {
	root := t.TempDir()
	young := filepath.Join(root, "publish-1234567")
	old := filepath.Join(root, "publish-7654321")
	legacy := filepath.Join(root, "repack")
	mkDirWithFile(t, young, 32, time.Hour)
	mkDirWithFile(t, old, 32, 48*time.Hour)
	mkDirWithFile(t, legacy, 32, 48*time.Hour)

	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly()})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(t, young) {
		t.Fatal("an hour-old directory with no owner was collected; a running older release would have lost its spool")
	}
	if exists(t, old) || exists(t, legacy) {
		t.Fatal("a two-day-old unowned directory survived the age guard")
	}
	if got.Dirs != 2 {
		t.Fatalf("reclaimed %d directories, want 2 (%v)", got.Dirs, got.Names)
	}
}

// A state directory holds a volume's real state next to its scratch, and
// the sweep is one mistake away from deleting an overlay. It matches
// prefixes it created and nothing else.
func TestASweepTouchesNothingButScratch(t *testing.T) {
	root := t.TempDir()
	keep := []string{"overlay", "trash", "content", "gencache", "refs", "merge", "repacked-by-hand"}
	for _, name := range keep {
		mkDirWithFile(t, filepath.Join(root, name), 16, 72*time.Hour)
	}
	files := []string{"v2-dedup.db", "v2-signing.key", "pelfs-stats.json", "publish-notes.txt"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly()})
	if err != nil {
		t.Fatal(err)
	}
	if got.Dirs != 0 || got.Bytes != 0 {
		t.Fatalf("a state directory with no scratch in it lost %d directories (%v)", got.Dirs, got.Names)
	}
	for _, name := range append(append([]string{}, keep...), files...) {
		if !exists(t, filepath.Join(root, name)) {
			t.Fatalf("the sweep deleted %s, which is not scratch", name)
		}
	}
}

// The liveness oracle itself, against the OS rather than a stub: a process
// that has exited and been reaped is dead, and this process is not.
func TestPIDAliveAnswersForRealProcesses(t *testing.T) {
	if !scratch.PIDAlive(os.Getpid()) {
		t.Fatal("this process reports as dead")
	}
	for _, pid := range []int{0, -1} {
		if scratch.PIDAlive(pid) {
			t.Fatalf("pid %d reports as alive", pid)
		}
	}
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run a child to reap: %v", err)
	}
	if scratch.PIDAlive(cmd.Process.Pid) {
		t.Skip("the reaped child's pid was recycled before the check; nothing to conclude")
	}
}

// Reclaiming has to be reportable. Deleting gigabytes without a record is
// what makes "where did my disk go" unanswerable, so the count and the
// bytes come back from the sweep rather than being discarded.
func TestASweepReportsWhatItReclaimed(t *testing.T) {
	root := t.TempDir()
	dead := os.Getpid() + 1
	mkScratch(t, root, scratch.Publish, dead, 3<<20, 0)
	got, err := scratch.Sweep(root, scratch.Options{Alive: aliveOnly()})
	if err != nil {
		t.Fatal(err)
	}
	if got.Dirs != 1 || got.Bytes != 3<<20 {
		t.Fatalf("reported %d directories / %d bytes, want 1 / %d", got.Dirs, got.Bytes, 3<<20)
	}
	if len(got.Names) != 1 {
		t.Fatalf("reclaimed names %v, want exactly one", got.Names)
	}
}

// A read-only mount, a fresh state directory, a directory that is not
// there at all: the sweep runs on every mount, so every one of those is an
// ordinary case and none of them is an error.
func TestASweepOfNothingIsNotAnError(t *testing.T) {
	got, err := scratch.Sweep(filepath.Join(t.TempDir(), "never-created"), scratch.Options{})
	if err != nil {
		t.Fatalf("sweeping a missing directory: %v", err)
	}
	if got.Dirs != 0 {
		t.Fatalf("reclaimed %d directories from a directory that does not exist", got.Dirs)
	}
}
