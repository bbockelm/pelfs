package main

// --state-dir must cover EVERYTHING, including the mount-record registry.
//
// The bug these tests pin: --state-dir covered the session's own state —
// overlay, caches, control socket, signing key — while the registry
// directory was derived from stateRoot() independently of the flag. So a
// run pointed entirely at a temp directory still created
// ~/.local/state/pelfs/vol-<id>/, wrote mount.json into it, and left the
// directory behind, empty, when the record was retracted at exit. It was
// measured rather than theorised: the developer's state root grew by one
// directory per run of scripts/webui-playwright.sh, which had to export
// XDG_STATE_HOME to work around it.
//
// The assertion below is deliberately "nothing outside" rather than "the
// record is in the right place": a test that names the paths it expects
// cannot catch the NEXT path somebody derives from the default root.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"

	"net/http/httptest"
)

// sentinelHome points every default-state-root mechanism at empty
// directories of the test's own, and returns a function that fails the test
// if anything appeared in either of them.
//
// Both are needed: XDG_STATE_HOME is what defaultStateRoot prefers, and
// HOME is what it falls back to — a fix that honoured only one of them
// would pass a test that set only that one.
func sentinelHome(t *testing.T) func() {
	t.Helper()
	xdg := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	t.Setenv("HOME", home)
	// USERPROFILE is what os.UserHomeDir reads on Windows; setting it costs
	// nothing here and keeps this test honest if it ever runs there.
	t.Setenv("USERPROFILE", home)
	return func() {
		t.Helper()
		for _, root := range []string{xdg, home} {
			var found []string
			err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if p != root {
					found = append(found, strings.TrimPrefix(p, root))
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walking %s: %v", root, err)
			}
			if len(found) > 0 {
				t.Errorf("pelfs created %d path(s) outside --state-dir, under %s: %v",
					len(found), root, found)
			}
		}
	}
}

// TestStateDirCoversTheMountRecord drives the function that escaped, in
// the case that escaped: a FOREGROUND session (`pelfs shell`, `mount-gen`,
// `browse`) started with --state-dir.
func TestStateDirCoversTheMountRecord(t *testing.T) {
	nothingEscaped := sentinelHome(t)
	g := newGenSession(t, true)
	// Exactly as runMountGen builds it when --state-dir was given and the
	// session is not the `pelfs mount` daemon child.
	g.stateRoot = registryRoot(&cmdOpts{stateDir: g.stateDir}, false)

	retract := g.publishMountRecord()
	record := filepath.Join(volDirIn(g.stateDir, g.prefix), "mount.json")
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the record is not under the state dir: %v", err)
	}
	// And it is discoverable from that root, which is the property the fix
	// must not cost: `pelfs status --state-dir X` has to find what
	// `pelfs mount --state-dir X` registered.
	entries, err := listMounts(g.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].info.Prefix != g.prefix {
		t.Fatalf("listMounts(%s) = %+v", g.stateDir, entries)
	}
	// Not in the default root, which is the whole point.
	if def, err := listMounts(defaultStateRoot()); err != nil || len(def) != 0 {
		t.Fatalf("the default root has %d record(s) (err %v)", len(def), err)
	}
	retract()
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Errorf("the record survived its retraction: %v", err)
	}
	// And the directory goes with it when it is empty, which is what the
	// state root filling up with vol-<id> directories was.
	if _, err := os.Stat(filepath.Dir(record)); !os.IsNotExist(err) {
		t.Errorf("the retraction left an empty registry directory behind: %v", err)
	}
	nothingEscaped()
}

// TestABackgroundMountRegistersMachineGlobally is the deliberate exception,
// and it is here so that changing it is a decision rather than an accident.
//
// `pelfs mount` detaches. Its whole contract is that a shell can find it
// afterwards by prefix — `pelfs status`, `pelfs umount <prefix>`,
// `pelfs ctl <prefix> publish`, which is the sequence
// scripts/mount-gate-test.sh runs — and a reader cannot be told about a
// --state-dir it never saw. So that ONE session registers in the default
// root even under --state-dir, and the retraction above is what keeps the
// registry from accumulating.
func TestABackgroundMountRegistersMachineGlobally(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	g := newGenSession(t, true)
	g.stateRoot = registryRoot(&cmdOpts{stateDir: g.stateDir}, true)

	retract := g.publishMountRecord()
	// Found by prefix, with no flag, which is the property this exception
	// exists to preserve.
	entries, err := listMounts(defaultStateRoot())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].info.Prefix != g.prefix {
		t.Fatalf("a background mount is not discoverable by prefix: %+v", entries)
	}
	// And it points `pelfs ctl` at the session's real state, wherever the
	// --state-dir put it.
	if entries[0].info.StateDir != g.stateDir {
		t.Errorf("the record does not name the session's state dir: %q", entries[0].info.StateDir)
	}
	retract()
	if left, err := listMounts(defaultStateRoot()); err != nil || len(left) != 0 {
		t.Fatalf("the record outlived the session: %+v (err %v)", left, err)
	}
	// Nothing is left in the registry root at all: no empty vol-<id>.
	rest, err := os.ReadDir(filepath.Join(xdg, "pelfs"))
	if err == nil && len(rest) != 0 {
		t.Errorf("the registry root still holds %d entry/entries after retraction", len(rest))
	}
}

// TestSessionWithoutARootRecordsBesideItsOwnState: a genSession assembled
// without a root — every test in this package builds one — must record
// beside its own state and never in the user's home. The fallback is what
// makes the escape impossible rather than merely fixed at one call site.
func TestSessionWithoutARootRecordsBesideItsOwnState(t *testing.T) {
	nothingEscaped := sentinelHome(t)
	g := newGenSession(t, true)
	if g.stateRoot != "" {
		t.Fatalf("the fixture set a root: %q", g.stateRoot)
	}
	retract := g.publishMountRecord()
	defer retract()
	if _, err := os.Stat(filepath.Join(volDirIn(g.stateDir, g.prefix), "mount.json")); err != nil {
		t.Fatalf("no record beside the session's own state: %v", err)
	}
	nothingEscaped()
}

// TestStateRootResolution is the flag's contract in four lines: the flag
// wins, then XDG_STATE_HOME, then the home directory.
func TestStateRootResolution(t *testing.T) {
	xdg := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	t.Setenv("HOME", home)
	dir := t.TempDir()
	if got := (&cmdOpts{stateDir: dir}).stateRoot(); got != dir {
		t.Errorf("--state-dir did not win: %q", got)
	}
	if got := (&cmdOpts{}).stateRoot(); got != filepath.Join(xdg, "pelfs") {
		t.Errorf("XDG_STATE_HOME ignored: %q", got)
	}
	t.Setenv("XDG_STATE_HOME", "")
	if got := (&cmdOpts{}).stateRoot(); got != filepath.Join(home, ".local", "state", "pelfs") {
		t.Errorf("home fallback: %q", got)
	}
	// The per-prefix directory is a pure function of the root and the
	// prefix, so two roots cannot collide and one root cannot forget which
	// volume a record belongs to.
	a := volDirIn("/roots/one", "pelican://fed/a")
	b := volDirIn("/roots/two", "pelican://fed/a")
	c := volDirIn("/roots/one", "pelican://fed/b")
	if filepath.Base(a) != filepath.Base(b) || filepath.Base(a) == filepath.Base(c) {
		t.Errorf("volDirIn is not (root, prefix)-keyed: %q %q %q", a, b, c)
	}
}

// TestAWholeBrowseRunStaysInsideItsStateDir is the harness-level
// assertion: run the actual verb with --state-dir and let a walk of two
// empty directories say whether anything at all appeared outside it.
//
// It is deliberately not aimed at the record — `pelfs browse` publishes
// none; the escape was reached through `pelfs shell`, which is runMountGen
// and needs a kernel mount this package cannot take. What it is aimed at is
// EVERY OTHER path: the whole startup, the lease, the checkpointer, the
// control socket, the statistics, the seal at exit, and whatever a later
// milestone adds to that sequence. A test that named the paths it expected
// could not do that.
func TestAWholeBrowseRunStaysInsideItsStateDir(t *testing.T) {
	nothingEscaped := sentinelHome(t)
	ctx := context.Background()
	origin := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	defer origin.Close()
	prefix := origin.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatal(err)
	}
	// Short, because the control socket lives in here and a unix socket
	// path is capped near 104 bytes.
	stateDir, err := os.MkdirTemp("", "ps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stateDir) //nolint:errcheck
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "v2-signing.key"),
		[]byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var volID [16]byte
	if _, err := rand.Read(volID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: stateDir, Branch: "main", SigningKey: priv, VolumeID: volID,
	}); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut := os.Stdout
	os.Stdout = w
	stop := make(chan struct{})
	browseStop = stop
	t.Cleanup(func() { os.Stdout = savedOut; browseStop = nil })

	o := &cmdOpts{stateDir: stateDir, prefetch: "none", snapshotInterval: time.Minute}
	done := make(chan int, 1)
	go func() {
		done <- runBrowse(o, prefix, browseArgs{branch: "main", rw: true})
	}()

	// The verb prints its launch block; reading it is how this test knows
	// the listener is up, with no sleep anywhere.
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the launch block: %v", err)
		}
		if strings.Contains(line, "http://127.0.0.1:") && strings.Contains(line, "#bt=") {
			break
		}
	}
	close(stop)
	if code := <-done; code != 0 {
		t.Fatalf("runBrowse exited %d", code)
	}
	// The session really ran: its statistics file is in the state dir.
	if _, err := os.Stat(filepath.Join(stateDir, "pelfs-stats.json")); err != nil {
		t.Fatalf("the session did not get as far as its own teardown: %v", err)
	}
	nothingEscaped()
}
