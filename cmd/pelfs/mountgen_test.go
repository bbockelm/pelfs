package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/stats"
)

// newGenSession builds a real mount session over a fakeorigin-backed
// volume: generation 0, a genfs over it, and (when rw) a write overlay.
// Everything but the kernel binding, which is what the control socket and
// the seal path actually touch.
func newGenSession(t *testing.T, rw bool) *genSession {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	// A short path on purpose: the control socket lives in the state dir,
	// and a Unix socket path is capped near 104 bytes — t.TempDir() spells
	// the test's name into it and blows the limit.
	stateDir, err := os.MkdirTemp("", "pf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(stateDir, "v2-signing.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var volID [16]byte
	if _, err := rand.Read(volID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: stateDir, Branch: "main", SigningKey: priv, VolumeID: volID,
	}); err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	rstore, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch main: %v", err)
	}

	g := &genSession{
		prefix:     prefix,
		branch:     "main",
		stateDir:   stateDir,
		mountpoint: filepath.Join(stateDir, "mnt"),
		backend:    "fuse",
		sessionID:  "test-session",
		started:    time.Now(),
		rw:         rw,
		overlayDir: filepath.Join(stateDir, "overlay"),
		statsPath:  filepath.Join(stateDir, "pelfs-stats.json"),
		// As runMountGen builds it: inert until beginTeardown, so a test
		// that exercises the exit path gets the same breakdown a user does.
		down:    &phaseClock{},
		sb:      f.Superblock,
		prevRaw: f.Raw,
	}
	g.refs = rstore
	g.stats = stats.New(prefix, g.sessionID, g.statsPath)
	// The session's own traffic goes through the counter, exactly as it
	// does in runMountGen; the volume setup above deliberately does not,
	// so what the counters hold is what the session itself moved.
	g.inner = countedStore{ObjectStore: stats.WrapStorage(inner, g.stats), raw: inner}
	g.stats.Update(func(sum *stats.Summary) {
		sum.MountPoint = g.mountpoint
		sum.Branch = g.branch
		sum.Backend = g.backend
		sum.Writable = rw
	})

	g.gfs, err = genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: f.Superblock, CacheDir: filepath.Join(stateDir, "gencache"),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = g.gfs.Close() })
	if rw {
		g.ov, err = overlay.Open(g.overlayDir, g.gfs, overlay.Options{
			NextInode:      g.gfs.NextInode(),
			BaseRoot:       g.gfs.RootCatalog(),
			BaseGeneration: g.gfs.Generation(),
		})
		if err != nil {
			t.Fatalf("overlay.Open: %v", err)
		}
		t.Cleanup(func() { _ = g.ov.Close() })
	}
	return g
}

// writeFile creates one file with content in the overlay.
func writeFile(t *testing.T, ov *overlay.FS, name, body string) {
	t.Helper()
	ctx := context.Background()
	n, err := ov.Create(ctx, overlay.RootInode, name, 0644, 0, 0)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte(body)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func serve(t *testing.T, g *genSession) *control.Client {
	t.Helper()
	srv, err := control.Start(g.stateDir, g.controlHooks())
	if err != nil {
		t.Fatalf("control.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return control.NewClient(g.stateDir)
}

func TestMountGenControlStatusAndStats(t *testing.T) {
	g := newGenSession(t, true)
	c := serve(t, g)
	ctx := context.Background()

	body, err := c.Do(ctx, "GET", "/v1/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("status body %s: %v", body, err)
	}
	for k, want := range map[string]any{
		"engine":     "catalog-native",
		"branch":     "main",
		"backend":    "fuse",
		"read_only":  false,
		"generation": float64(0),
	} {
		if st[k] != want {
			t.Errorf("status[%q] = %v, want %v", k, st[k], want)
		}
	}

	writeFile(t, g.ov, "dirty.txt", "unsealed work")
	body, err = c.Do(ctx, "GET", "/v1/stats")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	var sum stats.Summary
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatalf("stats body %s: %v", body, err)
	}
	if !sum.Writable || sum.Backend != "fuse" {
		t.Errorf("stats did not carry the session's mode and backend: %+v", sum)
	}
	// The hook samples before flushing, so the dirty write above must be
	// visible without waiting for the periodic tick.
	if sum.OverlayDirtyNodes == 0 || sum.OverlayStagedBytes == 0 {
		t.Errorf("overlay pressure not reported: nodes=%d staged=%d",
			sum.OverlayDirtyNodes, sum.OverlayStagedBytes)
	}
}

// A read-only mount-gen session must expose no way to write: no lease is
// taken and the publish verb is absent.
func TestMountGenControlReadOnlyHasNoPublish(t *testing.T) {
	g := newGenSession(t, false)
	c := serve(t, g)
	ctx := context.Background()
	if _, err := c.Do(ctx, "POST", "/v1/publish"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("POST /v1/publish: err=%v, want 404", err)
	}
	if g.lease != nil {
		t.Error("a read-only session took the write lease")
	}
}

// The checkpoint verb seals mid-session and the mount keeps working:
// the served generation and the overlay are untouched, and — the part
// that only an advanced seal anchor gets right — a SECOND checkpoint
// still passes the ref compare-and-swap.
func TestMountGenCheckpointSealsAndKeepsServing(t *testing.T) {
	g := newGenSession(t, true)
	c := serve(t, g)
	ctx := context.Background()

	// Nothing dirty yet: the verb must be a no-op, not a new generation.
	body, err := c.Do(ctx, "POST", "/v1/publish")
	if err != nil {
		t.Fatalf("publish (clean): %v", err)
	}
	if !strings.Contains(string(body), "nothing changed") {
		t.Fatalf("clean checkpoint published anyway: %s", body)
	}

	writeFile(t, g.ov, "first.txt", "one")
	if body, err = c.Do(ctx, "POST", "/v1/publish"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !strings.Contains(string(body), "generation 1") {
		t.Fatalf("first checkpoint: %s", body)
	}
	// A checkpoint ADVANCES the served generation: the mount swaps onto
	// what it just published so the overlay's now-redundant rows can be
	// dropped and those inodes go back to clean (infinite kernel TTLs).
	// Rebase refuses to drop rows against an older base, so this order is
	// enforced, not merely conventional.
	if got := g.gfs.Generation(); got != 1 {
		t.Errorf("served generation is %d after the checkpoint; it must follow the seal to 1", got)
	}
	// Whatever the engine did underneath, the mount keeps serving the
	// same tree — the write is still there, by the same name.
	if _, err := g.ov.Lookup(ctx, overlay.RootInode, "first.txt"); err != nil {
		t.Errorf("the mount stopped serving its own write after the checkpoint: %v", err)
	}
	if dirty, err := g.ov.IsDirty(overlay.RootInode); err == nil && dirty {
		t.Logf("root still dirty after checkpoint (acceptable: it may have been touched since the snapshot)")
	}

	// More work, then a second checkpoint. Without the anchor advancing,
	// publish's CAS sees a ref that no longer matches PrevRaw and refuses.
	writeFile(t, g.ov, "second.txt", "two")
	if body, err = c.Do(ctx, "POST", "/v1/publish"); err != nil {
		t.Fatalf("second checkpoint: %v", err)
	}
	if !strings.Contains(string(body), "generation 2") {
		t.Fatalf("second checkpoint: %s", body)
	}

	// The branch head is the checkpoint, and it carries both writes.
	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after checkpoints: %v", err)
	}
	if f.Superblock.Generation != 2 {
		t.Fatalf("branch head is generation %d, want 2", f.Superblock.Generation)
	}
	head, err := genfs.Open(ctx, genfs.Options{
		Inner: g.inner, SB: f.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open the checkpointed generation: %v", err)
	}
	defer head.Close() //nolint:errcheck
	for _, name := range []string{"first.txt", "second.txt"} {
		if _, err := head.Lookup(ctx, genfs.RootInode, name); err != nil {
			t.Errorf("%s missing from the checkpointed generation: %v", name, err)
		}
	}

	// Statistics record every seal, the last generation, and that the
	// session is still holding unsealed state.
	var sum stats.Summary
	body, err = c.Do(ctx, "GET", "/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Seals != 2 || sum.SealedGeneration != 2 {
		t.Errorf("seal statistics: seals=%d last=%d, want 2/2", sum.Seals, sum.SealedGeneration)
	}
}

// sealAtExit retires the overlay, and a checkpoint after that must be
// refused rather than panic on a closed database.
func TestMountGenSealAtExitRetiresOverlay(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "final.txt", "sealed at unmount")
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}
	if _, err := os.Stat(g.overlayDir); !os.IsNotExist(err) {
		t.Errorf("the spent overlay survived at %s (err %v)", g.overlayDir, err)
	}
	if _, err := g.checkpoint(ctx); err == nil {
		t.Error("checkpoint on a retired overlay succeeded")
	}
	// A second seal is a no-op, not a second generation.
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("second sealAtExit: %v", err)
	}
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	if sum.Seals != 1 || sum.SealOK == nil || !*sum.SealOK {
		t.Errorf("seal statistics after exit: %+v", sum)
	}
	// The last sample of overlay pressure survives the retirement: it is
	// what the seal consumed.
	g.refresh()
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	// The seal advanced the BRANCH, and the mount deliberately did not
	// follow it there. Following means re-descending the resident tree and
	// rewriting overlay rows so future reads are cheap, and an unmount has
	// no future reads — the overlay is retired above. Pinned because it
	// was minutes of latency on the exit path of a large tree.
	if sum.SealedGeneration != 1 {
		t.Errorf("sealed generation is %d; the exit seal should have published 1", sum.SealedGeneration)
	}
	if sum.GenerationSwaps != 0 {
		t.Errorf("the exit seal swapped the served generation %d times; nothing reads it after unmount",
			sum.GenerationSwaps)
	}

	// The document a supervisor reads after the session is gone.
	if err := g.stats.Finalize(0, true); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	body, err := os.ReadFile(g.statsPath)
	if err != nil {
		t.Fatalf("read stats file: %v", err)
	}
	var final stats.Summary
	if err := json.Unmarshal(body, &final); err != nil {
		t.Fatalf("stats file %s: %v", body, err)
	}
	if !final.CleanShutdown || final.ExitCode != 0 || final.SealedGeneration != 1 ||
		final.Branch != "main" || !final.Writable {
		t.Errorf("finalized summary: %+v", final)
	}
}

// Retirement must not pay for deletion: the spent overlay moves aside in
// constant time and its bytes are still on disk afterwards, for a sweep
// nobody is waiting on to reclaim.
func TestRetireOverlayRenamesInsteadOfDeleting(t *testing.T) {
	g := newGenSession(t, true)
	writeFile(t, g.ov, "final.txt", "sealed at unmount")
	if err := g.ov.Close(); err != nil {
		t.Fatalf("close overlay: %v", err)
	}

	// Hold the reclaim back so the state right after retirement is
	// observable: what is being asserted is that retirement itself does
	// not delete anything.
	var reclaimed []string
	g.reclaimFn = func(dir string) { reclaimed = append(reclaimed, dir) }
	if err := g.retireDir(g.overlayDir); err != nil {
		t.Fatalf("retireDir: %v", err)
	}
	if _, err := os.Stat(g.overlayDir); !os.IsNotExist(err) {
		t.Errorf("the spent overlay is still at %s (err %v)", g.overlayDir, err)
	}
	trash := filepath.Join(g.stateDir, trashDirName)
	ents, err := os.ReadDir(trash)
	if err != nil {
		t.Fatalf("read trash: %v", err)
	}
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), g.sessionID+"-") {
		t.Fatalf("trash holds %v, want one entry named for this session", ents)
	}
	spent := filepath.Join(trash, ents[0].Name())
	if len(reclaimed) != 1 || reclaimed[0] != spent {
		t.Errorf("reclaim was handed %v, want [%s]", reclaimed, spent)
	}
	inside, err := os.ReadDir(spent)
	if err != nil {
		t.Fatalf("read the retired overlay: %v", err)
	}
	if len(inside) == 0 {
		t.Error("retirement deleted the overlay's contents; the whole point is that it does not")
	}
}

// The seal at unmount runs after the mountpoint is gone, so there is no
// writer to freeze the overlay against — and freezing it anyway cost one
// hardlink per staged inode in and one unlink out. It must publish the
// live overlay, and it must publish the same bytes.
func TestSealAtExitDoesNotFreezeTheOverlay(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	g.reclaimFn = func(string) {} // keep retired scratch observable
	writeFile(t, g.ov, "final.txt", "sealed at unmount")
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}
	ents, err := os.ReadDir(g.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "snapshot-") {
			t.Errorf("the exit seal left a snapshot at %s", e.Name())
		}
	}
	trashed, err := os.ReadDir(filepath.Join(g.stateDir, trashDirName))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range trashed {
		if strings.Contains(e.Name(), "snapshot-") {
			t.Errorf("the exit seal froze the overlay into %s", e.Name())
		}
	}

	// Same bytes, read back through a fresh reader over what was published.
	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	head, err := genfs.Open(ctx, genfs.Options{
		Inner: g.inner, SB: f.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer head.Close() //nolint:errcheck
	n, err := head.Lookup(ctx, genfs.RootInode, "final.txt")
	if err != nil {
		t.Fatalf("lookup the sealed file: %v", err)
	}
	buf := make([]byte, n.Length)
	if _, err := head.Read(ctx, n.Inode, 0, buf); err != nil {
		t.Fatalf("read the sealed file: %v", err)
	}
	if string(buf) != "sealed at unmount" {
		t.Errorf("sealed content is %q", buf)
	}
}

// A checkpoint DOES freeze: it publishes while writers keep working, and
// the frozen sequence is what lets the rebase mark inodes clean.
func TestCheckpointStillFreezesTheOverlay(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	g.reclaimFn = func(string) {}
	writeFile(t, g.ov, "first.txt", "one")
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	trashed, err := os.ReadDir(filepath.Join(g.stateDir, trashDirName))
	if err != nil {
		t.Fatalf("a checkpoint did not freeze the overlay: %v", err)
	}
	found := false
	for _, e := range trashed {
		if strings.Contains(e.Name(), "snapshot-") {
			found = true
		}
	}
	if !found {
		t.Errorf("a checkpoint did not freeze the overlay; trash holds %v", trashed)
	}
}

// The crash window that matters: killed after the rename, before the
// bytes are gone. A later mount must start a FRESH overlay and must never
// see the retired one, and the sweep must then reclaim it.
func TestRetiredOverlayIsNotResumedByALaterMount(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "final.txt", "sealed at unmount")
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}

	// A later mount of the same state directory, over the head the seal
	// published.
	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after the exit seal: %v", err)
	}
	next, err := genfs.Open(ctx, genfs.Options{
		Inner: g.inner, SB: f.Superblock, CacheDir: filepath.Join(g.stateDir, "gencache2"),
	})
	if err != nil {
		t.Fatalf("genfs.Open on the sealed head: %v", err)
	}
	defer next.Close() //nolint:errcheck
	ov2, err := overlay.Open(g.overlayDir, next, overlay.Options{
		NextInode:      next.NextInode(),
		BaseRoot:       next.RootCatalog(),
		BaseGeneration: next.Generation(),
	})
	if err != nil {
		t.Fatalf("the state directory was not reusable after a seal: %v", err)
	}
	defer ov2.Close() //nolint:errcheck
	st, err := ov2.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.DirtyNodes != 0 || st.DirtyEdges != 0 {
		t.Errorf("the new overlay inherited state from the retired one: %+v", st)
	}
	// And it serves the sealed tree, so nothing was lost on the way.
	if _, err := ov2.Lookup(ctx, overlay.RootInode, "final.txt"); err != nil {
		t.Errorf("the sealed file is not visible through the new mount: %v", err)
	}

	// Whatever the exit path's background delete did or did not finish,
	// the sweep leaves the trash empty and touches nothing else.
	sweepRetiredOverlays(g.stateDir)
	ents, err := os.ReadDir(filepath.Join(g.stateDir, trashDirName))
	if err != nil {
		t.Fatalf("read trash after the sweep: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("the sweep left %d retired overlays behind", len(ents))
	}
	if _, err := os.Stat(g.overlayDir); err != nil {
		t.Errorf("the sweep took the LIVE overlay: %v", err)
	}
}

// sweepRetiredOverlays must survive being pointed at a state directory
// that never retired anything, and must clear what a killed session left.
func TestSweepRetiredOverlaysReclaimsWhatACrashLeft(t *testing.T) {
	dir := t.TempDir()
	sweepRetiredOverlays(dir) // no trash directory at all
	spent := filepath.Join(dir, trashDirName, "20260101T000000Z-host-deadbeef", "staging")
	if err := os.MkdirAll(spent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spent, "42"), []byte("orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	sweepRetiredOverlays(dir)
	ents, err := os.ReadDir(filepath.Join(dir, trashDirName))
	if err != nil {
		t.Fatalf("read trash: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("sweep left %d entries", len(ents))
	}
}

// --no-seal is the resumable path and must stay one: the overlay is kept
// where the next mount looks for it, with its dirty state intact.
func TestSealAtExitKeepsTheOverlayWithNoSeal(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	g.noSeal = true
	writeFile(t, g.ov, "unsealed.txt", "still mine")
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}
	if _, err := os.Stat(g.overlayDir); err != nil {
		t.Fatalf("--no-seal retired the overlay anyway: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.stateDir, trashDirName)); !os.IsNotExist(err) {
		t.Errorf("--no-seal created a trash directory (err %v)", err)
	}
	// Resumable means the next mount reads the dirty state back, not just
	// that the directory survived.
	if err := g.ov.Close(); err != nil {
		t.Fatalf("close overlay: %v", err)
	}
	ov2, err := overlay.Open(g.overlayDir, g.gfs, overlay.Options{
		NextInode:      g.gfs.NextInode(),
		BaseRoot:       g.gfs.RootCatalog(),
		BaseGeneration: g.gfs.Generation(),
	})
	if err != nil {
		t.Fatalf("reopen the kept overlay: %v", err)
	}
	defer ov2.Close() //nolint:errcheck
	if _, err := ov2.Lookup(ctx, overlay.RootInode, "unsealed.txt"); err != nil {
		t.Errorf("the kept overlay lost its unsealed write: %v", err)
	}
}

// TestMountGenCheckpointsOnACadence pins that a writable mount seals on
// its own while serving. Without it every session defers all packing and
// uploading to unmount, so `exit` blocks for as long as the session's
// work takes -- minutes after a large extraction.
//
// It watches the published ref rather than the served generation: the
// checkpoint swaps the mount under its own lock, and polling that state
// from the test would race it.
func TestMountGenCheckpointsOnACadence(t *testing.T) {
	g := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, g.ov, "first.txt", "one")
	go g.checkpointPeriodically(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := rstore.Fetch(ctx, "main")
		if err == nil && f.Superblock.Generation >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a writable mount never checkpointed on its own; unmount would have to seal the whole session at once")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A cadence must not manufacture empty generations once the session
	// goes quiet: checkpoint skips a clean overlay, so the branch head
	// has to stop advancing.
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after checkpoint: %v", err)
	}
	settled := f.Superblock.Generation
	time.Sleep(200 * time.Millisecond) // many ticks at 10ms
	if f, err = rstore.Fetch(ctx, "main"); err != nil {
		t.Fatalf("fetch after idling: %v", err)
	}
	if f.Superblock.Generation != settled {
		t.Errorf("idle mount kept publishing: generation went %d -> %d with nothing dirty",
			settled, f.Superblock.Generation)
	}
}

// randomFile writes size bytes of incompressible content, so what the
// seal uploads is bounded below by what was written rather than by how
// well a pack compressed.
func randomFile(t *testing.T, ov *overlay.FS, name string, size int) {
	t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	writeFile(t, ov, name, string(buf))
}

func phaseSnapshot(g *genSession) stats.Summary {
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	return sum
}

// checkPhasesReconcile is the property that makes the split trustworthy:
// every counted operation lands in exactly one phase, so a reader can
// take "0 during the session" at face value instead of wondering what
// fell between the two.
func checkPhasesReconcile(t *testing.T, sum stats.Summary) {
	t.Helper()
	for _, c := range []struct {
		name               string
		agg, ses, teardown stats.OpCounters
	}{
		{"get", sum.Get, sum.SessionPhase.Get, sum.TeardownPhase.Get},
		{"put", sum.Put, sum.SessionPhase.Put, sum.TeardownPhase.Put},
		{"delete", sum.Delete, sum.SessionPhase.Delete, sum.TeardownPhase.Delete},
		{"other", sum.Other, sum.SessionPhase.Other, sum.TeardownPhase.Other},
	} {
		if got := c.ses.Ops + c.teardown.Ops; got != c.agg.Ops {
			t.Errorf("%s ops: %d session + %d teardown = %d, but the total is %d",
				c.name, c.ses.Ops, c.teardown.Ops, got, c.agg.Ops)
		}
		if got := c.ses.Bytes + c.teardown.Bytes; got != c.agg.Bytes {
			t.Errorf("%s bytes: %d session + %d teardown = %d, but the total is %d",
				c.name, c.ses.Bytes, c.teardown.Bytes, got, c.agg.Bytes)
		}
		if got := c.ses.Errors + c.teardown.Errors; got != c.agg.Errors {
			t.Errorf("%s errors: %d session + %d teardown = %d, but the total is %d",
				c.name, c.ses.Errors, c.teardown.Errors, got, c.agg.Errors)
		}
	}
	if got := sum.SessionPhase.Seals + sum.TeardownPhase.Seals; got != sum.Seals {
		t.Errorf("seals: %d session + %d teardown = %d, but the total is %d",
			sum.SessionPhase.Seals, sum.TeardownPhase.Seals, got, sum.Seals)
	}
}

// TestPhaseSplitChargesAnExitSealToTeardown is half of the answer to
// "was any of this published while I was working?". A session whose only
// seal is at unmount must report zero uploaded bytes for the session
// phase and the whole payload for teardown -- the unflattering answer,
// stated plainly rather than hidden inside a session total.
func TestPhaseSplitChargesAnExitSealToTeardown(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	const payload = 512 << 10
	randomFile(t, g.ov, "vmlinux", payload)

	// Writing into the overlay is local work: a writable mount puts
	// nothing in the federation until something seals.
	if s := phaseSnapshot(g); s.SessionPhase.Put.Bytes != 0 {
		t.Fatalf("writing to the overlay uploaded %d bytes before any seal", s.SessionPhase.Put.Bytes)
	}

	g.beginTeardown()
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}

	sum := phaseSnapshot(g)
	t.Logf("session put %d bytes / %d seals, teardown put %d bytes / %d seals",
		sum.SessionPhase.Put.Bytes, sum.SessionPhase.Seals,
		sum.TeardownPhase.Put.Bytes, sum.TeardownPhase.Seals)
	if sum.SessionPhase.Put.Bytes != 0 || sum.SessionPhase.Seals != 0 {
		t.Errorf("the session phase shows %d bytes in %d seals; nothing was published before the payload exited",
			sum.SessionPhase.Put.Bytes, sum.SessionPhase.Seals)
	}
	if sum.TeardownPhase.Put.Bytes < payload {
		t.Errorf("teardown uploaded %d bytes for a %d-byte payload", sum.TeardownPhase.Put.Bytes, payload)
	}
	if sum.TeardownPhase.Seals != 1 {
		t.Errorf("teardown recorded %d seals, want the one at exit", sum.TeardownPhase.Seals)
	}
	if sum.TeardownBegan.IsZero() {
		t.Error("the summary does not say where the phase boundary was drawn")
	}
	checkPhasesReconcile(t, sum)
}

// TestPhaseSplitChargesACheckpointToTheSession is the other half: a
// mid-session checkpoint is work that did NOT wait for the end, so it
// belongs to the session phase, and the seal at exit is then left with
// almost nothing to send.
func TestPhaseSplitChargesACheckpointToTheSession(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	g.reclaimFn = func(string) {}
	const payload = 512 << 10
	randomFile(t, g.ov, "vmlinux", payload)

	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	mid := phaseSnapshot(g)
	if mid.SessionPhase.Put.Bytes < payload {
		t.Errorf("the checkpoint uploaded %d bytes for a %d-byte payload", mid.SessionPhase.Put.Bytes, payload)
	}
	if mid.SessionPhase.Seals != 1 {
		t.Errorf("the session phase recorded %d seals, want the checkpoint", mid.SessionPhase.Seals)
	}
	if mid.TeardownPhase.Put.Bytes != 0 || mid.TeardownPhase.Seals != 0 {
		t.Errorf("teardown counted %d bytes in %d seals while the payload was still running",
			mid.TeardownPhase.Put.Bytes, mid.TeardownPhase.Seals)
	}

	g.beginTeardown()
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit: %v", err)
	}
	sum := phaseSnapshot(g)
	t.Logf("session put %d bytes / %d seals, teardown put %d bytes / %d seals",
		sum.SessionPhase.Put.Bytes, sum.SessionPhase.Seals,
		sum.TeardownPhase.Put.Bytes, sum.TeardownPhase.Seals)
	// The content is already in the federation, so whatever the exit seal
	// still has to write is metadata carried forward, not the payload.
	if sum.TeardownPhase.Put.Bytes >= sum.SessionPhase.Put.Bytes {
		t.Errorf("teardown uploaded %d bytes against the session's %d; the checkpoint bought nothing",
			sum.TeardownPhase.Put.Bytes, sum.SessionPhase.Put.Bytes)
	}
	checkPhasesReconcile(t, sum)
}

// TestCheckpointFiresUnderWritePressure pins the trigger that the clock
// alone cannot provide. Extracting a kernel tree wrote 441 MiB in 1m45s
// against a 5 minute interval, so no checkpoint fired and the entire
// session's upload landed after the user typed exit. A session that
// writes fast has to publish often regardless of elapsed time.
func TestCheckpointFiresUnderWritePressure(t *testing.T) {
	g := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// An interval far longer than this test will run: if a checkpoint
	// happens, only pressure can have caused it.
	go g.checkpointPeriodically(ctx, time.Hour)

	// Stage more than the threshold. Written as several files because
	// staged bytes are summed across staging files, which is what the
	// sampler reads.
	body := make([]byte, 8<<20)
	for i := 0; i < (checkpointBytes/len(body))+2; i++ {
		writeFile(t, g.ov, fmt.Sprintf("big-%02d.bin", i), string(body))
	}

	deadline := time.Now().Add(60 * time.Second * raceSlowdown)
	for {
		f, err := rstore.Fetch(ctx, "main")
		if err == nil && f.Superblock.Generation >= 1 {
			return
		}
		if time.Now().After(deadline) {
			staged, nodes, edges := g.pressure()
			t.Fatalf("staged %d bytes across %d dirty inodes and %d dirty edges without a "+
				"checkpoint; only the hour-long timer could publish it", staged, nodes, edges)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// gatePutsOn holds every Put whose key starts with a prefix until release
// is closed, and announces the first one it holds. It is how a test puts
// a checkpoint genuinely IN FLIGHT — parked inside sealLocked with the
// seal lock held — instead of hoping to catch one by timing.
type gatePutsOn struct {
	pelicanobj.Store
	prefix  string
	once    sync.Once
	held    chan struct{}
	release chan struct{}
}

func (g *gatePutsOn) Put(ctx context.Context, key string, r io.Reader) error {
	if strings.HasPrefix(key, g.prefix) {
		g.once.Do(func() { close(g.held) })
		<-g.release
	}
	return g.Store.Put(ctx, key, r)
}

// Unwrap keeps the transport's capabilities visible through the
// decorator, for the reason failPutsOn does.
func (g *gatePutsOn) Unwrap() pelicanobj.Store { return g.Store }

// phaseDuration reads one phase back out of a clock, so a test can assert
// on the breakdown a user reads rather than on log output.
func phaseDuration(c *phaseClock, name string) (time.Duration, bool) {
	if c == nil {
		return 0, false
	}
	for i := 0; i+1 < len(c.parts); i += 2 {
		if n, ok := c.parts[i].(string); ok && n == name {
			d, _ := c.parts[i+1].(time.Duration)
			return d, true
		}
	}
	return 0, false
}

// Teardown must JOIN the periodic checkpointer, not race it.
//
// The nil-map panic (a16b948) made the collision survivable in
// internal/overlay, but survivable is not done: a checkpoint cut off by
// teardown publishes NOTHING, and the changes it was sealing stay in an
// overlay whose state directory a batch-system wrapper is entitled to
// wipe the moment the process exits. So the property is not "no crash",
// it is "the seal that was in flight LANDED before the overlay was
// touched" — asserted here as the published ref advancing and the mount
// following it, with the overlay still open underneath.
func TestExitDrainsAnInFlightCheckpoint(t *testing.T) {
	g := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.reclaimFn = func(string) {}

	// A ref store on the ungated transport: the test must be able to read
	// the branch head while the checkpoint's packs are held.
	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := &gatePutsOn{
		Store:   g.inner,
		prefix:  "packs/",
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
	g.inner = gate

	writeFile(t, g.ov, "in-flight.txt", "written before the user typed exit")
	g.startCheckpointer(ctx, 10*time.Millisecond)

	select {
	case <-gate.held:
	case <-time.After(30 * time.Second * raceSlowdown):
		t.Fatal("no checkpoint ever reached the federation; there is nothing in flight to drain")
	}

	// The user exits here, with a checkpoint parked mid-seal.
	g.beginTeardown()
	drained := make(chan struct{})
	go func() {
		g.drainCheckpoints()
		close(drained)
	}()
	const held = 500 * time.Millisecond
	select {
	case <-drained:
		t.Fatal("teardown walked past a checkpoint that was still sealing; the next step closes the overlay")
	case <-time.After(held):
	}
	close(gate.release)
	select {
	case <-drained:
	case <-time.After(60 * time.Second * raceSlowdown):
		t.Fatal("the drain never returned")
	}

	// The generation landed and the ref advanced: the checkpoint ran to
	// completion rather than being abandoned at the stop.
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after the drain: %v", err)
	}
	if f.Superblock.Generation < 1 {
		t.Fatalf("the branch is still at generation %d; the drained checkpoint published nothing",
			f.Superblock.Generation)
	}
	// Following is the second half of a checkpoint — the rebase that drops
	// the redundant overlay rows — and it is the half that was being cut
	// off. If the mount is on the published generation, the whole
	// checkpoint completed, not just its uploads.
	if got := g.gfs.Generation(); got != f.Superblock.Generation {
		t.Errorf("the mount is serving generation %d against a head of %d; the drained checkpoint stopped halfway",
			got, f.Superblock.Generation)
	}
	// And it completed while the overlay was still open, which is the
	// ordering the whole change is about.
	if _, err := g.ov.Stats(); err != nil {
		t.Errorf("the overlay was already unusable when the drain returned: %v", err)
	}
	sealed, err := genfs.Open(ctx, genfs.Options{
		Inner: gate.Store, SB: f.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open the drained checkpoint's generation: %v", err)
	}
	defer sealed.Close() //nolint:errcheck
	if _, err := sealed.Lookup(ctx, genfs.RootInode, "in-flight.txt"); err != nil {
		t.Errorf("the drained checkpoint's generation does not carry the write: %v", err)
	}

	// The wait is attributable: it is its own phase in the teardown line,
	// not time smeared into the seal that follows it.
	d, ok := phaseDuration(g.down, "checkpoint drain")
	if !ok {
		t.Fatalf("the teardown breakdown has no drain phase: %q", g.down.sentence("torn down"))
	}
	if d < held {
		t.Errorf("the drain phase reports %v for a checkpoint held %v; the wait is being charged elsewhere", d, held)
	}
	if s := g.down.sentence("torn down"); !strings.Contains(s, "checkpoint drain {checkpoint drain}") {
		t.Errorf("the teardown line does not name the drain: %s", s)
	}
	t.Logf("teardown line: %s (drain %v)", g.down.sentence("torn down"), d)
}

// The drain is a join, not a delay: a session with nothing in flight
// must pay for it in microseconds, and a session that never started a
// checkpointer must not even name the phase — the teardown line only
// lists phases that actually ran.
func TestCheckpointDrainCostsNothingWithNothingInFlight(t *testing.T) {
	noCheckpointer := newGenSession(t, true)
	noCheckpointer.beginTeardown()
	start := time.Now()
	noCheckpointer.drainCheckpoints()
	if d := time.Since(start); d > time.Second {
		t.Errorf("draining a session that never checkpointed took %v", d)
	}
	if d, ok := phaseDuration(noCheckpointer.down, "checkpoint drain"); ok {
		t.Errorf("a session with no checkpointer reported a drain phase of %v", d)
	}

	// An idle checkpointer: the phase is reported, because one ran, and
	// it costs about nothing, because nothing was sealing.
	idle := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	idle.startCheckpointer(ctx, time.Hour) // never ticks during this test
	idle.beginTeardown()
	start = time.Now()
	idle.drainCheckpoints()
	waited := time.Since(start)
	if waited > checkpointDrainNotice {
		t.Errorf("draining an idle checkpointer took %v, past the point where it announces a wait", waited)
	}
	d, ok := phaseDuration(idle.down, "checkpoint drain")
	if !ok {
		t.Fatalf("a session that ran a checkpointer has no drain phase: %q", idle.down.sentence("torn down"))
	}
	t.Logf("idle drain: %v (phase %v)", waited, d)
}

// The drain and the exit seal must not both publish the same work. When
// the checkpoint that teardown waited for already sealed everything, the
// seal at exit has nothing to do and has to say so — no second
// generation, and the overlay left where the "nothing changed" path
// leaves it rather than retired behind an empty publish.
func TestExitSealAfterACheckpointPublishesNothingNew(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	g.reclaimFn = func(string) {}
	writeFile(t, g.ov, "everything.txt", "the checkpoint published this")
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	checkpointed := f.Superblock.Generation

	g.beginTeardown()
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("sealAtExit after a checkpoint: %v", err)
	}
	f2, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if f2.Superblock.Generation != checkpointed {
		t.Errorf("the exit seal published generation %d over a checkpoint at %d; it double-sealed",
			f2.Superblock.Generation, checkpointed)
	}
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	if sum.Seals != 1 {
		t.Errorf("%d seals recorded; the checkpoint is the only one that had anything to publish", sum.Seals)
	}
	if sum.TeardownPhase.Seals != 0 {
		t.Errorf("teardown recorded %d seals with a clean overlay", sum.TeardownPhase.Seals)
	}
}

// failPutsOn fails every Put whose key starts with a prefix, which is how
// a seal fails in the field: the uplink dies partway through the packs
// (a closed laptop, a reset connection, an origin restart).
type failPutsOn struct {
	pelicanobj.Store
	prefix string
	fail   *atomic.Bool
}

func (f failPutsOn) Put(ctx context.Context, key string, r io.Reader) error {
	if f.fail.Load() && strings.HasPrefix(key, f.prefix) {
		return errors.New("simulated uplink failure")
	}
	return f.Store.Put(ctx, key, r)
}

// Unwrap keeps the transport's capabilities visible through the
// decorator, as countedStore does: refs and the lease probe for them, and
// hiding them would change what the test exercises.
func (f failPutsOn) Unwrap() pelicanobj.Store { return f.Store }

// A seal that cannot reach the federation must lose NOTHING. The exit
// path promises "the overlay is intact at ...; remount to retry", and
// that promise is the only thing standing between a flaky uplink and a
// discarded session — the exact failure a real run hit when a laptop
// closed mid-seal.
//
// So: fail every pack upload, assert the session survives on disk, then
// reopen the overlay the way a remount does and seal it for real.
func TestAFailedSealKeepsTheOverlayAndARemountSealsIt(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	// Captured before anything seals: a successful seal advances g.sb, so
	// comparing against it afterwards compares the new generation with
	// itself.
	startGen := g.sb.Generation
	writeFile(t, g.ov, "survivor.txt", "this must outlive a failed seal")

	good := g.inner
	var failing atomic.Bool
	failing.Store(true)
	g.inner = failPutsOn{Store: good, prefix: "packs/", fail: &failing}

	err := g.sealAtExit(ctx)
	if err == nil {
		t.Fatal("a seal whose pack uploads all failed reported success")
	}
	// The message has to say where the data is. A user who is told only
	// that the seal failed has no reason to believe their work survived.
	if !strings.Contains(err.Error(), g.overlayDir) {
		t.Errorf("the failure does not name the overlay: %v", err)
	}
	if _, serr := os.Stat(g.overlayDir); serr != nil {
		t.Fatalf("a failed seal removed the overlay: %v", serr)
	}
	if g.spent {
		t.Error("a failed seal marked the overlay spent; the next mount would refuse to resume it")
	}
	ents, rerr := os.ReadDir(filepath.Join(g.stateDir, trashDirName))
	if rerr == nil && len(ents) != 0 {
		t.Errorf("a failed seal retired %d overlay(s) into the trash", len(ents))
	}
	// And the head must be unchanged: a generation was never published,
	// so nothing may claim one was.
	rstore, rerr := refs.New(good, t.TempDir(), nil)
	if rerr != nil {
		t.Fatal(rerr)
	}
	f, rerr := rstore.Fetch(ctx, "main")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if f.Superblock.Generation != startGen {
		t.Fatalf("the branch moved to generation %d despite a failed seal", f.Superblock.Generation)
	}

	// The remount: same state directory, same overlay on disk, a working
	// uplink. Closing and reopening is the part that proves the session
	// survived in the FILE rather than in this process's memory.
	g.ovMu.Lock()
	if cerr := g.ov.Close(); cerr != nil {
		g.ovMu.Unlock()
		t.Fatalf("close the overlay: %v", cerr)
	}
	reopened, oerr := overlay.Open(g.overlayDir, g.gfs, overlay.Options{
		NextInode:      g.gfs.NextInode(),
		BaseRoot:       g.gfs.RootCatalog(),
		BaseGeneration: g.gfs.Generation(),
	})
	if oerr != nil {
		g.ovMu.Unlock()
		t.Fatalf("a later mount could not reopen the overlay a failed seal left: %v", oerr)
	}
	g.ov = reopened
	g.ovMu.Unlock()
	t.Cleanup(func() { _ = reopened.Close() })

	st, serr := g.ov.Stats()
	if serr != nil {
		t.Fatal(serr)
	}
	if st.DirtyNodes == 0 && st.DirtyEdges == 0 {
		t.Fatal("the reopened overlay reports nothing to seal; the session was lost")
	}

	failing.Store(false)
	g.inner = good
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("the retry seal failed: %v", err)
	}

	// The file is in the published generation, which is the whole claim.
	f2, rerr := rstore.Fetch(ctx, "main")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if f2.Superblock.Generation <= startGen {
		t.Fatalf("the retry published generation %d, which does not follow %d", f2.Superblock.Generation, startGen)
	}
	sealed, gerr := genfs.Open(ctx, genfs.Options{
		Inner: good, SB: f2.Superblock, CacheDir: filepath.Join(g.stateDir, "gencache-retry"),
	})
	if gerr != nil {
		t.Fatalf("open the retried generation: %v", gerr)
	}
	defer sealed.Close() //nolint:errcheck
	if _, lerr := sealed.Lookup(ctx, overlay.RootInode, "survivor.txt"); lerr != nil {
		t.Fatalf("the file written before the failed seal is not in the retried generation: %v", lerr)
	}
	t.Logf("failed seal kept %d dirty nodes; the retry published generation %d",
		st.DirtyNodes, f2.Superblock.Generation)
}

// Automatic repacking, from the mount that hosts it.
//
// The property being gated is not "a repack happened" — internal/repack
// covers that — but that a LIVE MOUNT survives one. It runs while the
// session is serving, the head moves under it, and the session has to
// follow so that its own seal at unmount is still built on the right
// parent. A mount that repacked and then failed its final seal would
// have traded storage for the user's work.
func TestAutoRepackRunsUnderALiveMountAndTheSessionFollows(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()

	// Two generations with content that mostly dies: enough for the
	// planner to have something to condemn.
	for i := range 4 {
		writeFile(t, g.ov, fmt.Sprintf("f%d.bin", i), string(incompressible(1<<20, int64(i))))
	}
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	for i := 1; i < 4; i++ {
		n, err := g.ov.Lookup(ctx, overlay.RootInode, fmt.Sprintf("f%d.bin", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.ov.Write(ctx, n.Inode, 0, incompressible(1<<20, int64(100+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("second checkpoint: %v", err)
	}
	before := g.sb.Generation

	// Packs: 1 forces the cheap gate open; the clock is moved past the
	// grace window, which no real deployment can do and every test must.
	_, err := g.autoRepackOnce(ctx, repack.AutoPolicy{Packs: 1, Now: time.Now().Add(200 * time.Hour)})
	if err != nil {
		t.Fatalf("autoRepackOnce: %v", err)
	}
	if g.sb.Generation <= before {
		t.Fatalf("the session is still on generation %d; either nothing was repacked or it did not follow",
			g.sb.Generation)
	}
	if g.sb.Maint == nil {
		t.Error("the session followed onto a generation with no maintenance state")
	}
	// The namespace is untouched, which is what makes following cheap: no
	// rebase, no inode invalidation, nothing to tell the kernel.
	if _, err := g.ov.Lookup(ctx, overlay.RootInode, "f0.bin"); err != nil {
		t.Fatalf("the tree is not readable through the overlay after a repack: %v", err)
	}

	// The whole point of following: the session can still seal its own
	// work onto the branch the repack moved.
	writeFile(t, g.ov, "after.txt", "written after the repack")
	if err := g.sealAtExit(ctx); err != nil {
		t.Fatalf("the seal at unmount was refused after an automatic repack: %v", err)
	}
	f, err := g.refs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := genfs.Open(ctx, genfs.Options{
		Inner: g.inner, SB: f.Superblock, CacheDir: filepath.Join(g.stateDir, "gencache-final"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close() //nolint:errcheck
	if _, err := sealed.Lookup(ctx, overlay.RootInode, "after.txt"); err != nil {
		t.Errorf("work written after the repack is not in the sealed generation: %v", err)
	}
	if _, err := sealed.Lookup(ctx, overlay.RootInode, "f0.bin"); err != nil {
		t.Errorf("content that survived the repack is missing from the sealed generation: %v", err)
	}
	t.Logf("repacked to generation %d under a live mount, then sealed to %d",
		g.sb.Generation, f.Superblock.Generation)
}

// The cheap gate must keep a quiet, small volume from ever paying for a
// sweep: that is the whole reason it exists.
func TestAutoRepackDoesNothingOnASmallVolume(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "small.txt", "not much here")
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	before := g.sb.Generation
	if _, err := g.autoRepackOnce(ctx, repack.AutoPolicy{}); err != nil {
		t.Fatalf("autoRepackOnce: %v", err)
	}
	if g.sb.Generation != before {
		t.Fatalf("a small volume was repacked anyway: generation %d, was %d", g.sb.Generation, before)
	}
}

// incompressible content, so that stored bytes track logical bytes and a
// rewritten file really does strand the pack its old chunks sat in. A
// compressible fixture packs four files into almost nothing and leaves
// every pack comfortably live, which is a fixture that tests the planner
// rather than the repack.
func incompressible(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// TestCheckpointTriggersCoverBothMeters pins the rule a metadata-heavy
// session depends on: bytes are not the only pressure. A tree of small
// files can dirty hundreds of thousands of inodes without ever staging a
// gigabyte, and until the inode meter existed nothing but the clock
// published it — while per-inode session state (overlay modSeq and dirty
// set, provenance, residency, the location map, the seal's edge map;
// ~600 B/file measured) grew the whole time.
func TestCheckpointTriggersCoverBothMeters(t *testing.T) {
	cases := []struct {
		what   string
		staged int64
		nodes  int
		want   bool
	}{
		{what: "an idle session", staged: 0, nodes: 0, want: false},
		{what: "bytes alone", staged: checkpointBytes, nodes: 12, want: true},
		{what: "inodes alone", staged: 4 << 10, nodes: checkpointInodes, want: true},
		{what: "just under both", staged: checkpointBytes - 1, nodes: checkpointInodes - 1, want: false},
		// The unsampled overlay reports -1 for both, which must never read
		// as pressure.
		{what: "an overlay being sealed", staged: -1, nodes: -1, want: false},
		// The workload the byte and time triggers already handle well: a
		// kernel-tree extraction. It must NOT start checkpointing on the
		// inode meter, or this trigger has made those sessions slower.
		{what: "a 90k-file source tree", staged: 400 << 20, nodes: 90_000, want: false},
	}
	for _, c := range cases {
		if got := checkpointDue(c.staged, c.nodes); got != c.want {
			t.Errorf("%s (%d bytes, %d inodes): checkpointDue = %v, want %v",
				c.what, c.staged, c.nodes, got, c.want)
		}
	}
}

// TestSessionStatsCarryTheWritePath is the monitoring claim behind C5:
// the write path's counters have to be readable from a RUNNING mount.
// Every one of them was already being kept, and Store.Stats had exactly
// one caller reading exactly one field — so from outside the process a
// session pacing its writes against a slow uplink and a session that had
// hung produced the same observation, which is none.
func TestSessionStatsCarryTheWritePath(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	store, err := g.openContent(ctx, false)
	if err != nil {
		t.Fatalf("openContent: %v", err)
	}
	t.Cleanup(func() { _ = g.closeContent() })
	c := serve(t, g)

	body := bytes.Repeat([]byte("write path visibility"), 4096)
	for ino := uint64(100); ino < 110; ino++ {
		if err := store.Write(ctx, ino, 0, body); err != nil {
			t.Fatalf("write inode %d: %v", ino, err)
		}
	}

	raw, err := c.Do(ctx, "GET", "/v1/stats")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	var sum stats.Summary
	if err := json.Unmarshal(raw, &sum); err != nil {
		t.Fatalf("stats body %s: %v", raw, err)
	}
	if sum.Write == nil {
		t.Fatal("a writable session with a live content store reported no write-path statistics")
	}
	// The ring is the leading indicator: a mount whose free space is
	// falling is a mount that is about to block, and that has to be
	// visible BEFORE the blocked writes are.
	if sum.Write.RingUsed < int64(len(body)) {
		t.Errorf("ring reports %d bytes used after writing %d", sum.Write.RingUsed, 10*len(body))
	}
	if sum.Write.RingFree <= 0 {
		t.Errorf("ring reports %d bytes free; the write buffer is not being read", sum.Write.RingFree)
	}
	// And the whole set agrees with the store it came from, which is what
	// makes the counter a blocked write increments (memtable, tested
	// there) reachable through this document.
	st := store.Stats()
	if sum.Write.BlockedWrites != st.BlockedWrites ||
		sum.Write.UploadBacklog != st.UploadBacklog ||
		sum.Write.Packs != st.Packs ||
		sum.Write.UploadedChunks != st.UploadedChunks {
		t.Errorf("published write statistics disagree with the store: %+v vs %+v", sum.Write, st)
	}
}

// A background repack has already paid for a whole reachability sweep and
// a rewrite by the time it flips, so a periodic checkpoint landing in the
// middle costs the repack ALL of it — the repack refuses on a moved head
// — while costing itself one interval. The periodic checkpoint therefore
// gives way.
//
// Both directions are asserted, because a guard that never lifts is the
// same bug from the other side: a mount that stopped checkpointing would
// hand its whole session to the seal at unmount.
func TestPeriodicCheckpointStandsAsideForARepack(t *testing.T) {
	g := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, g.ov, "during-repack.txt", "written while a repack is in flight")

	g.mu.Lock()
	g.repacking = true
	g.mu.Unlock()
	go g.checkpointPeriodically(ctx, 10*time.Millisecond)

	// Many intervals' worth. The overlay is dirty the whole time, so
	// without the guard this publishes almost immediately.
	time.Sleep(300 * time.Millisecond)
	if f, err := rstore.Fetch(ctx, "main"); err == nil && f.Superblock.Generation > 0 {
		t.Fatalf("a checkpoint published generation %d while a repack was in flight",
			f.Superblock.Generation)
	}

	// And it resumes: the guard is a pause, not a stop.
	g.mu.Lock()
	g.repacking = false
	g.mu.Unlock()
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := rstore.Fetch(ctx, "main")
		if err == nil && f.Superblock.Generation >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("checkpointing never resumed after the repack finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The reentrancy half: a second attempt while one is in flight does
// nothing rather than racing it.
func TestAutoRepackDoesNotRunTwiceAtOnce(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "f.bin", string(incompressible(1<<20, 7)))
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	before := g.sb.Generation

	g.mu.Lock()
	g.repacking = true
	g.mu.Unlock()
	// Thresholds that would certainly trigger, so only the in-flight guard
	// can be what stops it.
	if _, err := g.autoRepackOnce(ctx, repack.AutoPolicy{Packs: 1, Now: time.Now().Add(200 * time.Hour)}); err != nil {
		t.Fatalf("autoRepackOnce: %v", err)
	}
	if g.sb.Generation != before {
		t.Fatalf("a second repack ran while one was in flight: generation %d, was %d",
			g.sb.Generation, before)
	}
}

// A volume's identity is a property of the VOLUME, not of the command
// that happens to be running, so init, the seal at unmount, a checkpoint
// and a background repack must all resolve the key to the same file. Two
// resolvers that disagreed would mint a second identity and publish a
// generation every existing reader rejects.
func TestEveryPathThatSignsResolvesTheSameKey(t *testing.T) {
	g := newGenSession(t, true)
	const override = "/imported/from/the/other/machine.key"

	if got, want := g.signingKeyFile(), filepath.Join(g.stateDir, "v2-signing.key"); got != want {
		t.Errorf("default key path = %q, want %q", got, want)
	}
	if got := signingKeyFileIn(g.stateDir, ""); got != g.signingKeyFile() {
		t.Errorf("init resolves %q, the session resolves %q", got, g.signingKeyFile())
	}

	g.signingKeyPath = override
	if got := g.signingKeyFile(); got != override {
		t.Errorf("--signing-key ignored by the session: %q", got)
	}
	if got := signingKeyFileIn(g.stateDir, override); got != override {
		t.Errorf("--signing-key ignored at volume creation: %q", got)
	}
}
