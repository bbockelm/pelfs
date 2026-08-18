package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
)

// newGenSession builds a real phase-3 session over a fakeorigin-backed
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
		sb:         f.Superblock,
		prevRaw:    f.Raw,
	}
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
		t.Errorf("stats did not carry the phase-3 facts: %+v", sum)
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
	// observable: the point of the change is that retirement itself does
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

	deadline := time.Now().Add(60 * time.Second)
	for {
		f, err := rstore.Fetch(ctx, "main")
		if err == nil && f.Superblock.Generation >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("staged %d bytes without a checkpoint; only the hour-long timer could publish it",
				g.stagedBytes())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
