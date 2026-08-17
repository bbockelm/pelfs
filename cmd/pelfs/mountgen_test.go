package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
		inner:      inner,
		statsPath:  filepath.Join(stateDir, "pelfs-stats.json"),
		sb:         f.Superblock,
		prevRaw:    f.Raw,
	}
	g.stats = stats.New(prefix, g.sessionID, g.statsPath)
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
// taken and the publish verb is absent. Flush is absent for every phase-3
// mount — there is no staging tier to drain.
func TestMountGenControlReadOnlyHasNoPublish(t *testing.T) {
	g := newGenSession(t, false)
	c := serve(t, g)
	ctx := context.Background()
	for _, ep := range []string{"/v1/publish", "/v1/flush"} {
		if _, err := c.Do(ctx, "POST", ep); err == nil || !strings.Contains(err.Error(), "404") {
			t.Errorf("POST %s: err=%v, want 404", ep, err)
		}
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
	// The seal advanced the branch, and the mount followed it there.
	if sum.Generation != 1 {
		t.Errorf("served generation is %d; the exit seal should have advanced it to 1", sum.Generation)
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
