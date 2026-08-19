package main

import (
	"context"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// planVolume publishes a small volume behind a fakeorigin server and
// returns the prefix URL a command would be given, the store, the
// published head, and the on-disk volume directory.
func planVolume(t *testing.T) (string, pelicanobj.Store, *superblock.Superblock, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	v := testvol.New(t, inner, testvol.Options{})
	body := make([]byte, 2<<20)
	mrand.New(mrand.NewSource(11)).Read(body)
	v.WriteFile(1, "f.bin", body)
	res := v.Publish(publish.Options{SMax: 1000, TargetPackSize: 2 << 20})
	return prefix, inner, res.Superblock, filepath.Join(root, "vol")
}

// capture runs fn with stdout redirected and returns what it printed.
func capture(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	code := fn()
	os.Stdout = saved
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out), code
}

// The command's wiring: it must find the branch head and every tag, sweep
// them, and print a plan with the numbers behind it. Everything this
// fixture writes is seconds old, so the age guard alone guarantees the
// healthy answer — which is the answer that has to work.
func TestRepackPlanReportsAHealthyVolume(t *testing.T) {
	prefix, _, _, _ := planVolume(t)
	out, code := capture(t, func() int {
		return cmdRepackPlan([]string{"--state-dir", t.TempDir(), prefix})
	})
	t.Log("\n" + out)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "nothing to do") {
		t.Fatalf("a healthy volume did not report an empty plan:\n%s", out)
	}
	if !strings.Contains(out, "grace window") || !strings.Contains(out, "packs:") {
		t.Fatalf("the report is missing the numbers behind the decision:\n%s", out)
	}
}

// The printer is what an operator actually reads, and the numbers it must
// never drop are the two that make a plan refusable: what it reclaims and
// what it moves to get there. Driven from a plan built by hand, since the
// clock a real one needs is not a flag.
func TestPrintPlanShowsTheTrade(t *testing.T) {
	p := &repack.Plan{
		Generations: 2, ScannedPacks: 9, Bytes: 40 << 20, LiveBytes: 8 << 20, Grace: 72 * time.Hour,
		IntoPacks:         1,
		SkippedYoung:      1,
		SkippedYoungNames: []string{"p-18cd33f3915cf5c8-59fc"},
		Packs: []repack.PackCandidate{
			{Name: "p-18cd33ee4a697448-f53d", Size: 2 << 20, Bytes: 2 << 20, LiveFraction: 0, Move: 0, Reclaim: 2 << 20},
			{Name: "p-18cd33ee4ab64840-743e", Size: 4 << 20, Bytes: 4 << 20, LiveBytes: 1 << 20, LiveFraction: 0.25, Move: 1 << 20, Reclaim: 3 << 20},
		},
		Refs: []repack.RefCandidate{
			{Kind: repack.RefManifest, Name: "279b2773", Size: 1952, Packs: 26, LivePacks: 10, CondemnedPacks: 16,
				LiveFraction: 10.0 / 26, Move: 1952, Reclaim: 1201},
		},
	}
	out, _ := capture(t, func() int { printPlan(p, 0.5); return 0 })
	t.Log("\n" + out)
	for _, want := range []string{
		"repack 2 packs", "retire 1 ref", "manifest 279b2773", "10/26 packs live",
		"move 1.0 MiB into 1 pack to reclaim 5.0 MiB", "total: move 1.0 MiB to reclaim 5.0 MiB",
		"held back", "only plans",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

// A sweep that cannot read a catalog must produce no plan and say so, and
// the command must exit non-zero: "nothing could be decided" is not the
// same answer as "nothing to do", and a script has to be able to tell
// them apart.
func TestRepackPlanRefusesAnIncompleteSweep(t *testing.T) {
	prefix, inner, head, volDir := planVolume(t)
	ctx := context.Background()

	// Scribble over every catalog entry in every pack. The trailers are
	// untouched, so the packs still index and the sweep can still see the
	// entries; what fails is the decode, which is exactly the failure that
	// makes a liveness measurement impossible.
	packs, err := manifest.Packs(ctx, inner, head)
	if err != nil {
		t.Fatal(err)
	}
	var damaged int
	for _, pe := range packs {
		entries, err := packstore.FetchTrailer(ctx, inner, pe.Name, pe.Size)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Type != packstore.EntryCatalog {
				continue
			}
			f, err := os.OpenFile(filepath.Join(volDir, packstore.PackDirKey, pe.Name), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			noise := make([]byte, e.Length)
			mrand.New(mrand.NewSource(3)).Read(noise)
			_, werr := f.WriteAt(noise, e.Off)
			_ = f.Close()
			if werr != nil {
				t.Fatal(werr)
			}
			damaged++
		}
	}
	if damaged == 0 {
		t.Fatal("no catalog entry was damaged; the test would prove nothing")
	}

	out, code := capture(t, func() int {
		return cmdRepackPlan([]string{"--state-dir", t.TempDir(), prefix})
	})
	t.Log("\n" + out)
	if code == 0 {
		t.Fatal("a sweep that could not read the volume exited 0")
	}
	if strings.Contains(out, "repack ") || strings.Contains(out, "retire ") || strings.Contains(out, "nothing to do") {
		t.Fatalf("a refused run printed a plan:\n%s", out)
	}
}
