package repack_test

// A repack's scratch, and what it leaves behind.
//
// A repack spools the packs it rewrites onto local disk before it uploads
// them, which for the volumes worth repacking is gigabytes. The cleanup
// used to fire only when Execute had made the directory itself — a caller
// that supplied one got no cleanup at all, and both callers in this repo
// supply one, so every automatic repack stranded its spool in the state
// directory forever.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/scratch"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// sharedPackVolume builds a volume whose packs are PARTLY live: sixteen
// small files share a handful of packs and twelve of them are rewritten,
// so every candidate pack keeps a survivor that the repack has to read
// out and spool into a new one.
func sharedPackVolume(t *testing.T, uuid string) (pelicanobj.Store, *testvol.Volume, *superblock.Superblock) {
	t.Helper()
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	const files = 16
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("s%02d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(256<<10, int64(400+i)))
	}
	v.Publish(publishOpts)
	for i := range files {
		if i%4 == 0 {
			continue
		}
		v.Write(v.Lookup(rootIno, names[i]), pseudorandom(256<<10, int64(500+i)))
	}
	return inner, v, v.Publish(publishOpts).Superblock
}

// leftBehind lists what is still in a spool parent, so a failure names the
// directory rather than only counting it.
func leftBehind(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the spool parent: %v", err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// THE HAPPY PATH: a repack that publishes a generation removes its own
// scratch. The caller supplies the spool parent — a state directory — and
// gets it back empty.
func TestARepackRemovesItsSpoolWhenItSucceeds(t *testing.T) {
	// Small files sharing packs, so the packs this run condemns are PARTLY
	// live and their survivors are really written out to the spool. A
	// fixture of whole-pack-sized files would condemn without spooling a
	// byte, and would prove nothing about cleaning up after itself.
	inner, v, head := sharedPackVolume(t, "5c0117e0-1111-2222-3333-444444444444")
	ctx := context.Background()
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(),
		SpoolDir: stateDir,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res.NewPacks) == 0 {
		t.Fatal("this fixture is meant to rewrite packs; nothing was spooled, so nothing is proven")
	}
	if got := leftBehind(t, stateDir); len(got) != 0 {
		t.Fatalf("a repack that succeeded left %v in the state directory; those are the rewritten "+
			"packs, and nothing else ever deletes them", got)
	}
}

// THE UNHAPPY PATH, which is the shape a leak actually takes: the run
// spools its packs, writes them out, and then fails. The FLIP is faulted
// here rather than the upload, so the failure lands after the scratch
// directory has been created and filled — and it is the cheap fault to
// stage, since a faulted pack upload spends the uploader's whole retry
// schedule before it gives up.
func TestARepackRemovesItsSpoolWhenItFails(t *testing.T) {
	inner, v, head := sharedPackVolume(t, "5c0117e0-2222-2222-3333-444444444444")
	ctx := context.Background()
	broken := &faultStore{Store: inner, failPrefix: "refs/"}
	rstore, err := refs.New(broken, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	_, err = repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: broken, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(),
		SpoolDir: stateDir,
	})
	if err == nil {
		t.Fatal("a repack whose flip could not be written reported success")
	}
	if got := leftBehind(t, stateDir); len(got) != 0 {
		t.Fatalf("a repack that failed after spooling left %v behind; an operation that fails is the one "+
			"most likely to be retried, and every retry would strand another spool", got)
	}
}

// The scratch a repack makes is named the way every other family is, so
// that the sweep which collects a crashed run's spool can attribute this
// one too. Asserted through the naming rule rather than by catching the
// directory mid-run, which would be a race.
func TestARepackSpoolIsAttributableToTheProcessThatMadeIt(t *testing.T) {
	dir, err := scratch.Make(t.TempDir(), scratch.Repack)
	if err != nil {
		t.Fatal(err)
	}
	pid, owned := scratch.Owner(filepath.Base(dir))
	if !owned || pid != os.Getpid() {
		t.Fatalf("a repack spool named %q is owned by %d/%v, want this process", filepath.Base(dir), pid, owned)
	}
}
