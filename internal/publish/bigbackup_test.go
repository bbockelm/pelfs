package publish_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// INVARIANT: the superblock write budget governs the objects that are read
// through the mutable-object cap, and nothing else.
//
// THE INTERACTION THIS EXISTS FOR, because both halves of it were right on
// their own. The size guard refuses to flip a superblock past half the 1
// MiB ceiling that pelicanobj.ReadMutable enforces, and it was applied to
// every superblock a seal built. Separately, the disaster-recovery backup
// stopped buying a manifest segment of its own and started stating its
// packs INLINE — which is sound, because nothing mounts a backup and a
// rescue reads its pack set as the union of that list and the carried refs.
//
// Together they refused a first ingest of about 12 GB. The backup grows at
// ~90 bytes per pack while the head, which states its packs through
// manifest refs, stays near a kilobyte forever: at ~6,000 packs the backup
// crosses the budget and the seal fails, with a message naming a pack list
// that is not in the document anyone reads. The head in this test is three
// figures of bytes while the backup is over the budget that was refusing
// it.
//
// The backup is not read through ReadMutable at all — it is an entry inside
// a pack, reached by a trailer and a ranged read, with no cap on the path.
// So the check belongs on the document that gets flipped.
func TestASealOfManyPacksSucceedsAndItsBackupIsStillReadable(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	v := testvol.New(t, inner, testvol.Options{VolumeID: id})

	// A tiny cut, so the pack count this needs costs megabytes rather than
	// the ~12 GB the same count costs at the default 2 MiB target. What is
	// being tested is what a pack COUNT does to the two documents, and the
	// cut size is only how the count is reached.
	const files = 6200
	for i := range files {
		v.WriteFile(testvol.RootInode, fmt.Sprintf("f%05d.bin", i), pseudorandom(600, int64(i)))
	}
	res := v.Publish(publish.Options{TargetPackSize: 512, SMax: 100000, InlineMax: 1})

	if len(res.NewPacks) < 6000 {
		t.Fatalf("fixture: the seal cut %d packs, and the interaction only appears past about 6,000",
			len(res.NewPacks))
	}
	// The head is nowhere near the budget and never will be: it states its
	// packs through manifest refs.
	if err := res.Superblock.CheckSize(len(res.Raw)); err != nil {
		t.Fatalf("the flipped head is over budget: %v", err)
	}
	if len(res.Superblock.PackList) != 0 {
		t.Fatalf("the head states %d packs inline; it should state them through its %d manifest ref(s)",
			len(res.Superblock.PackList), len(res.Superblock.Manifests))
	}

	// The backup: bigger than the budget that was refusing this seal, which
	// is the whole point, and still readable the way a rescue reads it.
	backup := backupFromPacks(t, inner, res)
	raw, err := backup.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) <= superblock.MaxEncodedBytes {
		t.Fatalf("fixture: the backup encodes to %d bytes, inside the %d-byte budget — this seal would "+
			"have succeeded under the old rule too, so it proves nothing",
			len(raw), int64(superblock.MaxEncodedBytes))
	}
	t.Logf("head %d bytes through %d manifest ref(s); backup %d bytes naming %d packs inline",
		len(res.Raw), len(res.Superblock.Manifests), len(raw), len(backup.PackList))

	// And it says what a rescue needs it to say: the generation MINUS ITS
	// TAIL, which has always been the contract. The tail is the pack still
	// open when the backup was built — sealedSoFar names only packs already
	// cut — plus the pack the backup itself lands in, which at this cut size
	// is one of its own.
	named := map[string]bool{}
	for _, pe := range backup.PackList {
		named[pe.Name] = true
	}
	const tail = 2
	missing := 0
	for _, sp := range res.NewPacks[:len(res.NewPacks)-tail] {
		if !named[sp.Name] {
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("the backup does not name %d of the %d packs sealed before its tail; a rescue from it "+
			"recovers less than the generation minus that tail", missing, len(res.NewPacks)-tail)
	}

	// Cold, byte-exact, through the generation that was published: the seal
	// that now succeeds also has to be correct.
	fs := openCold(t, inner, res.Superblock)
	defer fs.Close() //nolint:errcheck
	for _, i := range []int{0, files / 2, files - 1} {
		name := fmt.Sprintf("f%05d.bin", i)
		n, err := fs.Lookup(ctx, testvol.RootInode, name)
		if err != nil {
			t.Fatalf("%s is gone: %v", name, err)
		}
		want := pseudorandom(600, int64(i))
		got := make([]byte, len(want))
		if _, err := fs.Read(ctx, n.Inode, 0, got); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("%s differs at byte %d", name, j)
			}
		}
	}
}

// backupFromPacks digs the disaster-recovery superblock out of the pack
// that carries it, which is the only way a rescue can get at it: no ref, no
// manifest, just a trailer and a ranged read.
func backupFromPacks(t *testing.T, inner pelicanobj.Store, res *publish.Result) *superblock.Superblock {
	t.Helper()
	ctx := context.Background()
	// Backwards: the backup rides in one of the last packs the seal cut.
	for i := len(res.NewPacks) - 1; i >= 0; i-- {
		sp := res.NewPacks[i]
		entries, err := packstore.FetchTrailer(ctx, inner, sp.Name, sp.Size)
		if err != nil {
			t.Fatalf("trailer of %s: %v", sp.Name, err)
		}
		for _, e := range entries {
			if e.Type != packstore.EntrySuperblock {
				continue
			}
			rc, err := inner.Get(ctx, packstore.PackDirKey+"/"+sp.Name, e.Off, e.Length)
			if err != nil {
				t.Fatalf("read the backup out of %s: %v", sp.Name, err)
			}
			raw, err := io.ReadAll(rc)
			rc.Close() //nolint:errcheck
			if err != nil {
				t.Fatalf("read the backup out of %s: %v", sp.Name, err)
			}
			sb, err := superblock.Decode(raw)
			if err != nil {
				t.Fatalf("decode the backup in %s: %v", sp.Name, err)
			}
			return sb
		}
	}
	t.Fatal("no superblock backup rode in any pack this seal wrote")
	return nil
}

// openCold mounts a generation with an empty cache, so every catalog and
// every pack comes out of the store through what the superblock names.
func openCold(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock) *genfs.FS {
	t.Helper()
	fs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: sb, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open generation %d cold: %v", sb.Generation, err)
	}
	return fs
}
