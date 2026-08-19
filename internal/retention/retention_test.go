package retention

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// newInner returns a store over a fake origin and the directory backing
// it — the derived key spaces are aged with os.Chtimes, which needs the
// files themselves.
func newInner(t *testing.T) (pelicanobj.Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner, root
}

// hashName fabricates a name shaped like the content hashes publish gives
// index and manifest objects.
func hashName(c byte) string { return strings.Repeat(string(c), 64) }

func putObj(t *testing.T, inner pelicanobj.Store, key string, size int) {
	t.Helper()
	if err := inner.Put(context.Background(), key, strings.NewReader(strings.Repeat("x", size))); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

// age backdates an object's mtime, which is the only clock a hash-named
// object has.
func age(t *testing.T, root, key string, when time.Time) {
	t.Helper()
	p := filepath.Join(root, "vol", filepath.FromSlash(key))
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", key, err)
	}
}

func alive(t *testing.T, inner pelicanobj.Store, key string) bool {
	t.Helper()
	_, err := inner.StatKey(context.Background(), key)
	return err == nil
}

// packName fabricates a pack name whose embedded timestamp is at t0.
func packName(t0 time.Time, suffix string) string {
	return fmt.Sprintf("p-%016x-%s", t0.UnixNano(), suffix)
}

func putPack(t *testing.T, inner pelicanobj.Store, name string, size int) {
	t.Helper()
	if err := inner.Put(context.Background(), packstore.PackDirKey+"/"+name,
		strings.NewReader(strings.Repeat("x", size))); err != nil {
		t.Fatalf("put pack %s: %v", name, err)
	}
}

func publishHead(t *testing.T, rs *refs.Store, priv ed25519.PrivateKey, gen uint64, prevRaw []byte,
	etag string, packs []string, condemned []superblock.CondemnedPack, indexes ...string) []byte {
	t.Helper()
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      gen,
		CreatedUnixNano: int64(gen + 1),
	}
	if prevRaw != nil {
		sb.PrevHash = superblock.Hash(prevRaw)
	}
	for _, p := range packs {
		sb.PackList = append(sb.PackList, superblock.PackEntry{Name: p, Size: 1})
	}
	for _, ix := range indexes {
		sb.PackIndexes = append(sb.PackIndexes, superblock.IndexRef{Name: ix, Size: 1, Entries: 1, Packs: 1})
	}
	sb.Condemned = condemned
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(context.Background(), "main", raw, etag); err != nil {
		t.Fatalf("flip gen %d: %v", gen, err)
	}
	return raw
}

func TestGCSetArithmetic(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	old := now.Add(-100 * time.Hour) // past the 72h default grace
	young := now.Add(-1 * time.Hour)

	live := packName(old, "aaaa")             // old but referenced -> kept
	garbageOld := packName(old, "bbbb")       // old, unreferenced -> deleted
	garbageYoung := packName(young, "cccc")   // young, unreferenced -> kept (age guard)
	condemnedNew := packName(old, "dddd")     // old, unreferenced, condemned recently -> kept
	condemnedStale := packName(old, "eeee")   // old, unreferenced, condemned long ago -> deleted
	unparseable := "p-zzzznotatimestamp-ffff" // unaged -> kept forever

	for _, n := range []string{live, garbageOld, garbageYoung, condemnedNew, condemnedStale, unparseable} {
		putPack(t, inner, n, 100)
	}
	publishHead(t, rs, priv, 0, nil, "", []string{live}, []superblock.CondemnedPack{
		{Name: condemnedNew, CondemnedAtUnix: now.Add(-1 * time.Hour).Unix()},
		{Name: condemnedStale, CondemnedAtUnix: now.Add(-200 * time.Hour).Unix()},
	})

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Deleted != 2 {
		t.Fatalf("deleted %d packs (%v), want 2", rep.Deleted, rep.CandidateNames)
	}
	for _, want := range []struct {
		name  string
		alive bool
	}{
		{live, true}, {garbageOld, false}, {garbageYoung, true},
		{condemnedNew, true}, {condemnedStale, false}, {unparseable, true},
	} {
		_, err := inner.StatKey(ctx, packstore.PackDirKey+"/"+want.name)
		if alive := err == nil; alive != want.alive {
			t.Errorf("pack %s: alive=%v, want %v", want.name, alive, want.alive)
		}
	}
	if rep.SkippedYoung != 2 { // garbageYoung + unparseable
		t.Errorf("SkippedYoung = %d, want 2", rep.SkippedYoung)
	}
}

func TestGCFailsClosedOnUnverifiableRef(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	_, evilPriv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	garbage := packName(now.Add(-100*time.Hour), "aaaa")
	putPack(t, inner, garbage, 100)
	raw0 := publishHead(t, rs, priv, 0, nil, "", nil, nil)
	if _, err := rs.Fetch(ctx, "main"); err != nil { // pin the good key
		t.Fatal(err)
	}

	// A second branch signed by a different key cannot be verified.
	evil := &superblock.Superblock{FormatVersion: superblock.FormatV2, Generation: 3, CreatedUnixNano: 9}
	if err := evil.Sign(evilPriv); err != nil {
		t.Fatal(err)
	}
	evilRaw, _ := evil.Encode()
	if err := rs.Flip(ctx, "scratch", evilRaw, ""); err != nil {
		t.Fatal(err)
	}
	_ = raw0

	if _, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now}); err == nil {
		t.Fatal("GC proceeded with an unverifiable branch present")
	}
	if _, err := inner.StatKey(ctx, packstore.PackDirKey+"/"+garbage); err != nil {
		t.Fatal("fail-closed GC deleted a pack anyway")
	}
}

func TestGCRefusesEmptyNamespace(t *testing.T) {
	inner, _ := newInner(t)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	old := packName(time.Now().Add(-100*time.Hour), "aaaa")
	putPack(t, inner, old, 100)
	if _, err := GC(context.Background(), Options{Inner: inner, Refs: rs, Delete: true}); err == nil {
		t.Fatal("GC with no refs/tags did not refuse to run")
	}
}

func TestGCTagRetains(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-100 * time.Hour)
	tagged := packName(old, "aaaa")
	dropped := packName(old, "bbbb")
	putPack(t, inner, tagged, 100)
	putPack(t, inner, dropped, 100)

	// Gen 0 references both and is tagged; gen 1 (the head) references
	// neither. The tag alone must keep its pack set alive.
	raw0 := publishHead(t, rs, priv, 0, nil, "", []string{tagged, dropped}, nil)
	f0, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Tag(ctx, "keep", raw0); err != nil {
		t.Fatal(err)
	}
	// Head drops both; "dropped" is not in the tag either... it IS in the
	// tag (gen 0 lists both). To exercise deletion alongside a tag, add a
	// third pack no generation references.
	loose := packName(old, "cccc")
	putPack(t, inner, loose, 100)
	publishHead(t, rs, priv, 1, raw0, f0.ETag, nil, nil)

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Deleted != 1 {
		t.Fatalf("deleted %d, want 1 (only the loose pack): %v", rep.Deleted, rep.CandidateNames)
	}
	if _, err := inner.StatKey(ctx, packstore.PackDirKey+"/"+tagged); err != nil {
		t.Fatal("tag-retained pack was deleted")
	}
	if _, err := inner.StatKey(ctx, packstore.PackDirKey+"/"+loose); err == nil {
		t.Fatal("loose pack survived")
	}
}

// TestGCSweepsIndexes covers the four cases the index sweep turns on: the
// head's index, an index only a RETAINED generation still names (the head
// has consolidated past it), an orphan past the grace window, and an
// orphan inside it — the shape a publish leaves between uploading its
// index and flipping the ref.
func TestGCSweepsIndexes(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-100 * time.Hour) // past the 72h default grace

	ixHead := hashName('a')    // named by the head -> kept
	ixTagged := hashName('b')  // named only by the tagged generation -> kept
	ixOrphan := hashName('c')  // named by nothing, old -> deleted
	ixPending := hashName('d') // named by nothing, young -> kept
	for _, n := range []string{ixHead, ixTagged, ixOrphan, ixPending} {
		putObj(t, inner, mpi.Dir+"/"+n, 64)
	}
	// Everything but the pending index predates the window; ixHead and
	// ixTagged are old too, so only liveness can be saving them.
	for _, n := range []string{ixHead, ixTagged, ixOrphan} {
		age(t, root, mpi.Dir+"/"+n, old)
	}

	raw0 := publishHead(t, rs, priv, 0, nil, "", nil, nil, ixTagged)
	f0, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Tag(ctx, "keep", raw0); err != nil {
		t.Fatal(err)
	}
	// Gen 1 consolidated: it names its own index and no longer carries
	// gen 0's forward. The tag is all that keeps ixTagged alive.
	publishHead(t, rs, priv, 1, raw0, f0.ETag, nil, nil, ixHead)

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, want := range []struct {
		name string
		live bool
	}{{ixHead, true}, {ixTagged, true}, {ixOrphan, false}, {ixPending, true}} {
		if got := alive(t, inner, mpi.Dir+"/"+want.name); got != want.live {
			t.Errorf("index %s...: alive=%v, want %v", want.name[:8], got, want.live)
		}
	}
	if rep.Indexes.Deleted != 1 || rep.Indexes.Candidates != 1 {
		t.Errorf("Indexes = %+v, want exactly one candidate deleted", rep.Indexes)
	}
	if rep.Indexes.Retained != 2 || rep.Indexes.Scanned != 4 || rep.Indexes.SkippedYoung != 1 {
		t.Errorf("Indexes = %+v, want Retained=2 Scanned=4 SkippedYoung=1", rep.Indexes)
	}
	if rep.Deleted != 0 {
		t.Errorf("the index sweep deleted %d packs", rep.Deleted)
	}
}

// TestGCSweepsManifests checks the manifest key space sweeps on the age
// guard alone, which is all it has until a superblock names manifests.
func TestGCSweepsManifests(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	stale := hashName('a') // old, referenced by nothing -> deleted
	fresh := hashName('b') // young -> kept
	putObj(t, inner, manifest.Dir+"/"+stale, 72)
	putObj(t, inner, manifest.Dir+"/"+fresh, 72)
	age(t, root, manifest.Dir+"/"+stale, now.Add(-100*time.Hour))
	publishHead(t, rs, priv, 0, nil, "", nil, nil)

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if alive(t, inner, manifest.Dir+"/"+stale) {
		t.Error("stale manifest survived")
	}
	if !alive(t, inner, manifest.Dir+"/"+fresh) {
		t.Error("manifest inside the grace window was deleted")
	}
	if rep.Manifests.Deleted != 1 || rep.Manifests.SkippedYoung != 1 {
		t.Errorf("Manifests = %+v, want one deleted and one skipped", rep.Manifests)
	}
}

// TestGCKeepsUndatableObject: with no name-borne timestamp and no mtime
// from either the listing or a HEAD, the object's age is unknown — and an
// object whose age is unknown may be the index a publish uploaded a
// second ago.
func TestGCKeepsUndatableObject(t *testing.T) {
	raw, root := newInner(t)
	inner := &timelessStore{Store: raw, dir: mpi.Dir}
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	undatable := hashName('a')
	putObj(t, raw, mpi.Dir+"/"+undatable, 64)
	// Old on disk: only the missing metadata is keeping it alive.
	age(t, root, mpi.Dir+"/"+undatable, now.Add(-100*time.Hour))
	publishHead(t, rs, priv, 0, nil, "", nil, nil)

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if !alive(t, raw, mpi.Dir+"/"+undatable) {
		t.Fatal("an object with no determinable time was deleted")
	}
	if rep.Indexes.SkippedYoung != 1 || rep.Indexes.Deleted != 0 {
		t.Errorf("Indexes = %+v, want the undatable object skipped", rep.Indexes)
	}
}

// timelessStore is a transport whose listings carry no mtime and whose
// HEAD fails, for one key space. Real ones exist: the mtime property is
// the server's to send, and a HEAD can fail for reasons that have nothing
// to do with the object being absent.
type timelessStore struct {
	pelicanobj.Store
	dir string
}

func (s *timelessStore) ListDir(ctx context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	entries, err := s.Store.ListDir(ctx, dir)
	if err != nil || dir != s.dir {
		return entries, err
	}
	for i := range entries {
		entries[i].Mtime = time.Time{}
	}
	return entries, nil
}

func (s *timelessStore) StatKey(ctx context.Context, key string) (*pelicanobj.KeyInfo, error) {
	if strings.HasPrefix(key, s.dir+"/") {
		return nil, fmt.Errorf("stat %s: metadata unavailable", key)
	}
	return s.Store.StatKey(ctx, key)
}

// A generation that keeps its pack list in a manifest must keep both:
// the manifest object itself, and the packs it names. Sweeping either is
// how this change could destroy a volume — the first leaves the
// generation unreadable, the second deletes its content — so both are
// checked against a real manifest object, parsed by the same code the
// sweep uses.
func TestGCRetainsAManifestAndThePacksItNames(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	old := now.Add(-100 * time.Hour)
	named := packName(old, "aaaa")   // named by the manifest -> kept
	garbage := packName(old, "bbbb") // named by nothing -> deleted
	putPack(t, inner, named, 100)
	putPack(t, inner, garbage, 100)

	ref := putManifest(t, inner, named)
	stale := hashName('c') // an old manifest no generation names -> swept
	putObj(t, inner, manifest.Dir+"/"+stale, 64)
	age(t, root, manifest.Dir+"/"+stale, old)
	age(t, root, manifest.Dir+"/"+ref.Name, old) // old too: only the live set may save it

	publishManifestHead(t, rs, priv, ref)

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if !alive(t, inner, manifest.Dir+"/"+ref.Name) {
		t.Error("swept the manifest the head names; that generation can no longer be read")
	}
	if alive(t, inner, manifest.Dir+"/"+stale) {
		t.Error("kept a manifest no generation names")
	}
	if !alive(t, inner, packstore.PackDirKey+"/"+named) {
		t.Error("deleted a pack the head's manifest names")
	}
	if alive(t, inner, packstore.PackDirKey+"/"+garbage) {
		t.Error("kept a pack nothing names")
	}
	if rep.RetainedPacks != 1 || rep.Manifests.Retained != 1 {
		t.Errorf("retained %d packs / %d manifests, want 1 / 1", rep.RetainedPacks, rep.Manifests.Retained)
	}
}

// The sweep deletes on the strength of the retained set, so a manifest it
// cannot read means it does not know that set. Fail closed, exactly as
// for an unverifiable superblock.
func TestGCRefusesWhenAManifestCannotBeRead(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	garbage := packName(now.Add(-100*time.Hour), "bbbb")
	putPack(t, inner, garbage, 100)

	ref := putManifest(t, inner, packName(now.Add(-100*time.Hour), "aaaa"))
	// The ref stays, the object goes: a generation naming a manifest that
	// is not there.
	if err := inner.Delete(ctx, manifest.Dir+"/"+ref.Name); err != nil {
		t.Fatal(err)
	}
	publishManifestHead(t, rs, priv, ref)

	if _, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now}); err == nil {
		t.Fatal("GC ran with an unresolvable pack set; it would have deleted every pack")
	}
	if !alive(t, inner, packstore.PackDirKey+"/"+garbage) {
		t.Error("a pack was deleted by a sweep that could not read the retained set")
	}
}

// putManifest writes a real manifest segment naming packs and returns the
// ref a superblock lists it by.
func putManifest(t *testing.T, inner pelicanobj.Store, packs ...string) superblock.ManifestRef {
	t.Helper()
	b := manifest.NewBuilder()
	for _, p := range packs {
		if err := b.Add(packstore.SealedPack{Name: p, Size: 1}); err != nil {
			t.Fatal(err)
		}
	}
	raw := b.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := inner.Put(context.Background(), manifest.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return superblock.ManifestRef{Name: name, Hash: hash, Size: int64(len(raw)), Packs: uint32(b.Len())}
}

// publishManifestHead flips a head in the new shape: no inline pack list,
// the packs named by a manifest ref.
func publishManifestHead(t *testing.T, rs *refs.Store, priv ed25519.PrivateKey, refsList ...superblock.ManifestRef) {
	t.Helper()
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      0,
		CreatedUnixNano: 1,
		Manifests:       refsList,
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(context.Background(), "main", raw, ""); err != nil {
		t.Fatalf("flip: %v", err)
	}
}

// flipHead signs sb and makes it the branch head, for the tests that need
// to shape a superblock publishHead's parameters do not cover.
func flipHead(t *testing.T, rs *refs.Store, priv ed25519.PrivateKey, sb *superblock.Superblock, etag string) []byte {
	t.Helper()
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(context.Background(), "main", raw, etag); err != nil {
		t.Fatalf("flip gen %d: %v", sb.Generation, err)
	}
	return raw
}

// A consolidated-away index is named only by a generation the sweep
// cannot enumerate, so the ledger is the only thing standing between it
// and deletion. Inside the window it survives; past the window publish
// has already stopped carrying the entry, and it sweeps like any other
// orphan — which is the limit, not an oversight.
func TestGCKeepsACondemnedIndexInsideTheWindow(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-100 * time.Hour) // past the 72h default grace

	ixHead := hashName('a')      // listed by the head -> kept
	ixCondemned := hashName('b') // merged away an hour ago -> kept by the ledger
	ixAgedOut := hashName('c')   // merged away 200h ago -> the entry is gone, so swept
	ixOrphan := hashName('d')    // never named -> swept
	for _, n := range []string{ixHead, ixCondemned, ixAgedOut, ixOrphan} {
		putObj(t, inner, mpi.Dir+"/"+n, 64)
		// Every object predates the window, so only liveness can save one.
		age(t, root, mpi.Dir+"/"+n, old)
	}

	// The shape a seal leaves behind: one listed index, and a ledger of
	// what consolidation stopped listing. The aged-out entry is written
	// here anyway — publish would have dropped it, and a sweep must not
	// honour it either way.
	flipHead(t, rs, priv, &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      1,
		CreatedUnixNano: 1,
		PackIndexes:     []superblock.IndexRef{{Name: ixHead, Size: 1, Entries: 1, Packs: 1}},
		CondemnedIndexes: []superblock.CondemnedRef{
			{Name: ixCondemned, CondemnedAtUnix: now.Add(-1 * time.Hour).Unix()},
			{Name: ixAgedOut, CondemnedAtUnix: now.Add(-200 * time.Hour).Unix()},
		},
	}, "")

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, want := range []struct {
		name string
		live bool
	}{{ixHead, true}, {ixCondemned, true}, {ixAgedOut, false}, {ixOrphan, false}} {
		if got := alive(t, inner, mpi.Dir+"/"+want.name); got != want.live {
			t.Errorf("index %s...: alive=%v, want %v", want.name[:8], got, want.live)
		}
	}
	if rep.Indexes.Retained != 2 || rep.Indexes.Deleted != 2 {
		t.Errorf("Indexes = %+v, want Retained=2 Deleted=2", rep.Indexes)
	}
}

// The manifest case, and the reason it needed this more than the index
// did: a retired generation's manifest IS its pack list, so the test
// asserts the consequence rather than the file. Inside the window that
// generation still RESOLVES — same code path the sweep and a mount use —
// and its packs are still there. Past the window it does not, which is
// the honest limit of a ledger that ages.
func TestACondemnedManifestKeepsARetiredGenerationReadable(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-100 * time.Hour)

	retiredPack := packName(old, "aaaa") // named by the retired generation
	newPack := packName(old, "bbbb")     // added by the head
	putPack(t, inner, retiredPack, 100)
	putPack(t, inner, newPack, 100)

	// The segment the retired generation names, the one a later seal
	// merged it into, and a third that was condemned long enough ago that
	// publish would have stopped carrying it.
	retired := putManifest(t, inner, retiredPack)
	merged := putManifest(t, inner, retiredPack, newPack)
	agedOut := putManifest(t, inner, newPack)
	for _, ref := range []superblock.ManifestRef{retired, merged, agedOut} {
		age(t, root, manifest.Dir+"/"+ref.Name, old)
	}

	// Generation 0 is retired: reachable only by hash, so the sweep never
	// sees it. Nothing but the head's ledger speaks for its manifest.
	retiredSB := &superblock.Superblock{
		FormatVersion: superblock.FormatV2, Generation: 0, CreatedUnixNano: 1,
		Manifests: []superblock.ManifestRef{retired},
	}
	if err := retiredSB.Sign(priv); err != nil {
		t.Fatal(err)
	}
	flipHead(t, rs, priv, &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      1,
		CreatedUnixNano: 2,
		Manifests:       []superblock.ManifestRef{merged},
		CondemnedManifests: []superblock.CondemnedRef{
			{Name: retired.Name, CondemnedAtUnix: now.Add(-1 * time.Hour).Unix()},
			{Name: agedOut.Name, CondemnedAtUnix: now.Add(-200 * time.Hour).Unix()},
		},
	}, "")

	if _, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now}); err != nil {
		t.Fatalf("GC: %v", err)
	}

	// The consequence, not the object: the retired generation can still
	// state what it references.
	packs, err := manifest.Packs(ctx, inner, retiredSB)
	if err != nil {
		t.Fatalf("a generation inside the grace window can no longer resolve its pack set: %v", err)
	}
	if len(packs) != 1 || packs[0].Name != retiredPack {
		t.Fatalf("the retired generation resolved to %+v, want just %s", packs, retiredPack)
	}
	if !alive(t, inner, packstore.PackDirKey+"/"+retiredPack) {
		t.Error("the pack that generation names was deleted")
	}
	if !alive(t, inner, manifest.Dir+"/"+merged.Name) {
		t.Error("the head's own manifest was swept")
	}

	// And the limit, asserted rather than implied: once the entry ages off
	// the ledger, the object goes and a generation naming it is finished.
	if alive(t, inner, manifest.Dir+"/"+agedOut.Name) {
		t.Fatal("a manifest condemned 200h ago survived a 72h grace window")
	}
	lost := &superblock.Superblock{
		FormatVersion: superblock.FormatV2, Generation: 0, CreatedUnixNano: 1,
		Manifests: []superblock.ManifestRef{agedOut},
	}
	if _, err := manifest.Packs(ctx, inner, lost); err == nil {
		t.Error("a generation whose manifest aged out of the ledger still resolved; the fixture proves nothing")
	}
}

// A superblock written before the ledgers existed carries neither field.
// It must decode, verify and sweep exactly as it always did — the sweep
// reads the ledgers unconditionally, so a nil one has to mean "condemns
// nothing" rather than "unknown".
func TestGCSweepsASuperblockWithNoCondemnedRefs(t *testing.T) {
	inner, root := newInner(t)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-100 * time.Hour)

	ixLive := hashName('a')
	ixOrphan := hashName('b')
	for _, n := range []string{ixLive, ixOrphan} {
		putObj(t, inner, mpi.Dir+"/"+n, 64)
		age(t, root, mpi.Dir+"/"+n, old)
	}
	raw := publishHead(t, rs, priv, 0, nil, "", nil, nil, ixLive)
	pre, err := superblock.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pre.CondemnedIndexes != nil || pre.CondemnedManifests != nil {
		t.Fatalf("the pre-ledger fixture is not one: %+v / %+v", pre.CondemnedIndexes, pre.CondemnedManifests)
	}

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC on a pre-ledger superblock: %v", err)
	}
	if !alive(t, inner, mpi.Dir+"/"+ixLive) {
		t.Error("swept an index the head lists")
	}
	if alive(t, inner, mpi.Dir+"/"+ixOrphan) {
		t.Error("an empty ledger stopped the sweep deleting an orphan")
	}
	if rep.Indexes.Deleted != 1 {
		t.Errorf("Indexes = %+v, want exactly one deleted", rep.Indexes)
	}
}
