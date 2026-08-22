package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// vol is a real volume on a real (fake) origin, with the ORIGIN'S BACKING
// DIRECTORY reachable — because every fixture here is a disaster, and the
// disasters are done to the objects on disk rather than through an API that
// would refuse them.
type vol struct {
	t      *testing.T
	root   string
	inner  pelicanobj.Store
	tv     *testvol.Volume
	rstore *refs.Store
	key    ed25519.PrivateKey
	state  string
	clock  time.Time
	// want is what was written, by path, so the end-to-end test can check
	// the rescued mount byte for byte.
	want map[string][]byte
}

func newVol(t *testing.T) *vol {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	v := &vol{
		t: t, root: filepath.Join(root, "vol"), inner: inner, key: key, state: state,
		tv:    testvol.New(t, inner, testvol.Options{SigningKey: key}),
		clock: time.Now(), want: map[string][]byte{},
	}
	if v.rstore, err = refs.New(inner, state, nil); err != nil {
		t.Fatal(err)
	}
	// Pin the key the ordinary way, so the rescue path is exercised with a
	// pin rather than with an explicit key unless a test asks for one.
	if _, err := v.rstore.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	return v
}

// write adds a file and remembers its bytes.
func (v *vol) write(name string, body []byte) {
	v.t.Helper()
	v.tv.WriteFile(testvol.RootInode, name, body)
	v.want[name] = body
}

func (v *vol) seal() *publish.Result {
	v.t.Helper()
	v.clock = v.clock.Add(time.Hour)
	return v.tv.Publish(publish.Options{SMax: 1000, CreatedUnixNano: v.clock.UnixNano()})
}

func (v *vol) opts() Options {
	return Options{Inner: v.inner, Refs: v.rstore, Branch: "main"}
}

func (v *vol) applyOpts() ApplyOptions {
	v.clock = v.clock.Add(time.Minute)
	return ApplyOptions{Options: v.opts(), SigningKey: v.key, Now: v.clock.UnixNano()}
}

// deleteRefs is the disaster: the whole refs directory, gone.
func (v *vol) deleteRefs() {
	v.t.Helper()
	if err := os.RemoveAll(filepath.Join(v.root, "refs")); err != nil {
		v.t.Fatal(err)
	}
}

// corruptRef is the other disaster, and it is the more insidious one: the
// object is THERE, so nothing 404s; it just is not a superblock any more.
func (v *vol) corruptRef(branch string) {
	v.t.Helper()
	p := filepath.Join(v.root, "refs", branch)
	if err := os.WriteFile(p, []byte("this is not a superblock"), 0644); err != nil {
		v.t.Fatal(err)
	}
}

// packsHolding names the pack objects whose trailers list a superblock
// backup for the given generation — what a test deletes to make a rescue
// fall back a step.
func (v *vol) packsHolding(gen uint64) []string {
	v.t.Helper()
	ctx := context.Background()
	entries, err := v.inner.ListDir(ctx, packstore.PackDirKey)
	if err != nil {
		v.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir || !strings.HasPrefix(e.Name, "p-") {
			continue
		}
		tr, err := packstore.FetchTrailer(ctx, v.inner, e.Name, e.Size)
		if err != nil {
			continue
		}
		for _, en := range tr {
			if en.Type != packstore.EntrySuperblock {
				continue
			}
			raw, err := readEntry(ctx, v.inner, e.Name, en)
			if err != nil {
				continue
			}
			sb, err := superblock.Decode(raw)
			if err == nil && sb.Generation == gen {
				out = append(out, e.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (v *vol) deletePack(name string) {
	v.t.Helper()
	if err := os.Remove(filepath.Join(v.root, packstore.PackDirKey, name)); err != nil {
		v.t.Fatal(err)
	}
}

// ============================ THE THREE DISASTERS ======================

// TestRefsDeletedOutright is the headline case: refs/ is gone and the volume
// is rebuilt from packs alone.
func TestRefsDeletedOutright(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.write("b.txt", []byte("world"))
	last := v.seal()
	v.deleteRefs()

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(rep.Branches) != 1 {
		t.Fatalf("branches = %d, want 1", len(rep.Branches))
	}
	p := rep.Branches[0]
	if p.Current.Present {
		t.Error("the report says refs/main is present after it was deleted")
	}
	if p.Chosen == nil {
		t.Fatalf("nothing recoverable; skipped=%+v", p.Skipped)
	}
	// The newest backup describes the generation BELOW the head that wrote
	// it (it is built before its own seal finishes), so the newest thing
	// recoverable from packs is the last generation's own document.
	if p.Chosen.SB.Generation != last.Superblock.Generation {
		t.Errorf("offered generation %d, want %d", p.Chosen.SB.Generation, last.Superblock.Generation)
	}
	if !p.Chosen.Attributed || p.Chosen.SB.Branch != "main" {
		t.Errorf("candidate is not attributed to main: attributed=%v branch=%q",
			p.Chosen.Attributed, p.Chosen.SB.Branch)
	}
	if !p.Root.Located {
		t.Errorf("root catalog not located: %s", p.Root.Note)
	}
	if len(rep.Rejected) != 0 {
		t.Errorf("rejected %d documents on a healthy volume: %+v", len(rep.Rejected), rep.Rejected)
	}
}

// TestARefThatIsPresentButCorrupt: the object exists, so nothing 404s and
// the flip is a REPLACE rather than a create. Both halves matter — a rescue
// that treated a corrupt ref as absent would flip with an empty expect-ETag
// and be refused by the create-if-absent guard.
func TestARefThatIsPresentButCorrupt(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.corruptRef("main")

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	p := rep.Branches[0]
	if !p.Current.Present {
		t.Error("a corrupt ref was reported as absent; the flip would then be refused as create-if-absent")
	}
	if p.Current.Verified {
		t.Error("a corrupt ref was reported as verifying")
	}
	if p.Current.Problem == "" {
		t.Error("no problem recorded for an unusable ref")
	}
	if p.Chosen == nil {
		t.Fatal("nothing recoverable")
	}
	res, err := Apply(context.Background(), v.applyOpts(), p, false)
	if err != nil {
		t.Fatalf("Apply over a corrupt ref: %v", err)
	}
	if !res.Replaced {
		t.Error("the report says a ref was created; it was replaced")
	}
	if _, err := v.rstore.Fetch(context.Background(), "main"); err != nil {
		t.Errorf("the rescued ref does not verify: %v", err)
	}
}

// TestTheNewestBackupsPackIsGone is the spec's documented fall-back-a-step,
// driven by deleting the pack that carries the newest backup.
func TestTheNewestBackupsPackIsGone(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	first := v.seal()
	v.write("b.txt", []byte("world"))
	last := v.seal()
	v.deleteRefs()

	// Sanity: without the deletion the newest is offered. Establishing this
	// first is what stops the test from passing for the wrong reason.
	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Branches[0].Chosen.SB.Generation; got != last.Superblock.Generation {
		t.Fatalf("baseline offered generation %d, want %d", got, last.Superblock.Generation)
	}

	// Now remove every pack holding a backup for the newest generation.
	holders := v.packsHolding(last.Superblock.Generation)
	if len(holders) == 0 {
		t.Fatal("no pack holds the newest backup; the fixture cannot make this case")
	}
	for _, p := range holders {
		v.deletePack(p)
	}

	rep, err = Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory after losing the newest backup: %v", err)
	}
	p := rep.Branches[0]
	if p.Chosen == nil {
		t.Fatalf("fell back to nothing; skipped=%+v", p.Skipped)
	}
	if p.Chosen.SB.Generation >= last.Superblock.Generation {
		t.Errorf("still offering generation %d after its backup was deleted", p.Chosen.SB.Generation)
	}
	if p.Chosen.SB.Generation != first.Superblock.Generation {
		t.Errorf("fell back to generation %d, want %d (one step)",
			p.Chosen.SB.Generation, first.Superblock.Generation)
	}
}

// TestACandidateWhoseManifestIsGoneIsSkippedWithAReason is the OTHER
// fallback: the backup is right there and verifies, but its pack set cannot
// be resolved, so it is unusable. The difference from the case above is
// visible in the report — this one is SKIPPED with a reason, and a skip that
// was silent would be indistinguishable from a scan that saw nothing newer.
func TestACandidateWhoseManifestIsGoneIsSkippedWithAReason(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.write("b.txt", []byte("world"))
	last := v.seal()
	v.deleteRefs()

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatal(err)
	}
	cand := rep.Branches[0].Chosen
	if cand == nil || len(cand.SB.Manifests) == 0 {
		t.Skip("this volume states its packs inline, so there is no manifest to lose")
	}
	// Delete the segments the newest candidate carries.
	for _, m := range cand.SB.Manifests {
		if err := os.Remove(filepath.Join(v.root, "manifests", m.Name)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err = Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	p := rep.Branches[0]
	if len(p.Skipped) == 0 {
		t.Fatal("a candidate whose pack set is unresolvable was not reported as skipped")
	}
	found := false
	for _, s := range p.Skipped {
		if s.Generation == last.Superblock.Generation {
			found = true
			if !strings.Contains(s.Reason, "unresolvable") {
				t.Errorf("skip reason %q does not say the pack set could not be resolved", s.Reason)
			}
		}
	}
	if !found {
		t.Errorf("generation %d is not among the skips: %+v", last.Superblock.Generation, p.Skipped)
	}
	// AND IT IS NOT OFFERED. An unresolvable pack set flipped as a head is a
	// generation naming fewer packs than it needs, which a sweep then acts on.
	if p.Chosen != nil && p.Chosen.SB.Generation == last.Superblock.Generation {
		t.Error("the unresolvable candidate was offered anyway")
	}
}

// ============================ THE TRUST BOUNDARY =======================

// TestAPlantedBackupIsNotACandidate is the attack, run for real: a
// well-formed superblock signed by SOMEBODY ELSE'S key, appended to the pack
// space the way anyone with write access could. It must be reported and
// never offered.
func TestAPlantedBackupIsNotACandidate(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	real := v.seal()
	v.deleteRefs()

	// The attacker's document: a newer generation, same volume id, perfect
	// in every way except who signed it.
	_, evil, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	planted := *real.Superblock
	planted.Generation = real.Superblock.Generation + 50
	planted.Signature = [64]byte{}
	if err := planted.Sign(evil); err != nil {
		t.Fatal(err)
	}
	plantedRaw, err := planted.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plantBackup(t, v, plantedRaw)

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	p := rep.Branches[0]
	if p.Chosen == nil {
		t.Fatal("nothing recoverable")
	}
	if p.Chosen.SB.Generation == planted.Generation {
		t.Fatal("THE ATTACK SUCCEEDED: a rescue offered a backup signed by a key the volume never used")
	}
	if len(rep.Rejected) == 0 {
		t.Error("the planted document was silently dropped rather than reported")
	}
	// The rejection has to name where it is, or an operator cannot act on it.
	if rep.Rejected[0].Pack == "" {
		t.Error("a rejection names no pack")
	}
}

// TestVerificationIsWhatRejectsIt is the MUTATION for the test above: with
// verification bypassed, the planted document wins. Run as a positive
// control so the refusal above is known to come from the signature check
// and not from something incidental about the fixture.
func TestVerificationIsWhatRejectsIt(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	real := v.seal()

	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	planted := *real.Superblock
	planted.Generation = real.Superblock.Generation + 50
	planted.Signature = [64]byte{}
	if err := planted.Sign(evil); err != nil {
		t.Fatal(err)
	}
	plantedRaw, _ := planted.Encode()

	// The store the scan actually verifies against, pointed at the
	// ATTACKER'S key — which is precisely the mutation "break verification"
	// makes, expressed as a trust configuration rather than as an edit.
	evilStore, err := refs.New(v.inner, t.TempDir(), evil.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evilStore.Verify(plantedRaw); err != nil {
		t.Fatalf("the planted document does not verify under the attacker's own key: %v", err)
	}
	// And under the volume's real key it does not, which is the whole
	// defence in one line.
	if _, err := v.rstore.Verify(plantedRaw); err == nil {
		t.Fatal("the planted document verified under the volume's key")
	}
}

// TestRescueWithNoPinnedKeyRefuses: TOFU is not available here. A document
// dug out of a pack was chosen by whoever could append a pack, so letting
// one establish trust would hand the pin to any writer.
func TestRescueWithNoPinnedKeyRefuses(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.deleteRefs()

	// A client that has never successfully fetched a branch: no pin, no
	// explicit key.
	naive, err := refs.New(v.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o := v.opts()
	o.Refs = naive
	rep, err := Inventory(context.Background(), o)
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("error is %v, want ErrNoCandidates: with no key nothing can be trusted", err)
	}
	if rep == nil || len(rep.Rejected) == 0 {
		t.Fatal("the documents were not even reported as unverifiable")
	}
	if !strings.Contains(rep.Rejected[0].Reason, "no volume key pinned") {
		t.Errorf("rejection reason %q does not explain that no key is available", rep.Rejected[0].Reason)
	}

	// AND THE ESCAPE WORKS: an explicit key recovers the volume, which is
	// what makes the refusal a policy rather than a dead end.
	explicit, err := refs.New(v.inner, t.TempDir(), v.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	o.Refs = explicit
	if _, err := Inventory(context.Background(), o); err != nil {
		t.Errorf("--volume-pubkey did not recover the volume: %v", err)
	}
}

// TestAmbiguityIsPresentedNeverPicked: two distinct verified documents at one
// generation. This is a legitimate state (a publish that uploaded its last
// pack and then died leaves a backup its retry seals again) and it is also
// what a rollback by a key-holder looks like. Nothing here can tell them
// apart, so nothing here chooses.
func TestAmbiguityIsPresentedNeverPicked(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	real := v.seal()
	v.deleteRefs()

	// A second, differently-stamped document at the same generation, signed
	// by the volume's own key: both verify, and they are not the same bytes.
	twin := *real.Superblock
	twin.CreatedUnixNano = real.Superblock.CreatedUnixNano + 1
	twin.Signature = [64]byte{}
	if err := twin.Sign(v.key); err != nil {
		t.Fatal(err)
	}
	twinRaw, err := twin.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plantBackup(t, v, twinRaw)

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	p := rep.Branches[0]
	if len(p.Ambiguous) < 2 {
		t.Fatalf("ambiguity not reported: chosen=%v ambiguous=%d", p.Chosen != nil, len(p.Ambiguous))
	}
	if p.Chosen != nil {
		t.Fatal("a candidate was auto-picked from an ambiguous head")
	}
	// And --apply refuses rather than guessing.
	_, err = Apply(context.Background(), v.applyOpts(), p, false)
	if err == nil {
		t.Fatal("Apply accepted an ambiguous plan")
	}
	if !strings.Contains(err.Error(), "--pick") {
		t.Errorf("error %q does not tell the operator how to decide", err)
	}
	// Being TOLD resolves it, which is the only way it ever resolves.
	id := p.Ambiguous[0].ID()
	if err := Pick(p, id); err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if p.Chosen == nil || p.Chosen.ID() != id {
		t.Fatal("Pick did not select the named candidate")
	}
	if err := Resolve(context.Background(), v.opts(), p); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := Apply(context.Background(), v.applyOpts(), p, false); err != nil {
		t.Fatalf("Apply after Pick: %v", err)
	}
}

// TestTheSameBackupThroughTwoPacksIsNotAmbiguity: a repack copies backups
// into the packs it writes, so one document is reachable several ways. That
// must dedup by BYTES, or ordinary maintenance would make every volume look
// ambiguous and block its own rescue.
func TestTheSameBackupThroughTwoPacksIsNotAmbiguity(t *testing.T) {
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	real := v.seal()
	v.deleteRefs()

	// The identical bytes, in another pack. They have to be the BACKUP's
	// bytes, read back out of the pack it rides in — not the head's. The two
	// are different documents at the same generation (a backup is built
	// before its seal finishes), so re-encoding the head here would plant
	// genuine ambiguity and this test would pass for the wrong reason. It
	// did, on the first run.
	raw := backupBytes(t, v, real.Superblock.Generation)
	plantBackup(t, v, raw)

	rep, err := Inventory(context.Background(), v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(rep.Branches[0].Ambiguous) != 0 {
		t.Fatal("the same document reached through two packs was reported as two candidates")
	}
}

// ============================ END TO END ===============================

// TestDeleteRefsRescueApplyMountByteExact is the whole promise: destroy the
// mutable half of the volume, rebuild it from packs, mount the result, and
// read back every byte that was written.
func TestDeleteRefsRescueApplyMountByteExact(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	// Enough files, across enough seals, that the generation spans several
	// packs and several catalogs — a one-file volume would prove nothing
	// about resolving a pack set.
	for i := 0; i < 3; i++ {
		for j := 0; j < 6; j++ {
			body := make([]byte, 40<<10+j*1024)
			if _, err := rand.Read(body); err != nil {
				t.Fatal(err)
			}
			v.write(fmt.Sprintf("f-%d-%d.bin", i, j), body)
		}
		v.seal()
	}
	// One more seal with no new content, so the LAST generation's backup
	// describes a complete tree: a backup describes its parent, so the file
	// set under test has to be a generation old by the time the disaster
	// happens.
	v.write("last.txt", []byte("tail"))
	head := v.seal()

	v.deleteRefs()
	if _, err := v.rstore.Fetch(ctx, "main"); err == nil {
		t.Fatal("refs/main still readable after deletion")
	}

	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	p := rep.Branches[0]
	if p.Chosen == nil {
		t.Fatalf("nothing recoverable; skipped=%+v", p.Skipped)
	}
	res, err := Apply(ctx, v.applyOpts(), p, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Replaced {
		t.Error("the report says a ref was replaced; it was deleted, so it was created")
	}
	t.Logf("rescued generation %d naming %d packs (%s)", res.Generation, res.Packs, res.Shape)

	// THE REF IS BACK AND VERIFIES through the ordinary trust path.
	got, err := v.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("the rescued ref does not verify: %v", err)
	}
	if err := got.Superblock.Validate(); err != nil {
		t.Fatalf("the rescued head is not a valid head: %v", err)
	}
	// One shape, not both: this is the check that would have caught flipping
	// the backup verbatim.
	if len(got.Superblock.PackList) > 0 && len(got.Superblock.Manifests) > 0 {
		t.Fatal("the rescued head states its pack set twice")
	}

	// AND IT MOUNTS, BYTE FOR BYTE.
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: v.inner, SB: got.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("mounting the rescued generation: %v", err)
	}
	defer fs.Close() //nolint:errcheck

	// HOW MUCH IS RECOVERABLE, and this is the part that improved once the
	// carrier pack joined the union (resolvePacks, source 3). The spec called
	// a rescue "the newest generation minus its tail", because a backup
	// cannot name the pack it rides in. The rescuer can, so the FULL newest
	// generation comes back — including the file written by the very seal
	// that buried the backup.
	//
	// The one shape that legitimately recovers less is a seal whose catalogs
	// filled the open pack, so that adding the backup cut a fresh one: the
	// catalog pack is then in neither the backup's list nor the carrier, the
	// root is not located, and the rescue falls back a step. That is safe and
	// reported, so the assertion is written against what was actually
	// restored rather than against a number that would make this test flaky.
	full := got.Superblock.Generation == head.Superblock.Generation
	if !full {
		t.Logf("fell back a step (rescued %d, head %d): the final seal's catalogs and its backup landed "+
			"in different packs", got.Superblock.Generation, head.Superblock.Generation)
	}
	checked := 0
	for name, want := range v.want {
		if name == "last.txt" && !full {
			continue
		}
		node, err := fs.LookupPath(ctx, name)
		if err != nil {
			t.Errorf("%s: lookup in the rescued mount: %v", name, err)
			continue
		}
		buf := make([]byte, len(want))
		n, err := fs.Read(ctx, node.Inode, 0, buf)
		if err != nil {
			t.Errorf("%s: read: %v", name, err)
			continue
		}
		if n != len(want) {
			t.Errorf("%s: read %d bytes, want %d", name, n, len(want))
			continue
		}
		if string(buf) != string(want) {
			t.Errorf("%s: content differs after rescue", name)
			continue
		}
		checked++
	}
	wantFiles := len(v.want)
	if !full {
		wantFiles--
	}
	if checked != wantFiles {
		t.Fatalf("checked %d files, want %d", checked, wantFiles)
	}
	if !full {
		// Still the newest RECOVERABLE generation: one step, never two.
		if got.Superblock.Generation != head.Superblock.Generation-1 {
			t.Errorf("rescued generation %d, want %d or %d",
				got.Superblock.Generation, head.Superblock.Generation, head.Superblock.Generation-1)
		}
	}
}

// TestARescueNeverDeletes counts the objects on both sides. A rescue runs
// when nobody knows yet what is really missing, and this is the property
// that makes it safe to run early and often.
func TestARescueNeverDeletes(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.write("b.txt", []byte("world"))
	v.seal()

	before := objectSet(t, v.root)
	v.deleteRefs()
	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, v.applyOpts(), rep.Branches[0], false); err != nil {
		t.Fatal(err)
	}
	after := objectSet(t, v.root)
	for k := range before {
		if strings.HasPrefix(k, "refs/") {
			// Deleted by the TEST, not by the rescue.
			continue
		}
		if !after[k] {
			t.Errorf("the rescue removed %s", k)
		}
	}
}

// TestApplyRefusesAHeadThatCannotServeItsRoot: the document verifies, so
// trust has no objection — and flipping it would publish a head that cannot
// read its own root directory. --force is the deliberate override.
func TestApplyRefusesAHeadThatCannotServeItsRoot(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.write("b.txt", []byte("world"))
	v.seal()
	v.deleteRefs()

	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Branches[0]
	if !p.Root.Located {
		t.Fatalf("baseline: the root was not located, so this test cannot mutate it")
	}
	// Break exactly the finding: a root catalog identity nothing holds.
	p.Root = RootStatus{Note: "root catalog deadbeef is in none of this generation's packs"}
	if _, err := Apply(ctx, v.applyOpts(), p, false); err == nil {
		t.Fatal("Apply accepted a head whose root catalog was not located")
	}
	if _, err := Apply(ctx, v.applyOpts(), p, true); err != nil {
		t.Errorf("--force did not override: %v", err)
	}
}

// TestApplyNeedsASigningKey: a rescued head is a NEW document, because the
// backup states its pack set in a shape no head may use. So report-only
// needs no key and --apply does.
func TestApplyNeedsASigningKey(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.deleteRefs()

	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatal(err)
	}
	o := v.applyOpts()
	o.SigningKey = nil
	if _, err := Apply(ctx, o, rep.Branches[0], false); err == nil {
		t.Fatal("Apply signed a head with no key")
	}
}

// TestTheCarrierPackIsWhatMakesTheRescuedHeadMountable is THE mutation for
// this package, and it is the bug the end-to-end test found on its first run.
//
// A backup cannot name the pack it rides in — that pack is still an unnamed
// open spool file when the backup is built — and the generation's root
// catalog is packed immediately before the backup, so it is usually in
// exactly that pack. Resolve the pack set the way the spec described it (the
// union of the inline list and the carried manifest refs) and you get a head
// that verifies, states a root catalog, and cannot serve it.
//
// So the mutation is to drop source 3 and watch the root become unlocatable,
// then restore it and watch the root come back. Both directions, because
// only the pair proves the carrier is what fixed it.
func TestTheCarrierPackIsWhatMakesTheRescuedHeadMountable(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	for j := 0; j < 6; j++ {
		body := make([]byte, 60<<10)
		if _, err := rand.Read(body); err != nil {
			t.Fatal(err)
		}
		v.write(fmt.Sprintf("f%d.bin", j), body)
	}
	v.seal()
	v.write("more.bin", make([]byte, 70<<10))
	v.seal()
	v.deleteRefs()

	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Branches[0]
	if p.Chosen == nil {
		t.Fatal("nothing recoverable")
	}
	if !p.Root.Located {
		t.Fatalf("baseline: the root was not located, so the mutation has nothing to break: %s", p.Root.Note)
	}
	withCarrier := len(p.Packs)

	// THE MUTATION: the same candidate with its carrier forgotten, which is
	// the spec's two-source union exactly.
	blind := &Candidate{SB: p.Chosen.SB, Raw: p.Chosen.Raw, Hash: p.Chosen.Hash}
	spec, err := resolvePacks(ctx, v.opts(), blind)
	if err != nil {
		t.Fatalf("the two-source union does not even resolve: %v", err)
	}
	if len(spec) >= withCarrier {
		t.Fatalf("the carrier contributed nothing (%d packs either way); this fixture cannot show the "+
			"difference", withCarrier)
	}
	if root := locateRoot(ctx, v.opts(), p.Chosen.SB, spec); root.Located {
		t.Fatalf("the root catalog was located WITHOUT the carrier pack, in %s: the carrier is then not "+
			"load-bearing and source 3 of resolvePacks should be deleted", root.Pack)
	}
	// And it is specifically the carrier that holds it.
	if p.Root.Pack != p.Chosen.Pack {
		t.Errorf("the root was located in %s but the backup rode in %s; the comment claims these coincide",
			p.Root.Pack, p.Chosen.Pack)
	}
	t.Logf("union with carrier: %d packs; spec's two sources: %d", withCarrier, len(spec))
}

// TestTheCarrierPacksTrailerHashIsTheRealOne. The carrier's row is the one
// row in a rescued head's pack list that no signed document supplied, so it
// is computed from the object — and if it were computed wrongly, a reader
// would reject the location map for the one pack it most needs.
func TestTheCarrierPacksTrailerHashIsTheRealOne(t *testing.T) {
	ctx := context.Background()
	v := newVol(t)
	v.write("a.txt", []byte("hello"))
	v.seal()
	v.deleteRefs()

	rep, err := Inventory(ctx, v.opts())
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Branches[0]
	var row *superblock.PackEntry
	for i := range p.Packs {
		if p.Packs[i].Name == p.Chosen.Pack {
			row = &p.Packs[i]
		}
	}
	if row == nil {
		t.Fatal("the carrier pack is not in the resolved pack set")
	}
	if row.TrailerHash == ([32]byte{}) {
		t.Fatal("the carrier's trailer hash is zero; a reader verifying the location map would refuse it")
	}
	// The authoritative check: the reader's own verified fetch must accept it.
	if _, err := packstore.FetchTrailerVerified(ctx, v.inner, row.Name, row.Size, row.TrailerHash); err != nil {
		t.Errorf("a reader cannot verify the carrier's trailer against the hash the rescue recorded: %v", err)
	}
}

// plantBackup writes raw into the pack space as a superblock backup entry,
// the way anyone with write access could — which is the point.
func plantBackup(t *testing.T, v *vol, raw []byte) {
	t.Helper()
	ctx := context.Background()
	w, err := packstore.NewPackWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := superblock.Hash(raw)
	if err := w.Add(hex.EncodeToString(h[:]), packstore.EntrySuperblock, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Seal(ctx, v.inner); err != nil {
		t.Fatal(err)
	}
}

// objectSet lists every object under the volume's prefix on the origin's
// disk, for the never-deletes count.
func objectSet(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// backupBytes reads the wire bytes of the superblock backup for one
// generation straight out of the pack space, which is the only way to get
// the exact document a rescue will find.
func backupBytes(t *testing.T, v *vol, gen uint64) []byte {
	t.Helper()
	ctx := context.Background()
	entries, err := v.inner.ListDir(ctx, packstore.PackDirKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir || !strings.HasPrefix(e.Name, "p-") {
			continue
		}
		tr, err := packstore.FetchTrailer(ctx, v.inner, e.Name, e.Size)
		if err != nil {
			continue
		}
		for _, en := range tr {
			if en.Type != packstore.EntrySuperblock {
				continue
			}
			raw, err := readEntry(ctx, v.inner, e.Name, en)
			if err != nil {
				continue
			}
			sb, err := superblock.Decode(raw)
			if err == nil && sb.Generation == gen {
				return raw
			}
		}
	}
	t.Fatalf("no superblock backup for generation %d in the pack space", gen)
	return nil
}
