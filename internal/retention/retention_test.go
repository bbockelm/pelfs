package retention

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

func newInner(t *testing.T) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner
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
	etag string, packs []string, condemned []superblock.CondemnedPack) []byte {
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
	inner := newInner(t)
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
	inner := newInner(t)
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
	inner := newInner(t)
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
	inner := newInner(t)
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
