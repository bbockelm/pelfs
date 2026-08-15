package packstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// newInner starts a fakeorigin-backed pelicanobj store rooted at /vol and
// returns it along with the on-disk directory backing that prefix, so tests
// can inspect exactly which objects landed on "the federation".
func newInner(t *testing.T) (pelicanobj.Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner, filepath.Join(root, "vol")
}

func newPack(t *testing.T, inner pelicanobj.Store, cfg Config) *Store {
	t.Helper()
	if cfg.WriteEnabled && cfg.SpoolDir == "" {
		cfg.SpoolDir = t.TempDir()
	}
	s, err := New(context.Background(), inner, cfg)
	if err != nil {
		t.Fatalf("packstore.New: %v", err)
	}
	return s
}

// blob generates deterministic per-key content of length n.
func blob(key string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = key[i%len(key)] ^ byte(i%251)
	}
	return b
}

func readObj(t *testing.T, s pelicanobj.Store, key string, off, limit int64) []byte {
	t.Helper()
	rc, err := s.Get(context.Background(), key, off, limit)
	if err != nil {
		t.Fatalf("Get %s (off=%d limit=%d): %v", key, off, limit, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return data
}

// listKeys drains ListAll and returns the keys in emission order plus a
// key -> size map.
func listKeys(t *testing.T, s pelicanobj.Store, prefix string) ([]string, map[string]int64) {
	t.Helper()
	ch, err := s.ListAll(context.Background(), prefix, "", false)
	if err != nil {
		t.Fatalf("ListAll(%q): %v", prefix, err)
	}
	var keys []string
	sizes := make(map[string]int64)
	for o := range ch {
		if o == nil {
			t.Fatalf("ListAll(%q) emitted the failure sentinel", prefix)
		}
		keys = append(keys, o.Key())
		sizes[o.Key()] = o.Size()
	}
	return keys, sizes
}

// diskFiles lists every regular file under dir (empty when dir is absent).
func diskFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("walk %s: %v", dir, err)
	}
	return files
}

func TestPackRoundtrip(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true})

	var keys []string
	want := make(map[string][]byte)
	for i := 0; i < 20; i++ {
		n := 100 + i*37
		key := fmt.Sprintf("chunks/0/%d/%d_0_%d", i%4, i+1, n)
		data := blob(key, n)
		keys = append(keys, key)
		want[key] = data
		if err := s.Put(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}

	// Nothing may land as per-key chunk objects on the origin.
	if files := diskFiles(t, filepath.Join(vol, "chunks")); len(files) != 0 {
		t.Fatalf("per-key chunk objects leaked to the origin: %v", files)
	}
	if got := s.PendingBlocks(); got != 20 {
		t.Fatalf("PendingBlocks = %d, want 20", got)
	}

	// Pre-flush reads are served from the local spool (the blocks exist
	// nowhere else yet).
	for _, key := range keys {
		if got := readObj(t, s, key, 0, -1); !bytes.Equal(got, want[key]) {
			t.Fatalf("pre-flush Get %s: got %d bytes, want %d", key, len(got), len(want[key]))
		}
	}
	obj, err := s.Head(ctx, keys[3])
	if err != nil {
		t.Fatalf("pre-flush Head: %v", err)
	}
	if obj.Size() != int64(len(want[keys[3]])) {
		t.Fatalf("pre-flush Head size = %d, want %d", obj.Size(), len(want[keys[3]]))
	}

	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := s.PendingBlocks(); got != 0 {
		t.Fatalf("PendingBlocks after Flush = %d, want 0", got)
	}
	if files := diskFiles(t, filepath.Join(vol, "chunks")); len(files) != 0 {
		t.Fatalf("per-key chunk objects appeared after flush: %v", files)
	}
	packs := diskFiles(t, filepath.Join(vol, PackDirKey))
	if len(packs) != 1 {
		t.Fatalf("pack objects on origin = %v, want exactly one", packs)
	}

	// Post-flush reads become range requests into the pack.
	for _, key := range keys {
		if got := readObj(t, s, key, 0, -1); !bytes.Equal(got, want[key]) {
			t.Fatalf("post-flush Get %s mismatch", key)
		}
		obj, err := s.Head(ctx, key)
		if err != nil {
			t.Fatalf("post-flush Head %s: %v", key, err)
		}
		if obj.Size() != int64(len(want[key])) {
			t.Fatalf("post-flush Head %s size = %d, want %d", key, obj.Size(), len(want[key]))
		}
	}

	// Ranged read (off>0, limit>0) within one packed entry.
	key := keys[7]
	if got := readObj(t, s, key, 13, 41); !bytes.Equal(got, want[key][13:54]) {
		t.Fatalf("ranged Get %s returned the wrong slice (%d bytes)", key, len(got))
	}
	// A range running past the end of the entry is clamped at the entry
	// boundary and must not bleed into the neighboring block in the pack.
	tail := int64(len(want[key]) - 5)
	if got := readObj(t, s, key, tail, 100); !bytes.Equal(got, want[key][tail:]) {
		t.Fatalf("tail ranged Get %s returned %d bytes, want 5", key, len(got))
	}
}

func TestBootstrapFreshInstance(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true})

	want := make(map[string][]byte)
	for i := 0; i < 12; i++ {
		n := 50 + i*11
		key := fmt.Sprintf("chunks/%d/0/%d_0_%d", i%3, i+1, n)
		want[key] = blob(key, n)
		if err := s.Put(ctx, key, bytes.NewReader(want[key])); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if packs := diskFiles(t, filepath.Join(vol, PackDirKey)); len(packs) != 1 {
		t.Fatalf("pack objects on origin = %v, want exactly one", packs)
	}

	// A second, read-only instance over the same inner store must bootstrap
	// the whole index from the pack trailer.
	ro := newPack(t, inner, Config{})
	keys, sizes := listKeys(t, ro, "chunks/")
	if len(keys) != len(want) {
		t.Fatalf("ListAll returned %d keys, want %d: %v", len(keys), len(want), keys)
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("ListAll keys not sorted ascending: %v", keys)
	}
	for key, data := range want {
		if sizes[key] != int64(len(data)) {
			t.Fatalf("ListAll size for %s = %d, want %d", key, sizes[key], len(data))
		}
		obj, err := ro.Head(ctx, key)
		if err != nil {
			t.Fatalf("Head %s: %v", key, err)
		}
		if obj.Size() != int64(len(data)) {
			t.Fatalf("Head %s size = %d, want %d", key, obj.Size(), len(data))
		}
		if got := readObj(t, ro, key, 0, -1); !bytes.Equal(got, data) {
			t.Fatalf("fresh-instance Get %s mismatch", key)
		}
	}
}

func TestDeleteTombstoneShadowing(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true})

	a, b, c, d := "chunks/0/0/1_0_64", "chunks/0/0/2_0_64", "chunks/0/0/3_0_64", "chunks/0/0/4_0_64"
	for _, key := range []string{a, b, c} {
		if err := s.Put(ctx, key, bytes.NewReader(blob(key, 64))); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if err := s.Delete(ctx, b); err != nil {
		t.Fatalf("Delete %s: %v", b, err)
	}
	if _, err := s.Get(ctx, b, 0, -1); err == nil {
		t.Fatalf("Get %s after Delete should fail", b)
	}
	keys, _ := listKeys(t, s, "chunks/")
	if len(keys) != 2 || keys[0] != a || keys[1] != c {
		t.Fatalf("ListAll after Delete = %v, want [%s %s]", keys, a, c)
	}

	// The second flush carries b's tombstone into a new pack.
	if err := s.Put(ctx, d, bytes.NewReader(blob(d, 64))); err != nil {
		t.Fatalf("Put %s: %v", d, err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if packs := diskFiles(t, filepath.Join(vol, PackDirKey)); len(packs) != 2 {
		t.Fatalf("pack objects on origin = %v, want two", packs)
	}

	// A fresh bootstrap replays both trailers: the later pack's tombstone
	// must shadow b's entry in the earlier pack.
	fresh := newPack(t, inner, Config{})
	keys, _ = listKeys(t, fresh, "chunks/")
	wantKeys := []string{a, c, d}
	if len(keys) != len(wantKeys) {
		t.Fatalf("fresh ListAll = %v, want %v", keys, wantKeys)
	}
	for i := range wantKeys {
		if keys[i] != wantKeys[i] {
			t.Fatalf("fresh ListAll = %v, want %v", keys, wantKeys)
		}
	}
	if _, err := fresh.Get(ctx, b, 0, -1); err == nil {
		t.Fatalf("fresh Get %s should fail (tombstoned)", b)
	}
	for _, key := range wantKeys {
		if got := readObj(t, fresh, key, 0, -1); !bytes.Equal(got, blob(key, 64)) {
			t.Fatalf("fresh Get %s mismatch", key)
		}
	}
}

func TestNonPackablePassthrough(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true})

	key := "meta/x/current.db"
	data := blob(key, 300)
	if err := s.Put(ctx, key, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
	// The object must appear as a plain per-key file on the origin, and must
	// not touch the spool.
	onDisk, err := os.ReadFile(filepath.Join(vol, "meta/x/current.db"))
	if err != nil {
		t.Fatalf("meta object not on origin disk: %v", err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Fatalf("meta object on origin has wrong contents (%d bytes)", len(onDisk))
	}
	if got := s.PendingBlocks(); got != 0 {
		t.Fatalf("PendingBlocks = %d after non-packable Put, want 0", got)
	}

	if got := readObj(t, s, key, 0, -1); !bytes.Equal(got, data) {
		t.Fatalf("Get %s mismatch", key)
	}
	obj, err := s.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head %s: %v", key, err)
	}
	if obj.Size() != int64(len(data)) {
		t.Fatalf("Head %s size = %d, want %d", key, obj.Size(), len(data))
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete %s: %v", key, err)
	}
	if _, err := os.Stat(filepath.Join(vol, "meta/x/current.db")); !os.IsNotExist(err) {
		t.Fatalf("meta object still on origin disk after Delete (err=%v)", err)
	}
	if _, err := s.Get(ctx, key, 0, -1); err == nil {
		t.Fatalf("Get %s after Delete should fail", key)
	}
}

func TestLegacyMixedVolume(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)

	// A v1 volume already holds a per-key chunk object.
	legacyKey := "chunks/0/0/legacy_0_100"
	legacyData := blob("v1-legacy-object", 100)
	if err := inner.Put(ctx, legacyKey, bytes.NewReader(legacyData)); err != nil {
		t.Fatalf("inner Put %s: %v", legacyKey, err)
	}

	s := newPack(t, inner, Config{WriteEnabled: true})

	// Packed neighbors that sort on both sides of the legacy key.
	before, after := "chunks/0/0/aaa_0_40", "chunks/0/0/zzz_0_40"
	for _, key := range []string{before, after} {
		if err := s.Put(ctx, key, bytes.NewReader(blob(key, 40))); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// The legacy object is served by passthrough.
	if got := readObj(t, s, legacyKey, 0, -1); !bytes.Equal(got, legacyData) {
		t.Fatalf("legacy Get mismatch (%d bytes)", len(got))
	}
	obj, err := s.Head(ctx, legacyKey)
	if err != nil {
		t.Fatalf("legacy Head: %v", err)
	}
	if obj.Size() != int64(len(legacyData)) {
		t.Fatalf("legacy Head size = %d, want %d", obj.Size(), len(legacyData))
	}

	// The listing merges legacy and packed keys in sorted order.
	keys, sizes := listKeys(t, s, "chunks/")
	wantKeys := []string{before, legacyKey, after}
	if len(keys) != len(wantKeys) {
		t.Fatalf("ListAll = %v, want %v", keys, wantKeys)
	}
	for i := range wantKeys {
		if keys[i] != wantKeys[i] {
			t.Fatalf("ListAll = %v, want %v", keys, wantKeys)
		}
	}
	if sizes[legacyKey] != int64(len(legacyData)) {
		t.Fatalf("ListAll legacy size = %d, want %d", sizes[legacyKey], len(legacyData))
	}

	// A packed write of the same key shadows the legacy object.
	packedData := blob("packed-replacement", 123)
	if err := s.Put(ctx, legacyKey, bytes.NewReader(packedData)); err != nil {
		t.Fatalf("Put packed %s: %v", legacyKey, err)
	}
	if got := readObj(t, s, legacyKey, 0, -1); !bytes.Equal(got, packedData) {
		t.Fatalf("pending packed entry did not shadow legacy on Get")
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := readObj(t, s, legacyKey, 0, -1); !bytes.Equal(got, packedData) {
		t.Fatalf("packed entry did not shadow legacy on Get after flush")
	}

	// The listing must emit the shadowed key exactly once, with the PACKED
	// entry's view (size 123), matching what Get and Head serve.
	keys, sizes = listKeys(t, s, "chunks/")
	count := 0
	for _, k := range keys {
		if k == legacyKey {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("ListAll emitted %s %d times, want exactly once: %v", legacyKey, count, keys)
	}
	if sizes[legacyKey] != int64(len(packedData)) {
		t.Fatalf("ListAll size for shadowed key = %d, want packed %d", sizes[legacyKey], len(packedData))
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("ListAll keys not sorted: %v", keys)
	}

	// A fresh instance sees the packed data too.
	fresh := newPack(t, inner, Config{})
	if got := readObj(t, fresh, legacyKey, 0, -1); !bytes.Equal(got, packedData) {
		t.Fatalf("fresh instance served legacy data instead of packed")
	}
}

func TestAutoCutMultiplePacks(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true, TargetSize: 1000})

	want := make(map[string][]byte)
	for i := 0; i < 9; i++ {
		key := fmt.Sprintf("chunks/0/0/%d_0_400", i+1)
		want[key] = blob(key, 400)
		if err := s.Put(ctx, key, bytes.NewReader(want[key])); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}

	// The cut runs BEFORE an append that would exceed the 1000-byte target:
	// two 400-byte entries fit (800), the third triggers a seal first. Nine
	// puts therefore auto-cut four 2-entry packs and leave the ninth entry
	// pending — the unsealed spool never exceeds the target.
	packs := diskFiles(t, filepath.Join(vol, PackDirKey))
	if len(packs) != 4 {
		t.Fatalf("auto-cut produced %d packs, want 4: %v", len(packs), packs)
	}
	if got := s.PendingBlocks(); got != 1 {
		t.Fatalf("PendingBlocks = %d, want 1", got)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("final Flush: %v", err)
	}
	if got := s.PendingBlocks(); got != 0 {
		t.Fatalf("PendingBlocks after final Flush = %d, want 0", got)
	}

	fresh := newPack(t, inner, Config{})
	keys, _ := listKeys(t, fresh, "chunks/")
	if len(keys) != len(want) {
		t.Fatalf("fresh ListAll returned %d keys, want %d", len(keys), len(want))
	}
	for key, data := range want {
		if got := readObj(t, fresh, key, 0, -1); !bytes.Equal(got, data) {
			t.Fatalf("fresh Get %s mismatch", key)
		}
	}
}

func TestConcurrentPutFlushDurability(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true, TargetSize: 8 << 10})

	const writers = 4
	const perWriter = 25

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				key := fmt.Sprintf("chunks/%d/0/%d_0_300", w, i+1)
				if err := s.Put(ctx, key, bytes.NewReader(blob(key, 300))); err != nil {
					t.Errorf("Put %s: %v", key, err)
					return
				}
			}
		}(w)
	}

	// A flusher races the writers, exercising the spool-swap path in Flush.
	done := make(chan struct{})
	var flusher sync.WaitGroup
	flusher.Add(1)
	go func() {
		defer flusher.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if err := s.Flush(ctx); err != nil {
				t.Errorf("concurrent Flush: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	close(done)
	flusher.Wait()
	if t.Failed() {
		t.FailNow()
	}

	// Durability contract: after a final Flush, everything ever Put is
	// visible to a brand-new instance over the same inner store.
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("final Flush: %v", err)
	}
	if got := s.PendingBlocks(); got != 0 {
		t.Fatalf("PendingBlocks after final Flush = %d, want 0", got)
	}

	fresh := newPack(t, inner, Config{})
	keys, sizes := listKeys(t, fresh, "chunks/")
	if len(keys) != writers*perWriter {
		t.Fatalf("fresh ListAll returned %d keys, want %d", len(keys), writers*perWriter)
	}
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			key := fmt.Sprintf("chunks/%d/0/%d_0_300", w, i+1)
			if sizes[key] != 300 {
				t.Fatalf("fresh ListAll size for %s = %d, want 300", key, sizes[key])
			}
			if got := readObj(t, fresh, key, 0, -1); !bytes.Equal(got, blob(key, 300)) {
				t.Fatalf("fresh Get %s mismatch", key)
			}
		}
	}
}

func TestReadOnlyPutPassthrough(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	ro := newPack(t, inner, Config{}) // WriteEnabled=false: v1 write behavior

	key := "chunks/0/0/9_0_32"
	data := blob(key, 32)
	if err := ro.Put(ctx, key, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}

	// The block lands as a plain per-key object in the inner store.
	onDisk, err := os.ReadFile(filepath.Join(vol, "chunks/0/0/9_0_32"))
	if err != nil {
		t.Fatalf("per-key object not on origin disk: %v", err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Fatalf("per-key object has wrong contents (%d bytes)", len(onDisk))
	}
	if packs := diskFiles(t, filepath.Join(vol, PackDirKey)); len(packs) != 0 {
		t.Fatalf("read-only instance created packs: %v", packs)
	}

	if got := readObj(t, ro, key, 0, -1); !bytes.Equal(got, data) {
		t.Fatalf("Get %s mismatch", key)
	}
	obj, err := ro.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head %s: %v", key, err)
	}
	if obj.Size() != int64(len(data)) {
		t.Fatalf("Head %s size = %d, want %d", key, obj.Size(), len(data))
	}
}

// TestOverwriteChurnCompactsAtCut models a file (or hot 32KB byte range)
// overwritten repeatedly within one pack window: each version is a new
// block key, and JuiceFS chunk compaction tombstones the stale versions
// (blob.Delete) while they are still pending in the spool. The cut-time
// compaction must upload only the surviving version — blocks that die
// young never reach the federation.
func TestOverwriteChurnCompactsAtCut(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	s := newPack(t, inner, Config{TargetSize: 1 << 30, WriteEnabled: true})

	const versions = 10
	const blockSize = 32 << 10
	var lastKey string
	for v := 1; v <= versions; v++ {
		key := fmt.Sprintf("chunks/0/0/%d_0_%d", v, blockSize)
		if err := s.Put(ctx, key, bytes.NewReader(blob(key, blockSize))); err != nil {
			t.Fatalf("Put v%d: %v", v, err)
		}
		if lastKey != "" {
			if err := s.Delete(ctx, lastKey); err != nil {
				t.Fatalf("Delete stale v%d: %v", v-1, err)
			}
		}
		lastKey = key
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// One pack, sized for ONE version plus the index — not ten.
	packs, err := filepath.Glob(filepath.Join(vol, "packs", "*"))
	if err != nil || len(packs) != 1 {
		t.Fatalf("packs on origin = %v (err %v), want exactly 1", packs, err)
	}
	fi, err := os.Stat(packs[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() >= 2*blockSize {
		t.Fatalf("pack is %d bytes; churn was uploaded instead of compacted (want < %d)", fi.Size(), 2*blockSize)
	}
	if fi.Size() < blockSize {
		t.Fatalf("pack is %d bytes; live version missing", fi.Size())
	}

	// The survivor reads back (fresh instance too); stale versions are gone.
	if got := readObj(t, s, lastKey, 0, -1); !bytes.Equal(got, blob(lastKey, blockSize)) {
		t.Fatalf("live version corrupted")
	}
	fresh := newPack(t, inner, Config{})
	if got := readObj(t, fresh, lastKey, 0, -1); !bytes.Equal(got, blob(lastKey, blockSize)) {
		t.Fatalf("fresh instance: live version corrupted")
	}
	for v := 1; v < versions; v++ {
		key := fmt.Sprintf("chunks/0/0/%d_0_%d", v, blockSize)
		if _, err := fresh.Head(ctx, key); err == nil {
			t.Fatalf("stale version %s still visible", key)
		}
	}
}

// TestRepackReclaimsGarbage models overwrite churn that OUTLIVES the pack
// window: versions sealed into packs die later (tombstoned after upload),
// and repack must bound the resulting space — rewriting survivors into a
// new pack and deleting the sparse packs whole, with no tombstones needed
// (name-order shadowing) and idempotently.
func TestRepackReclaimsGarbage(t *testing.T) {
	ctx := context.Background()
	inner, vol := newInner(t)
	cfg := Config{
		WriteEnabled:     true,
		TargetSize:       1 << 30,
		RepackMinGarbage: 1,
		RepackAgeFloor:   time.Nanosecond,
	}
	s := newPack(t, inner, cfg)

	// Pack 1: six versions sealed while all still live.
	const n = 6
	const sz = 4 << 10
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("chunks/0/0/%d_0_%d", i+1, sz)
		if err := s.Put(ctx, keys[i], bytes.NewReader(blob(keys[i], sz))); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Churn after the seal: four of six die; the tombstones seal into a
	// second (tiny) pack alongside one fresh key.
	for _, k := range keys[:4] {
		if err := s.Delete(ctx, k); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}
	fresh := "chunks/0/0/9_0_" + fmt.Sprint(sz)
	if err := s.Put(ctx, fresh, bytes.NewReader(blob(fresh, sz))); err != nil {
		t.Fatalf("Put fresh: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}

	garbage := s.Garbage()
	if garbage != 4*sz {
		t.Fatalf("Garbage = %d, want %d", garbage, 4*sz)
	}
	packsBefore := diskFiles(t, filepath.Join(vol, PackDirKey))

	if err := s.Repack(ctx); err != nil {
		t.Fatalf("Repack: %v", err)
	}
	if g := s.Garbage(); g != 0 {
		t.Fatalf("Garbage after repack = %d, want 0", g)
	}
	packsAfter := diskFiles(t, filepath.Join(vol, PackDirKey))
	if len(packsAfter) >= len(packsBefore)+1 {
		t.Fatalf("repack did not delete the sparse pack: before=%d after=%d", len(packsBefore), len(packsAfter))
	}
	var total int64
	for _, p := range packsAfter {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total >= int64(n+1)*sz {
		t.Fatalf("stored bytes %d not reduced (live is %d)", total, 3*sz)
	}

	// Survivors intact — including from a cold bootstrap.
	ro := newPack(t, inner, Config{})
	for _, k := range append([]string{fresh}, keys[4:]...) {
		if got := readObj(t, ro, k, 0, -1); !bytes.Equal(got, blob(k, sz)) {
			t.Fatalf("survivor %s corrupted after repack", k)
		}
	}
	for _, k := range keys[:4] {
		if _, err := ro.Head(ctx, k); err == nil {
			t.Fatalf("deleted key %s visible after repack", k)
		}
	}

	// Idempotent: a second pass has nothing to do.
	if err := s.Repack(ctx); err != nil {
		t.Fatalf("second Repack: %v", err)
	}
}

// rangeLiar wraps a store and ignores Get ranges, always returning the
// whole object from offset zero — modeling a federation transport that
// mishandles Range requests (the observed "bad pack magic" failure).
type rangeLiar struct {
	pelicanobj.Store
}

func (r rangeLiar) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	return r.Store.Get(ctx, key, 0, -1)
}

// TestBootstrapSurvivesRangeLiar: when the tail range probe returns wrong
// bytes, bootstrap must fall back to a whole-object fetch, warn, and still
// build a correct index rather than refusing to mount.
func TestBootstrapSurvivesRangeLiar(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	s := newPack(t, inner, Config{WriteEnabled: true})
	want := make(map[string][]byte)
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("chunks/0/0/%d_0_128", i+1)
		want[key] = blob(key, 128)
		if err := s.Put(ctx, key, bytes.NewReader(want[key])); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	liar := rangeLiar{Store: inner}
	ro, err := New(ctx, liar, Config{})
	if err != nil {
		t.Fatalf("bootstrap over range-lying transport failed: %v", err)
	}
	keys, sizes := listKeys(t, ro, "chunks/")
	if len(keys) != len(want) {
		t.Fatalf("ListAll = %d keys, want %d", len(keys), len(want))
	}
	for key, data := range want {
		if sizes[key] != int64(len(data)) {
			t.Fatalf("size for %s = %d, want %d", key, sizes[key], len(data))
		}
	}
}
