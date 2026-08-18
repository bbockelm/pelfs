package publish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
)

// memSource is the write path's shape, with the metadata half stubbed
// down to a map: a flat namespace whose CONTENT lives in a memtable —
// chunked and uploaded while the writes were happening, not at seal.
//
// It is what proves the ContentProvider seam end to end. Everything a
// seal normally does to a file's bytes (open, read, CDC, hash, pack,
// upload) has already happened by the time this source is walked, and the
// test's assertion is that the seal does none of it again and the
// generation still reads back byte-exact through genfs.
type memSource struct {
	store  *memtable.Store
	sealer *memtable.Sealer
	names  []string
	nodes  map[uint64]publish.SrcNode
	ino    map[string]uint64
	next   uint64
}

var (
	_ publish.Source          = (*memSource)(nil)
	_ publish.ContentProvider = (*memSource)(nil)
)

func newMemSource(t *testing.T, obj *countingObjStore) *memSource {
	t.Helper()
	store, err := memtable.New(memtable.Options{
		Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatalf("memtable.New: %v", err)
	}
	t.Cleanup(func() { store.Close() }) //nolint:errcheck
	return &memSource{
		store: store,
		nodes: map[uint64]publish.SrcNode{},
		ino:   map[string]uint64{},
		next:  2,
	}
}

// write puts one file in the flat namespace and its bytes in the ring.
func (m *memSource) write(t *testing.T, name string, body []byte) {
	t.Helper()
	ino, ok := m.ino[name]
	if !ok {
		ino = m.next
		m.next++
		m.ino[name] = ino
		m.names = append(m.names, name)
		sort.Strings(m.names)
	}
	if err := m.store.Write(context.Background(), ino, 0, body); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	m.store.Truncate(ino, int64(len(body)))
	m.nodes[ino] = publish.SrcNode{
		Inode: ino, Type: catalog.TypeFile, Mode: 0644, Nlink: 1,
		Length: m.store.Size(ino), MtimeNS: 1, CtimeNS: 1,
	}
}

// patch overwrites part of a file, which is what makes a seal have to
// re-chunk rather than merely name what is already packed.
func (m *memSource) patch(t *testing.T, name string, off int64, body []byte) {
	t.Helper()
	if err := m.store.Write(context.Background(), m.ino[name], off, body); err != nil {
		t.Fatalf("patch %s: %v", name, err)
	}
}

func (m *memSource) Root() uint64      { return genfs.RootInode }
func (m *memSource) NextInode() uint64 { return m.next }

func (m *memSource) Readdir(_ context.Context, ino uint64) ([]publish.SrcEntry, error) {
	if ino != genfs.RootInode {
		return nil, nil
	}
	out := make([]publish.SrcEntry, 0, len(m.names))
	for _, name := range m.names {
		out = append(out, publish.SrcEntry{Name: name, Node: m.nodes[m.ino[name]]})
	}
	return out, nil
}

func (m *memSource) Stat(_ context.Context, ino uint64) (publish.SrcNode, error) {
	if ino == genfs.RootInode {
		return publish.SrcNode{Inode: ino, Type: catalog.TypeDir, Mode: 0755, Nlink: 2}, nil
	}
	n, ok := m.nodes[ino]
	if !ok {
		return publish.SrcNode{}, fmt.Errorf("no inode %d", ino)
	}
	return n, nil
}

func (m *memSource) Readlink(context.Context, uint64) (string, error) {
	return "", fmt.Errorf("no symlinks here")
}

func (m *memSource) Xattrs(context.Context, uint64) (map[string][]byte, error) { return nil, nil }

// Open is the fallback path: publish reaches it only for content the
// provider declined, which here is the inline-sized files.
func (m *memSource) Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	buf := make([]byte, length)
	if _, err := m.store.Read(ctx, ino, 0, buf); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buf)), nil
}

func (m *memSource) ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	n, ok := m.nodes[ino]
	if !ok {
		return genfs.Content{}, false, nil
	}
	if m.sealer == nil {
		m.sealer = m.store.NewSealer()
	}
	refs, err := m.sealer.Inode(ctx, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return genfs.Content{Length: n.Length, Refs: refs}, true, nil
}

func (m *memSource) ProvidedPacks(ctx context.Context) ([]packstore.SealedPack, error) {
	if m.sealer != nil {
		if err := m.sealer.Finish(ctx); err != nil {
			return nil, err
		}
		m.sealer = nil
	}
	return m.store.Packs(), nil
}

// countingObjStore counts what a seal moves. The claim under test is
// about what does NOT happen during the seal, so the store has to be able
// to say that nothing did.
type countingObjStore struct {
	pelicanobj.Store
	puts int
}

func (c *countingObjStore) Put(ctx context.Context, key string, in io.Reader) error {
	if strings.HasPrefix(key, packstore.PackDirKey+"/") {
		c.puts++
	}
	return c.Store.Put(ctx, key, in)
}

// The whole loop: bytes packed during the session, a seal that publishes
// them without reading or re-chunking a byte, and a generation that reads
// back through genfs like any other.
func TestSealPublishesContentTheSourcePacked(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gen0, err := publish.InitVolume(ctx, publish.Options{
		Inner: obj, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0xd0, 0x0d},
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	src := newMemSource(t, obj)
	want := map[string][]byte{
		"big.bin":    bytesPattern(200000, 1),
		"medium.bin": bytesPattern(60000, 2),
		"tiny.txt":   []byte("inline, so the provider declines it"),
	}
	for _, name := range []string{"big.bin", "medium.bin", "tiny.txt"} {
		src.write(t, name, want[name])
	}
	// Flush during the session: this is the whole point — the bytes are in
	// packs on the federation before the seal begins.
	if err := src.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// Then a partial rewrite, so the seal has something it cannot express
	// as whole chunks and must re-chunk.
	patch := bytesPattern(400, 9)
	src.patch(t, "big.bin", 5000, patch)
	copy(want["big.bin"][5000:], patch)
	if err := src.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	sessionPuts := obj.puts

	res, err := publish.Publish(ctx, publish.Options{
		Source: src, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: gen0.Superblock, PrevRaw: gen0.Raw,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if res.Stats.ProvidedFiles != 2 {
		t.Errorf("%d files provided, want the two chunked ones (%+v)", res.Stats.ProvidedFiles, res.Stats)
	}
	if res.Stats.ChunksAdded != 0 {
		t.Errorf("the seal chunked %d new chunks; the source had already packed its content", res.Stats.ChunksAdded)
	}
	if res.Stats.InlineFiles != 1 {
		t.Errorf("%d inline files, want the one below the threshold", res.Stats.InlineFiles)
	}

	// Every pack the source made must be listed, or the chunkrefs name
	// bytes that retention is entitled to delete.
	listed := map[string]bool{}
	for _, e := range res.Superblock.PackList {
		listed[e.Name] = true
	}
	for _, sp := range src.store.Packs() {
		if !listed[sp.Name] {
			t.Fatalf("pack %s holds provided content and is not in the generation's pack list", sp.Name)
		}
	}

	// And the generation reads back through the ordinary reader, which
	// knows nothing about any of this.
	fs := openGenfs(t, obj, res.Superblock, nil)
	for name, body := range want {
		n, err := fs.Lookup(ctx, genfs.RootInode, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if n.Length != int64(len(body)) {
			t.Fatalf("%s: length %d, want %d", name, n.Length, len(body))
		}
		got := make([]byte, n.Length)
		if _, err := fs.Read(ctx, n.Inode, 0, got); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("%s does not read back byte-exact", name)
		}
	}
	t.Logf("session uploaded %d packs, the seal added %d", sessionPuts, obj.puts-sessionPuts)
}

func bytesPattern(n int, seed uint64) []byte {
	out := make([]byte, n)
	x := seed*2862933555777941757 + 3037000493
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = byte(x >> 33)
	}
	return out
}
