package publish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// newInner starts a fakeorigin-backed pelicanobj store rooted at /vol (the
// packstore test pattern).
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

// testVolume is a live JuiceFS volume the tests mutate and cut (the cutdb
// test pattern, extended with cut snapshots via VACUUM INTO).
type testVolume struct {
	t        *testing.T
	metaPath string
	m        meta.Meta
	blob     object.ObjectStorage
	store    chunk.ChunkStore
	cuts     int
}

func newTestVolume(t *testing.T, uuid string) *testVolume {
	t.Helper()
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format := &meta.Format{
		Name:      "publish-test",
		UUID:      uuid,
		Storage:   "mem",
		BlockSize: 4096, // KiB
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("init meta: %v", err)
	}
	if err := m.NewSession(true); err != nil {
		t.Fatalf("session: %v", err)
	}
	t.Cleanup(func() { _ = m.CloseSession() })

	blob, err := object.CreateStorage("mem", "", "", "", "")
	if err != nil {
		t.Fatalf("mem store: %v", err)
	}
	store := chunk.NewCachedStore(blob, chunk.Config{
		BlockSize:  format.BlockSize * 1024,
		CacheDir:   "memory",
		CacheSize:  64 << 20,
		GetTimeout: 10 * time.Second, PutTimeout: 10 * time.Second,
		MaxUpload: 2, MaxDownload: 2, MaxRetries: 1, BufferSize: 32 << 20,
	}, prometheus.NewRegistry())
	return &testVolume{t: t, metaPath: metaPath, m: m, blob: blob, store: store}
}

func (v *testVolume) ctx() meta.Context { return meta.WrapContext(context.Background()) }

func (v *testVolume) mkdir(parent uint64, name string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Mkdir(v.ctx(), meta.Ino(parent), name, 0755, 0, 0, &ino, &attr); st != 0 {
		v.t.Fatalf("mkdir %s: %s", name, st)
	}
	return uint64(ino)
}

func (v *testVolume) create(parent uint64, name string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Create(v.ctx(), meta.Ino(parent), name, 0644, 0, 0, &ino, &attr); st != 0 {
		v.t.Fatalf("create %s: %s", name, st)
	}
	return uint64(ino)
}

// write stores data as one slice at offset 0 of chunk 0 (data must fit one
// 64 MiB chunk).
func (v *testVolume) write(ino uint64, data []byte) {
	v.t.Helper()
	var sliceID uint64
	if st := v.m.NewSlice(v.ctx(), &sliceID); st != 0 {
		v.t.Fatalf("new slice: %s", st)
	}
	w := v.store.NewWriter(sliceID, 0)
	if _, err := w.WriteAt(data, 0); err != nil {
		v.t.Fatalf("write slice: %v", err)
	}
	if err := w.Finish(len(data)); err != nil {
		v.t.Fatalf("finish slice: %v", err)
	}
	s := meta.Slice{Id: sliceID, Size: uint32(len(data)), Len: uint32(len(data))}
	if st := v.m.Write(v.ctx(), meta.Ino(ino), 0, 0, s, time.Now()); st != 0 {
		v.t.Fatalf("meta write: %s", st)
	}
}

func (v *testVolume) symlink(parent uint64, name, target string) {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Symlink(v.ctx(), meta.Ino(parent), name, target, &ino, &attr); st != 0 {
		v.t.Fatalf("symlink %s: %s", name, st)
	}
}

func (v *testVolume) link(ino, parent uint64, name string) {
	v.t.Helper()
	var attr meta.Attr
	if st := v.m.Link(v.ctx(), meta.Ino(ino), meta.Ino(parent), name, &attr); st != 0 {
		v.t.Fatalf("link %s: %s", name, st)
	}
}

func (v *testVolume) setxattr(ino uint64, name string, value []byte) {
	v.t.Helper()
	if st := v.m.SetXattr(v.ctx(), meta.Ino(ino), name, value, 0); st != 0 {
		v.t.Fatalf("setxattr %s: %s", name, st)
	}
}

// cut takes the publish-time metadata snapshot: VACUUM INTO a fresh file,
// exactly what the session's CUT stage produces.
func (v *testVolume) cut() string {
	v.t.Helper()
	v.cuts++
	dst := filepath.Join(v.t.TempDir(), fmt.Sprintf("cut-%d.db", v.cuts))
	db, err := sql.Open("sqlite", "file:"+v.metaPath+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		v.t.Fatalf("open meta for cut: %v", err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", dst)); err != nil {
		v.t.Fatalf("vacuum into: %v", err)
	}
	return dst
}

// pseudorandom returns deterministic incompressible content.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// entryLoc is where one entry lives: which pack, and the byte range.
type entryLoc struct {
	pack   string
	off    int64
	length int64
}

// readEnv reads published artifacts back the way any reader does: build
// the entry index from every pack's trailer, fetch entries as ranges,
// decode them, and reopen catalogs from the resulting bytes.
type readEnv struct {
	t      *testing.T
	inner  pelicanobj.Store
	index  map[string]entryLoc
	dek    []byte
	hasher chunkid.Hasher
	dir    string
	n      int
}

func newReadEnv(t *testing.T, inner pelicanobj.Store, dek, identityKey []byte) *readEnv {
	t.Helper()
	ctx := context.Background()
	index := make(map[string]entryLoc)
	packs, err := inner.ListDir(ctx, packstore.PackDirKey)
	if err != nil {
		t.Fatalf("list packs: %v", err)
	}
	for _, p := range packs {
		if p.IsDir || !strings.HasPrefix(p.Name, "p-") {
			continue
		}
		entries, err := packstore.FetchTrailer(ctx, inner, p.Name, p.Size)
		if err != nil {
			t.Fatalf("trailer of %s: %v", p.Name, err)
		}
		for _, pe := range entries {
			index[pe.Key] = entryLoc{pack: p.Name, off: pe.Off, length: pe.Length}
		}
	}
	return &readEnv{t: t, inner: inner, index: index, dek: dek,
		hasher: chunkid.NewHasher(identityKey), dir: t.TempDir()}
}

func (e *readEnv) entry(key string) []byte {
	e.t.Helper()
	loc, ok := e.index[key]
	if !ok {
		e.t.Fatalf("no pack holds entry %s", key)
	}
	rc, err := e.inner.Get(context.Background(), packstore.PackDirKey+"/"+loc.pack, loc.off, loc.length)
	if err != nil {
		e.t.Fatalf("read entry %s: %v", key, err)
	}
	defer rc.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(rc, loc.length))
	if err != nil {
		e.t.Fatalf("read entry %s: %v", key, err)
	}
	return data
}

// openCatalog fetches a catalog/shard entry, decodes it (catalog entries
// are always AlgZstd — nothing references them with an alg column),
// verifies its identity, and opens it from a temp file.
func (e *readEnv) openCatalog(identity []byte) *catalog.Catalog {
	e.t.Helper()
	stored := e.entry(hex.EncodeToString(identity))
	plain, err := entrycodec.Decode(stored, entrycodec.AlgZstd, e.dek)
	if err != nil {
		e.t.Fatalf("decode catalog %x: %v", identity, err)
	}
	if id := e.hasher.Sum(plain); !bytes.Equal(id[:], identity) {
		e.t.Fatalf("catalog identity mismatch: got %s, want %x", id.Hex(), identity)
	}
	e.n++
	fp := filepath.Join(e.dir, fmt.Sprintf("cat-%d.db", e.n))
	if err := os.WriteFile(fp, plain, 0600); err != nil {
		e.t.Fatal(err)
	}
	c, err := catalog.Open(fp)
	if err != nil {
		e.t.Fatalf("open catalog %x: %v", identity, err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	return c
}

// readChunks reassembles a chunked file from its chunkrefs via pack reads,
// verifying stored lengths and identities along the way.
func (e *readEnv) readChunks(c *catalog.Catalog, ino int64) []byte {
	e.t.Helper()
	refs, err := c.Chunks(ino)
	if err != nil {
		e.t.Fatalf("chunks of %d: %v", ino, err)
	}
	var buf bytes.Buffer
	for i, r := range refs {
		stored := e.entry(hex.EncodeToString(r.Identity))
		if int64(len(stored)) != r.CLen {
			e.t.Fatalf("chunk %d: stored %d bytes, clen %d", i, len(stored), r.CLen)
		}
		plain, err := entrycodec.Decode(stored, uint8(r.Alg), e.dek)
		if err != nil {
			e.t.Fatalf("chunk %d decode: %v", i, err)
		}
		if int64(len(plain)) != r.LLen {
			e.t.Fatalf("chunk %d: %d bytes, llen %d", i, len(plain), r.LLen)
		}
		if id := e.hasher.Sum(plain); !bytes.Equal(id[:], r.Identity) {
			e.t.Fatalf("chunk %d identity mismatch", i)
		}
		buf.Write(plain)
	}
	return buf.Bytes()
}

// fetchRef reads a mutable ref object directly from the inner store.
func fetchRef(t *testing.T, inner pelicanobj.Store, key string) []byte {
	t.Helper()
	rc, err := inner.Get(context.Background(), key, 0, -1)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	defer rc.Close() //nolint:errcheck
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return data
}

func direntNames(ds []catalog.Dirent) []string {
	var out []string
	for _, d := range ds {
		out = append(out, string(d.Name))
	}
	return out
}

func TestPublishEndToEnd(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b")

	bigContent := pseudorandom(6<<20, 42)
	smallContent := []byte("hello inline world, generation zero")
	hardContent := pseudorandom(100, 7)

	dirIno := v.mkdir(publishRootInode, "dir")
	smallIno := v.create(dirIno, "small.txt")
	v.write(smallIno, smallContent)
	v.setxattr(smallIno, "user.color", []byte("blue"))
	v.symlink(dirIno, "link", "small.txt")
	big1Ino := v.create(publishRootInode, "big.bin")
	v.write(big1Ino, bigContent)
	big2Ino := v.create(publishRootInode, "big2.bin")
	v.write(big2Ino, bigContent) // identical content: within-publish dedup
	hardIno := v.create(publishRootInode, "hard1")
	v.write(hardIno, hardContent)
	v.link(hardIno, dirIno, "hard2")
	cut := v.cut()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := publish.Publish(ctx, publish.Options{
		CutPath:         cut,
		Blob:            v.blob,
		CacheDir:        t.TempDir(),
		Inner:           inner,
		SpoolDir:        t.TempDir(),
		SigningKey:      priv,
		TargetPackSize:  2 << 20, // force multiple packs from 6 MiB of chunks
		SMax:            1000,    // force /dir into a nested catalog
		CreatedUnixNano: 424242,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// The flipped superblock.
	sb := res.Superblock
	if sb.Generation != 0 {
		t.Fatalf("generation = %d, want 0", sb.Generation)
	}
	if sb.PrevHash != [32]byte{} {
		t.Fatalf("first generation has a nonzero PrevHash")
	}
	if sb.CreatedUnixNano != 424242 {
		t.Fatalf("CreatedUnixNano = %d", sb.CreatedUnixNano)
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("superblock verify: %v", err)
	}

	// refs/main holds exactly the returned wire bytes and decodes+verifies.
	refRaw := fetchRef(t, inner, "refs/main")
	if !bytes.Equal(refRaw, res.Raw) {
		t.Fatalf("refs/main differs from Result.Raw")
	}
	decoded, err := superblock.Decode(refRaw)
	if err != nil {
		t.Fatalf("decode ref: %v", err)
	}
	if err := decoded.Verify(pub); err != nil {
		t.Fatalf("verify ref: %v", err)
	}

	// Every listed pack exists as an object of the recorded size, and the
	// new packs are exactly the pack list (first generation).
	if len(res.NewPacks) < 2 {
		t.Fatalf("expected multiple packs at a 2 MiB target, got %d", len(res.NewPacks))
	}
	if len(sb.PackList) != len(res.NewPacks) {
		t.Fatalf("pack list has %d entries, new packs %d", len(sb.PackList), len(res.NewPacks))
	}
	var packBytes int64
	for _, pe := range sb.PackList {
		info, err := inner.StatKey(ctx, packstore.PackDirKey+"/"+pe.Name)
		if err != nil {
			t.Fatalf("pack %s missing: %v", pe.Name, err)
		}
		if info.Size != pe.Size {
			t.Fatalf("pack %s is %d bytes, list says %d", pe.Name, info.Size, pe.Size)
		}
		packBytes += pe.Size
	}
	// Dedup: two identical 6 MiB files must not store their chunks twice.
	if packBytes >= 9<<20 {
		t.Fatalf("packs total %d bytes; identical file content was not deduped", packBytes)
	}

	env := newReadEnv(t, inner, nil, nil)

	// Root catalog: covers "/", carries the root-level entries, and holds
	// /dir as a transition point carrying BOTH halves — its dirent and
	// node row (lookup/stat without the child catalog) plus the nested
	// locator (SMax forced the split).
	root := env.openCatalog(sb.RootCatalog[:])
	if m := root.Meta(); m.CoveredPath != "/" || m.Generation != 0 || m.VolumeUUID != "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b" {
		t.Fatalf("root catalog meta = %+v", m)
	}
	dirents, nesteds, err := root.Readdir(publishRootInode)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := direntNames(dirents), []string{"big.bin", "big2.bin", "dir", "hard1"}; !equalStrings(got, want) {
		t.Fatalf("root dirents = %v, want %v", got, want)
	}
	if len(nesteds) != 1 || string(nesteds[0].Name) != "dir" {
		t.Fatalf("root nested rows = %+v, want one transition for dir", nesteds)
	}
	lr, err := root.Lookup(publishRootInode, []byte("dir"))
	if err != nil || lr.Dirent == nil || lr.NestedIdentity == nil {
		t.Fatalf("transition lookup = %+v err=%v, want dirent AND nested identity", lr, err)
	}
	if dn, err := root.Stat(lr.Dirent.Inode); err != nil || dn.Type != catalog.TypeDir {
		t.Fatalf("transition dir not statable in the parent catalog: %+v err=%v", dn, err)
	}
	if _, err := root.Stat(int64(smallIno)); !errors.Is(err, catalog.ErrNotExist) {
		t.Fatalf("small.txt leaked into the root catalog (err=%v)", err)
	}

	// The chunked file reassembles byte-exact, and its twin shares the
	// exact same chunk list.
	n1, err := root.Stat(int64(big1Ino))
	if err != nil {
		t.Fatal(err)
	}
	if n1.Length != int64(len(bigContent)) || n1.Type != catalog.TypeFile {
		t.Fatalf("big.bin node = %+v", n1)
	}
	if got := env.readChunks(root, int64(big1Ino)); !bytes.Equal(got, bigContent) {
		t.Fatalf("big.bin content mismatch (%d bytes)", len(got))
	}
	refs1, _ := root.Chunks(int64(big1Ino))
	refs2, _ := root.Chunks(int64(big2Ino))
	if len(refs1) == 0 || len(refs1) != len(refs2) {
		t.Fatalf("chunk lists differ: %d vs %d", len(refs1), len(refs2))
	}
	for i := range refs1 {
		if !bytes.Equal(refs1[i].Identity, refs2[i].Identity) {
			t.Fatalf("chunk %d identity differs between identical files", i)
		}
	}
	if res.Stats.ChunksAdded != len(refs1) || res.Stats.ChunksDeduped != len(refs2) {
		t.Fatalf("stats: added %d deduped %d, want %d/%d",
			res.Stats.ChunksAdded, res.Stats.ChunksDeduped, len(refs1), len(refs2))
	}

	// Nested catalog: /dir with the inline file, symlink, xattr.
	dirCat := env.openCatalog(nesteds[0].CatalogIdentity)
	if m := dirCat.Meta(); m.CoveredPath != "/dir" {
		t.Fatalf("dir catalog covers %q", m.CoveredPath)
	}
	dirents, nesteds, err = dirCat.Readdir(int64(dirIno))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := direntNames(dirents), []string{"hard2", "link", "small.txt"}; !equalStrings(got, want) {
		t.Fatalf("dir dirents = %v, want %v", got, want)
	}
	if len(nesteds) != 0 {
		t.Fatalf("dir catalog has unexpected transitions: %+v", nesteds)
	}
	ns, err := dirCat.Stat(int64(smallIno))
	if err != nil {
		t.Fatal(err)
	}
	if ns.Length != int64(len(smallContent)) {
		t.Fatalf("small.txt length = %d, want %d", ns.Length, len(smallContent))
	}
	inline, err := dirCat.Inline(int64(smallIno))
	if err != nil || !bytes.Equal(inline, smallContent) {
		t.Fatalf("small.txt inline = %q (%v)", inline, err)
	}
	xs, err := dirCat.Xattrs(int64(smallIno))
	if err != nil || len(xs) != 1 || string(xs[0].Name) != "user.color" || string(xs[0].Value) != "blue" {
		t.Fatalf("small.txt xattrs = %+v (%v)", xs, err)
	}
	var linkIno int64
	for _, d := range dirents {
		if string(d.Name) == "link" {
			linkIno = d.Inode
		}
	}
	target, err := dirCat.Symlink(linkIno)
	if err != nil || string(target) != "small.txt" {
		t.Fatalf("symlink target = %q (%v)", target, err)
	}

	// Hardlink pair: both edges present, nlink 2 everywhere, content
	// recorded once — in the inode shard, not in either path catalog.
	for _, c := range []*catalog.Catalog{root, dirCat} {
		n, err := c.Stat(int64(hardIno))
		if err != nil {
			t.Fatalf("hardlink node missing from a path catalog: %v", err)
		}
		if n.Nlink != 2 {
			t.Fatalf("hardlink nlink = %d, want 2", n.Nlink)
		}
		if data, err := c.Inline(int64(hardIno)); err != nil || data != nil {
			t.Fatalf("hardlink content leaked into a path catalog (%d bytes, %v)", len(data), err)
		}
		if refs, err := c.Chunks(int64(hardIno)); err != nil || refs != nil {
			t.Fatalf("hardlink chunkrefs leaked into a path catalog (%v, %v)", refs, err)
		}
	}
	if len(sb.Shards) != 1 {
		t.Fatalf("shards = %+v, want exactly one", sb.Shards)
	}
	sh := sb.Shards[0]
	if sh.FirstInode > hardIno || hardIno > sh.LastInode {
		t.Fatalf("shard range [%d,%d] misses inode %d", sh.FirstInode, sh.LastInode, hardIno)
	}
	shard := env.openCatalog(sh.Identity[:])
	hn, err := shard.Stat(int64(hardIno))
	if err != nil || hn.Nlink != 2 {
		t.Fatalf("shard node = %+v (%v)", hn, err)
	}
	if data, err := shard.Inline(int64(hardIno)); err != nil || !bytes.Equal(data, hardContent) {
		t.Fatalf("shard inline mismatch (%d bytes, %v)", len(data), err)
	}
	if res.Stats.PromotedInodes != 1 || res.Stats.Shards != 1 {
		t.Fatalf("stats = %+v, want one promoted inode in one shard", res.Stats)
	}

	// A signed superblock backup rides in the packs.
	if !findBackup(t, env, 0, pub) {
		t.Fatalf("no verifiable generation-0 superblock backup found in any pack")
	}

	// NextInode clears every inode the cut allocated.
	if sb.NextInode <= hardIno {
		t.Fatalf("NextInode = %d, not past max inode %d", sb.NextInode, hardIno)
	}
}

func TestPublishSecondGeneration(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "11112222-3333-4444-5555-666677778888")

	aContent := []byte("alpha file, stable across generations")
	bContent := []byte("beta file, first version")
	dirIno := v.mkdir(publishRootInode, "d")
	aIno := v.create(dirIno, "a.txt")
	v.write(aIno, aContent)
	bIno := v.create(dirIno, "b.txt")
	v.write(bIno, bContent)
	cut1 := v.cut()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := publish.Options{
		Blob:       v.blob,
		Inner:      inner,
		SigningKey: priv,
	}
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut1, t.TempDir(), t.TempDir()
	res1, err := publish.Publish(ctx, opts)
	if err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if res1.Superblock.Generation != 0 {
		t.Fatalf("generation = %d, want 0", res1.Superblock.Generation)
	}

	// Re-publishing as a first generation must trip the flip guard.
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut1, t.TempDir(), t.TempDir()
	if _, err := publish.Publish(ctx, opts); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second first-generation publish should fail the flip guard, got %v", err)
	}

	// Modify one file, cut again, publish generation 1.
	bContent2 := []byte("beta file, second version, longer")
	v.write(bIno, bContent2)
	cut2 := v.cut()
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut2, t.TempDir(), t.TempDir()
	opts.Prev, opts.PrevRaw = res1.Superblock, res1.Raw
	res2, err := publish.Publish(ctx, opts)
	if err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	sb2 := res2.Superblock
	if sb2.Generation != 1 {
		t.Fatalf("generation = %d, want 1", sb2.Generation)
	}
	if want := superblock.Hash(res1.Raw); sb2.PrevHash != want {
		t.Fatalf("PrevHash does not match generation 0's wire bytes")
	}
	if err := superblock.VerifyChain(res1.Raw, sb2, pub); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !bytes.Equal(fetchRef(t, inner, "refs/main"), res2.Raw) {
		t.Fatalf("refs/main was not advanced to generation 1")
	}

	// Generation 0's packs carry forward; the new packs join them.
	names := make(map[string]bool)
	for _, pe := range sb2.PackList {
		names[pe.Name] = true
	}
	for _, pe := range res1.Superblock.PackList {
		if !names[pe.Name] {
			t.Fatalf("generation 0 pack %s dropped from generation 1's list", pe.Name)
		}
	}
	for _, sp := range res2.NewPacks {
		if !names[sp.Name] {
			t.Fatalf("new pack %s missing from generation 1's list", sp.Name)
		}
	}
	if sb2.RootCatalog == res1.Superblock.RootCatalog {
		t.Fatalf("root catalog identity unchanged despite a modified file")
	}

	// The changed content round-trips; the unchanged file is intact.
	env := newReadEnv(t, inner, nil, nil)
	root := env.openCatalog(sb2.RootCatalog[:])
	if root.Meta().Generation != 1 {
		t.Fatalf("root catalog generation = %d", root.Meta().Generation)
	}
	_, nesteds, err := root.Readdir(publishRootInode)
	if err != nil {
		t.Fatal(err)
	}
	c := root
	if len(nesteds) == 1 { // default SMax keeps this tree in one catalog, but stay robust
		c = env.openCatalog(nesteds[0].CatalogIdentity)
	}
	if data, err := c.Inline(int64(bIno)); err != nil || !bytes.Equal(data, bContent2) {
		t.Fatalf("b.txt = %q (%v), want the second version", data, err)
	}
	if data, err := c.Inline(int64(aIno)); err != nil || !bytes.Equal(data, aContent) {
		t.Fatalf("a.txt = %q (%v)", data, err)
	}
}

func TestPublishEncrypted(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "aaaabbbb-cccc-dddd-eeee-ffff00001111")

	secret := []byte("the inline secret")
	blob := pseudorandom(5<<20/2, 99) // 2.5 MiB, chunked
	dirIno := v.mkdir(publishRootInode, "enc")
	secretIno := v.create(dirIno, "secret.txt")
	v.write(secretIno, secret)
	blobIno := v.create(publishRootInode, "blob.bin")
	v.write(blobIno, blob)
	cut := v.cut()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dek := pseudorandom(32, 1)
	idKey := pseudorandom(32, 2)
	res, err := publish.Publish(ctx, publish.Options{
		CutPath:     cut,
		Blob:        v.blob,
		CacheDir:    t.TempDir(),
		Inner:       inner,
		SpoolDir:    t.TempDir(),
		SigningKey:  priv,
		IdentityKey: idKey,
		DEK:         dek,
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	sb := res.Superblock
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(sb.KeyTable) != 2 || sb.KeyTable[0].ID != 7 {
		t.Fatalf("key table = %+v", sb.KeyTable)
	}

	// Without the DEK the catalog entry is opaque.
	blind := newReadEnv(t, inner, nil, nil)
	storedRoot := blind.entry(hex.EncodeToString(sb.RootCatalog[:]))
	if _, err := entrycodec.Decode(storedRoot, entrycodec.AlgZstd, nil); err == nil {
		t.Fatalf("encrypted root catalog decoded without the DEK")
	}

	// With the keys, the full tree round-trips.
	env := newReadEnv(t, inner, dek, idKey)
	root := env.openCatalog(sb.RootCatalog[:])
	if algo := root.Meta().IdentityAlgo; algo != "blake3-256-keyed" {
		t.Fatalf("identity algo = %q", algo)
	}
	if data, err := root.Inline(int64(secretIno)); err != nil || !bytes.Equal(data, secret) {
		t.Fatalf("secret.txt = %q (%v)", data, err)
	}
	refs, err := root.Chunks(int64(blobIno))
	if err != nil || len(refs) == 0 {
		t.Fatalf("blob chunkrefs: %v (%v)", refs, err)
	}
	for i, r := range refs {
		if r.KeyID != 7 {
			t.Fatalf("chunk %d keyid = %d, want 7", i, r.KeyID)
		}
		// Ciphertext must not expose plaintext at the logical offset.
		stored := env.entry(hex.EncodeToString(r.Identity))
		if bytes.Contains(stored, blob[r.LogicalOffset:r.LogicalOffset+64]) {
			t.Fatalf("chunk %d stored bytes contain plaintext", i)
		}
	}
	if got := env.readChunks(root, int64(blobIno)); !bytes.Equal(got, blob) {
		t.Fatalf("blob content mismatch (%d bytes)", len(got))
	}
}

// findBackup scans every pack entry for a decodable, verifiable superblock
// backup of the wanted generation. Only the backup is stored as raw CBOR;
// chunk and catalog entries fail the decode.
func findBackup(t *testing.T, env *readEnv, wantGen uint64, pub ed25519.PublicKey) bool {
	t.Helper()
	found := false
	for key := range env.index {
		if len(key) != 64 { // pack entry keys are 32-byte identities in hex
			continue
		}
		sb, err := superblock.Decode(env.entry(key))
		if err != nil || sb.Generation != wantGen {
			continue
		}
		if err := sb.Verify(pub); err == nil {
			found = true
		}
	}
	return found
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// publishRootInode mirrors cutdb.RootInode for readability at call sites
// that pass it as both uint64 and int64.
const publishRootInode = 1

func TestCrossGenerationDedupIndex(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "99998888-7777-6666-5555-444433332222")

	// A chunked (multi-MiB) file that stays identical across generations,
	// and a small file that changes.
	bigContent := pseudorandom(3<<20, 77)
	dirIno := v.mkdir(publishRootInode, "d")
	bigIno := v.create(dirIno, "big.bin")
	v.write(bigIno, bigContent)
	smallIno := v.create(dirIno, "small.txt")
	v.write(smallIno, []byte("v1"))
	cut1 := v.cut()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(t.TempDir(), "dedup.db")
	opts := publish.Options{
		Blob:           v.blob,
		Inner:          inner,
		SigningKey:     priv,
		DedupIndexPath: index,
	}
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut1, t.TempDir(), t.TempDir()
	res1, err := publish.Publish(ctx, opts)
	if err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if res1.Stats.ChunksAdded == 0 {
		t.Fatal("first publish added no chunks")
	}

	// Change only the small (inline) file; the big file's chunks must be
	// satisfied from the dedup index — zero chunk uploads.
	v.write(smallIno, []byte("v2 - changed"))
	cut2 := v.cut()
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut2, t.TempDir(), t.TempDir()
	opts.Prev, opts.PrevRaw = res1.Superblock, res1.Raw
	res2, err := publish.Publish(ctx, opts)
	if err != nil {
		t.Fatalf("second Publish: %v", err)
	}
	if res2.Stats.DedupIndexChunks != res1.Stats.ChunksAdded {
		t.Fatalf("index preloaded %d chunks, want %d", res2.Stats.DedupIndexChunks, res1.Stats.ChunksAdded)
	}
	if res2.Stats.ChunksAdded != 0 {
		t.Fatalf("second publish re-added %d chunks despite the index", res2.Stats.ChunksAdded)
	}
	if res2.Stats.ChunksDeduped != res1.Stats.ChunksAdded {
		t.Fatalf("deduped %d, want %d", res2.Stats.ChunksDeduped, res1.Stats.ChunksAdded)
	}

	// The deduped references must still resolve: read big.bin back from
	// generation 1's catalogs through real pack reads.
	env := newReadEnv(t, inner, nil, nil)
	root := env.openCatalog(res2.Superblock.RootCatalog[:])
	lr, err := root.Lookup(publishRootInode, []byte("d"))
	if err != nil || lr.Dirent == nil {
		t.Fatalf("lookup d: %+v err=%v", lr, err)
	}
	if got := env.readChunks(root, int64(bigIno)); !bytes.Equal(got, bigContent) {
		t.Fatalf("deduped big.bin content mismatch (%d bytes)", len(got))
	}

	// A THIRD publish built on gen 0 metadata (stale index generation)
	// must ignore the index rather than trust it.
	v.write(smallIno, []byte("v3"))
	cut3 := v.cut()
	opts.CutPath, opts.CacheDir, opts.SpoolDir = cut3, t.TempDir(), t.TempDir()
	opts.Prev, opts.PrevRaw = res1.Superblock, res1.Raw // stale: index is stamped for gen 1
	res3, err := publish.Publish(ctx, opts)
	if err == nil {
		// The flip guard may reject this stale publish outright (the ref
		// moved); if it somehow proceeds, the index must NOT have been used.
		if res3.Stats.DedupIndexChunks != 0 {
			t.Fatalf("stale index was trusted: %d preloaded chunks", res3.Stats.DedupIndexChunks)
		}
	}
}
