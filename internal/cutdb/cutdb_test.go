package cutdb

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"
)

// buildVolume creates a minimal JuiceFS volume: /dir/file with content
// (a leading 4 KiB hole, then payload), /dir/link -> file, an xattr on
// file, and a hardlink /dir/second to file. Returns the meta path, the
// shared blob store, and the file inode.
func buildVolume(t *testing.T, payload []byte) (string, object.ObjectStorage, uint64, uint64) {
	t.Helper()
	metaPath := filepath.Join(t.TempDir(), "cut.db")
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format := &meta.Format{
		Name:      "cutdb-test",
		UUID:      "00000000-0000-0000-0000-000000000001",
		Storage:   "mem",
		BlockSize: 4096, // KiB
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("init meta: %v", err)
	}
	if err := m.NewSession(true); err != nil {
		t.Fatalf("session: %v", err)
	}
	defer m.CloseSession() //nolint:errcheck

	blob, err := object.CreateStorage("mem", "", "", "", "")
	if err != nil {
		t.Fatalf("mem store: %v", err)
	}
	store := chunk.NewCachedStore(blob, chunk.Config{
		BlockSize:  format.BlockSize * 1024,
		CacheDir:   "memory",
		CacheSize:  8 << 20,
		GetTimeout: 10 * time.Second, PutTimeout: 10 * time.Second,
		MaxUpload: 2, MaxDownload: 2, MaxRetries: 1, BufferSize: 8 << 20,
	}, prometheus.NewRegistry())

	ctx := meta.WrapContext(context.Background())
	var dir, file, link meta.Ino
	var attr meta.Attr
	if st := m.Mkdir(ctx, meta.RootInode, "dir", 0755, 0, 0, &dir, &attr); st != 0 {
		t.Fatalf("mkdir: %s", st)
	}
	if st := m.Create(ctx, dir, "file", 0644, 0, 0, &file, &attr); st != 0 {
		t.Fatalf("create: %s", st)
	}

	var sliceID uint64
	if st := m.NewSlice(ctx, &sliceID); st != 0 {
		t.Fatalf("new slice: %s", st)
	}
	w := store.NewWriter(sliceID, 0)
	if _, err := w.WriteAt(payload, 0); err != nil {
		t.Fatalf("write slice: %v", err)
	}
	if err := w.Finish(len(payload)); err != nil {
		t.Fatalf("finish slice: %v", err)
	}
	s := meta.Slice{Id: sliceID, Size: uint32(len(payload)), Len: uint32(len(payload))}
	if st := m.Write(ctx, file, 0, 4096, s, time.Now()); st != 0 {
		t.Fatalf("meta write: %s", st)
	}

	if st := m.SetXattr(ctx, file, "user.color", []byte("blue"), 0); st != 0 {
		t.Fatalf("setxattr: %s", st)
	}
	if st := m.Symlink(ctx, dir, "link", "file", &link, &attr); st != 0 {
		t.Fatalf("symlink: %s", st)
	}
	if st := m.Link(ctx, file, dir, "second", &attr); st != 0 {
		t.Fatalf("link: %s", st)
	}
	return metaPath, blob, uint64(dir), uint64(file)
}

func TestWalkExtentsAndContent(t *testing.T) {
	payload := bytes.Repeat([]byte("pelfs-cut!"), 2000) // 20 KB
	metaPath, blob, dirIno, fileIno := buildVolume(t, payload)

	db, err := Open(metaPath, Options{Blob: blob, CacheDir: filepath.Join(t.TempDir(), "cache")})
	if err != nil {
		t.Fatalf("open cut: %v", err)
	}
	defer db.Close() //nolint:errcheck

	ctx := context.Background()
	type edge struct {
		parent uint64
		name   string
		typ    uint8
		nlink  uint32
	}
	var edges []edge
	if err := db.Walk(ctx, func(parent uint64, name string, n Node) error {
		edges = append(edges, edge{parent, name, n.Type, n.Nlink})
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	want := map[string]uint8{
		"dir": meta.TypeDirectory, "file": meta.TypeFile,
		"link": meta.TypeSymlink, "second": meta.TypeFile,
	}
	if len(edges) != len(want) {
		t.Fatalf("walked %d edges, want %d: %+v", len(edges), len(want), edges)
	}
	for _, e := range edges {
		if want[e.name] != e.typ {
			t.Errorf("edge %q: type %d, want %d", e.name, e.typ, want[e.name])
		}
		if e.name != "dir" && e.parent != dirIno {
			t.Errorf("edge %q: parent %d, want %d", e.name, e.parent, dirIno)
		}
		if (e.name == "file" || e.name == "second") && e.nlink != 2 {
			t.Errorf("edge %q: nlink %d, want 2 (hardlink)", e.name, e.nlink)
		}
	}

	n, err := db.Stat(ctx, fileIno)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	wantLen := uint64(4096 + len(payload))
	if n.Length != wantLen {
		t.Fatalf("file length %d, want %d", n.Length, wantLen)
	}

	exts, err := db.Extents(ctx, fileIno, n.Length)
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	var total uint64
	holes := 0
	for _, e := range exts {
		total += uint64(e.Len)
		if e.SliceID == 0 {
			holes++
		}
	}
	if total != wantLen {
		t.Fatalf("extent lengths sum to %d, want %d (extents: %+v)", total, wantLen, exts)
	}
	if holes == 0 {
		t.Fatalf("expected a hole extent for the leading 4 KiB gap: %+v", exts)
	}

	r, err := db.FileReader(ctx, fileIno, n.Length)
	if err != nil {
		t.Fatalf("file reader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	if !bytes.Equal(got[:4096], make([]byte, 4096)) {
		t.Fatalf("leading hole did not read as zeros")
	}
	if !bytes.Equal(got[4096:], payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got)-4096)
	}

	xa, err := db.Xattrs(ctx, fileIno)
	if err != nil {
		t.Fatalf("xattrs: %v", err)
	}
	if string(xa["user.color"]) != "blue" {
		t.Fatalf("xattr user.color = %q, want blue", xa["user.color"])
	}
	target, err := db.Readlink(ctx, edgesInode(t, db, dirIno, "link"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "file" {
		t.Fatalf("symlink target %q, want file", target)
	}
}

// edgesInode resolves one name under a directory via Walk (the package
// deliberately has no Lookup; publish always walks).
func edgesInode(t *testing.T, db *DB, parent uint64, name string) uint64 {
	t.Helper()
	var found uint64
	if err := db.Walk(context.Background(), func(p uint64, n string, node Node) error {
		if p == parent && n == name {
			found = node.Inode
		}
		return nil
	}); err != nil {
		t.Fatalf("walk for lookup: %v", err)
	}
	if found == 0 {
		t.Fatalf("no edge %q under %d", name, parent)
	}
	return found
}
