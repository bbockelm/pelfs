package catalog

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

var testMeta = Meta{
	VolumeUUID:   "9be0b4b1-1867-4b76-8f0e-6b8a54e8a405",
	CoveredPath:  "/data/sub",
	Generation:   42,
	IdentityAlgo: "blake3-256",
}

// buildTestCatalog writes a small tree exercising every table:
//
//	/ (1)
//	  file.bin (2)   three chunks incl. a hole row, two xattrs
//	  tiny.txt (3)   inline content
//	  link     (4)   symlink
//	  nesteddir      transition point to a child catalog
//	  bad.bin  (5)   chunk llens that do not sum to node.length
func buildTestCatalog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cat.sqlite")
	w, err := Create(path, testMeta)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	nodes := []Node{
		{Inode: 1, Type: TypeDir, Mode: 0o755, UID: 1000, GID: 1000, MtimeNS: 111, CtimeNS: 112, Nlink: 1, Length: 4096},
		{Inode: 2, Type: TypeFile, Mode: 0o644, UID: 1000, GID: 1000, MtimeNS: 221, CtimeNS: 222, Nlink: 1, Length: 100 + 4096 + 200, KeyID: 7, Flags: 3},
		{Inode: 3, Type: TypeFile, Mode: 0o600, UID: 1000, GID: 1000, MtimeNS: 331, CtimeNS: 332, Nlink: 1, Length: 11},
		{Inode: 4, Type: TypeSymlink, Mode: 0o777, UID: 1000, GID: 1000, MtimeNS: 441, CtimeNS: 442, Nlink: 1, Length: 9},
		{Inode: 5, Type: TypeFile, Mode: 0o644, UID: 1000, GID: 1000, MtimeNS: 551, CtimeNS: 552, Nlink: 1, Length: 999},
	}
	for _, n := range nodes {
		if err := w.AddNode(n); err != nil {
			t.Fatalf("AddNode(%d): %v", n.Inode, err)
		}
	}
	edges := []struct {
		name  string
		inode int64
		typ   uint8
	}{
		{"file.bin", 2, TypeFile},
		{"tiny.txt", 3, TypeFile},
		{"link", 4, TypeSymlink},
		{"bad.bin", 5, TypeFile},
	}
	for _, e := range edges {
		if err := w.AddEdge(1, []byte(e.name), e.inode, e.typ); err != nil {
			t.Fatalf("AddEdge(%s): %v", e.name, err)
		}
	}
	if err := w.AddNested(1, []byte("nesteddir"), []byte("child-identity-32-bytes-aaaaaaaa")); err != nil {
		t.Fatalf("AddNested: %v", err)
	}
	// Middle entry is a hole: nil identity, llen = hole length.
	chunks := []ChunkRef{
		{Identity: []byte("chunk-id-A"), LLen: 100, CLen: 60, Alg: 1, KeyID: 7},
		{Identity: nil, LLen: 4096},
		{Identity: []byte("chunk-id-B"), LLen: 200, CLen: 150, Alg: 2, KeyID: 7},
	}
	if err := w.AddChunks(2, chunks); err != nil {
		t.Fatalf("AddChunks: %v", err)
	}
	if err := w.AddChunks(5, []ChunkRef{{Identity: []byte("chunk-id-C"), LLen: 500, CLen: 500}}); err != nil {
		t.Fatalf("AddChunks(bad): %v", err)
	}
	if err := w.SetInline(3, []byte("hello inline")); err != nil {
		t.Fatalf("SetInline: %v", err)
	}
	if err := w.AddXattr(2, []byte("user.b"), []byte("bee")); err != nil {
		t.Fatalf("AddXattr: %v", err)
	}
	if err := w.AddXattr(2, []byte("user.a"), []byte("ay")); err != nil {
		t.Fatalf("AddXattr: %v", err)
	}
	if err := w.SetSymlink(4, []byte("file.bin")); err != nil {
		t.Fatalf("SetSymlink: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestRoundTrip(t *testing.T) {
	c, err := Open(buildTestCatalog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	if got := c.Meta(); got != testMeta {
		t.Errorf("Meta = %+v, want %+v", got, testMeta)
	}

	res, err := c.Lookup(1, []byte("file.bin"))
	if err != nil {
		t.Fatalf("Lookup(file.bin): %v", err)
	}
	if res.Dirent == nil || res.Dirent.Inode != 2 || res.Dirent.Type != TypeFile {
		t.Errorf("Lookup(file.bin) = %+v, want dirent inode 2", res)
	}
	res, err = c.Lookup(1, []byte("nesteddir"))
	if err != nil {
		t.Fatalf("Lookup(nesteddir): %v", err)
	}
	if res.Dirent != nil || !bytes.Equal(res.NestedIdentity, []byte("child-identity-32-bytes-aaaaaaaa")) {
		t.Errorf("Lookup(nesteddir) = %+v, want nested transition", res)
	}
	if _, err := c.Lookup(1, []byte("absent")); !errors.Is(err, ErrNotExist) {
		t.Errorf("Lookup(absent) err = %v, want ErrNotExist", err)
	}

	dirents, nesteds, err := c.Readdir(1)
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	wantNames := []string{"bad.bin", "file.bin", "link", "tiny.txt"}
	if len(dirents) != len(wantNames) {
		t.Fatalf("Readdir returned %d dirents, want %d", len(dirents), len(wantNames))
	}
	for i, name := range wantNames {
		if string(dirents[i].Name) != name {
			t.Errorf("dirent[%d] = %q, want %q (sorted by name)", i, dirents[i].Name, name)
		}
	}
	if len(nesteds) != 1 || string(nesteds[0].Name) != "nesteddir" {
		t.Errorf("Readdir nesteds = %+v, want one entry nesteddir", nesteds)
	}

	n, err := c.Stat(2)
	if err != nil {
		t.Fatalf("Stat(2): %v", err)
	}
	want := Node{Inode: 2, Type: TypeFile, Mode: 0o644, UID: 1000, GID: 1000, MtimeNS: 221, CtimeNS: 222, Nlink: 1, Length: 4396, KeyID: 7, Flags: 3}
	if n != want {
		t.Errorf("Stat(2) = %+v, want %+v", n, want)
	}
	if _, err := c.Stat(99); !errors.Is(err, ErrNotExist) {
		t.Errorf("Stat(99) err = %v, want ErrNotExist", err)
	}

	refs, err := c.Chunks(2)
	if err != nil {
		t.Fatalf("Chunks(2): %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("Chunks(2) returned %d refs, want 3", len(refs))
	}
	// Logical offsets are prefix sums of llen, never stored.
	wantOffsets := []int64{0, 100, 4196}
	for i, off := range wantOffsets {
		if refs[i].LogicalOffset != off {
			t.Errorf("chunk[%d].LogicalOffset = %d, want %d", i, refs[i].LogicalOffset, off)
		}
	}
	if !bytes.Equal(refs[0].Identity, []byte("chunk-id-A")) || refs[0].CLen != 60 || refs[0].Alg != 1 || refs[0].KeyID != 7 {
		t.Errorf("chunk[0] = %+v", refs[0])
	}
	if refs[1].Identity != nil || refs[1].LLen != 4096 {
		t.Errorf("chunk[1] = %+v, want hole (nil identity, llen 4096)", refs[1])
	}
	if refs, err := c.Chunks(3); err != nil || refs != nil {
		t.Errorf("Chunks(3) = %v, %v; want no refs for inline file", refs, err)
	}

	data, err := c.Inline(3)
	if err != nil || string(data) != "hello inline" {
		t.Errorf("Inline(3) = %q, %v", data, err)
	}
	if data, err := c.Inline(2); err != nil || data != nil {
		t.Errorf("Inline(2) = %q, %v; want nil for non-inline file", data, err)
	}

	attrs, err := c.Xattrs(2)
	if err != nil {
		t.Fatalf("Xattrs(2): %v", err)
	}
	if len(attrs) != 2 || string(attrs[0].Name) != "user.a" || string(attrs[1].Name) != "user.b" ||
		string(attrs[0].Value) != "ay" || string(attrs[1].Value) != "bee" {
		t.Errorf("Xattrs(2) = %+v, want user.a/user.b sorted", attrs)
	}

	target, err := c.Symlink(4)
	if err != nil || string(target) != "file.bin" {
		t.Errorf("Symlink(4) = %q, %v", target, err)
	}
	if _, err := c.Symlink(2); !errors.Is(err, ErrNotExist) {
		t.Errorf("Symlink(2) err = %v, want ErrNotExist", err)
	}
}

func TestChunkLengthMismatch(t *testing.T) {
	c, err := Open(buildTestCatalog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	// Inode 5's single 500-byte chunk disagrees with node.length 999.
	if _, err := c.Chunks(5); err == nil {
		t.Error("Chunks(5) succeeded, want length-mismatch error")
	}
}

func TestWithoutRowidSchema(t *testing.T) {
	c, err := Open(buildTestCatalog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	for _, table := range []string{"catalog_meta", "edge", "nested", "chunkref", "xattr"} {
		var ddl string
		if err := c.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&ddl); err != nil {
			t.Fatalf("read DDL for %s: %v", table, err)
		}
		if !strings.Contains(strings.ToUpper(ddl), "WITHOUT ROWID") {
			t.Errorf("table %s is not WITHOUT ROWID:\n%s", table, ddl)
		}
	}
	// node must have no atime column, per the design doc.
	var ddl string
	if err := c.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'node'`).Scan(&ddl); err != nil {
		t.Fatalf("read node DDL: %v", err)
	}
	if strings.Contains(strings.ToLower(ddl), "atime") {
		t.Errorf("node table carries an atime column:\n%s", ddl)
	}
}

// The catalog must self-identify for rescue: verify the raw catalog_meta
// rows, not just the parsed Meta.
func TestSelfIdentification(t *testing.T) {
	c, err := Open(buildTestCatalog(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	want := map[string]string{
		"volume_uuid":    testMeta.VolumeUUID,
		"covered_path":   testMeta.CoveredPath,
		"generation":     "42",
		"format_version": "1",
		"identity_algo":  testMeta.IdentityAlgo,
	}
	for key, wantVal := range want {
		var got []byte
		if err := c.db.QueryRow(`SELECT value FROM catalog_meta WHERE key = ?`, key).Scan(&got); err != nil {
			t.Fatalf("catalog_meta[%s]: %v", key, err)
		}
		if string(got) != wantVal {
			t.Errorf("catalog_meta[%s] = %q, want %q", key, got, wantVal)
		}
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	path := buildTestCatalog(t)
	if _, err := Create(path, testMeta); err == nil {
		t.Error("Create over an existing catalog succeeded, want error (write-once)")
	}
}
