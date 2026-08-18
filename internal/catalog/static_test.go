package catalog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// buildStatic assembles a small but structurally complete catalog: a
// root with children, a nested mount point, a hardlinked inode reachable
// by two names, inline content, a symlink, chunk lists, and xattrs on a
// minority of inodes.
func buildStatic(t *testing.T) []byte {
	t.Helper()
	w := NewStaticWriter(Meta{
		VolumeUUID:   "vol-uuid",
		CoveredPath:  "/",
		IdentityAlgo: "blake3-256",
	}, 1, 2048)

	dir := func(ino int64) Node {
		return Node{Inode: ino, Type: 2, Mode: 0755, Nlink: 2, MtimeNS: 100, CtimeNS: 100}
	}
	file := func(ino int64, ln int64, nlink uint32) Node {
		return Node{Inode: ino, Type: 1, Mode: 0644, Nlink: nlink, Length: ln, MtimeNS: 200, CtimeNS: 200}
	}
	w.AddNode(dir(1))
	w.AddNode(dir(2))
	w.AddNode(file(3, 5, 1))
	w.AddNode(file(4, 0, 2)) // hardlinked: two names below
	w.AddNode(Node{Inode: 5, Type: 3, Mode: 0777, Nlink: 1})

	// Deliberately added out of order: the writer sorts.
	w.AddEdge(1, []byte("zeta.txt"), 3, 1)
	w.AddEdge(1, []byte("alpha"), 2, 2)
	w.AddEdge(2, []byte("linked"), 4, 1)
	w.AddEdge(1, []byte("also-linked"), 4, 1)
	w.AddEdge(1, []byte("link"), 5, 3)

	w.SetInline(3, []byte("hello"))
	w.SetSymlink(5, []byte("alpha/zeta.txt"))
	w.AddChunks(4, []ChunkRef{
		{Identity: bytes.Repeat([]byte{0xa1}, 32), LLen: 10, CLen: 9, Alg: 1, KeyID: 7},
		{Identity: bytes.Repeat([]byte{0xb2}, 32), LLen: 4, CLen: 4},
	})
	w.AddXattr(3, []byte("user.b"), []byte("second"))
	w.AddXattr(3, []byte("user.a"), []byte("first"))

	nestedID := bytes.Repeat([]byte{0xcc}, 32)
	w.AddNested(1, []byte("sub"), nestedID)

	blob, err := w.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return blob
}

func TestStaticRoundTrip(t *testing.T) {
	s, err := OpenStatic(buildStatic(t))
	if err != nil {
		t.Fatalf("OpenStatic: %v", err)
	}

	if got := s.Meta(); got.VolumeUUID != "vol-uuid" || got.IdentityAlgo != "blake3-256" || got.CoveredPath != "/" {
		t.Fatalf("meta = %+v", got)
	}
	if !s.HasXattrs() {
		t.Error("HasXattrs is false though xattrs were written")
	}

	res, err := s.Lookup(1, []byte("alpha"))
	if err != nil || res.Dirent == nil || res.Dirent.Inode != 2 {
		t.Fatalf("lookup alpha: %+v err=%v", res.Dirent, err)
	}
	// A name with neither half is ErrNotExist, not an empty result: genfs
	// distinguishes them, and returning nil here made it read an absent
	// entry as a transition point missing its dirent.
	if _, err := s.Lookup(1, []byte("absent")); !errors.Is(err, ErrNotExist) {
		t.Fatalf("lookup of a missing name: err = %v, want ErrNotExist", err)
	}

	// A nested mount point resolves through the same call.
	res, err = s.Lookup(1, []byte("sub"))
	if err != nil {
		t.Fatalf("lookup sub: %v", err)
	}
	if len(res.NestedIdentity) != 32 || res.NestedIdentity[0] != 0xcc {
		t.Fatalf("nested identity = %x", res.NestedIdentity)
	}

	// Readdir is name-ordered because the sort key is (parent, name).
	ents, nested, err := s.Readdir(1)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, string(e.Name))
	}
	// Byte order, not any collation: "alpha" precedes "also-linked"
	// because 'p' < 's'. Readdir must return exactly the stored order.
	want := []string{"alpha", "also-linked", "link", "zeta.txt"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("readdir order = %v, want %v", names, want)
	}
	if len(nested) != 1 || string(nested[0].Name) != "sub" {
		t.Fatalf("nested = %+v", nested)
	}

	// ReaddirPlus must agree with Stat for every entry — that agreement
	// is what the node index replaces the join with.
	plus, err := s.ReaddirPlus(1)
	if err != nil {
		t.Fatalf("readdirplus: %v", err)
	}
	if len(plus) != len(ents) {
		t.Fatalf("readdirplus returned %d entries, readdir %d", len(plus), len(ents))
	}
	for i, p := range plus {
		if string(p.Name) != string(ents[i].Name) {
			t.Fatalf("entry %d: readdirplus %q, readdir %q", i, p.Name, ents[i].Name)
		}
		want, err := s.Stat(p.Node.Inode)
		if err != nil {
			t.Fatalf("stat %d: %v", p.Node.Inode, err)
		}
		if p.Node != want {
			t.Fatalf("entry %q: readdirplus %+v, stat %+v", p.Name, p.Node, want)
		}
	}

	// A hardlinked inode is reachable by both names and has ONE node.
	a, err := s.Lookup(1, []byte("also-linked"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Lookup(2, []byte("linked"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Dirent.Inode != b.Dirent.Inode {
		t.Fatalf("hardlink resolves to %d and %d", a.Dirent.Inode, b.Dirent.Inode)
	}

	if data, err := s.Inline(3); err != nil || string(data) != "hello" {
		t.Fatalf("inline = %q, err %v", data, err)
	}
	if tgt, err := s.Symlink(5); err != nil || string(tgt) != "alpha/zeta.txt" {
		t.Fatalf("symlink = %q, err %v", tgt, err)
	}
	if _, err := s.Inline(4); !errors.Is(err, ErrNotExist) {
		t.Fatalf("inline of a chunked file: err = %v, want ErrNotExist", err)
	}

	chunks, err := s.Chunks(4)
	if err != nil {
		t.Fatalf("chunks: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks", len(chunks))
	}
	// LogicalOffset is the prefix sum, not a stored field.
	if chunks[0].LogicalOffset != 0 || chunks[1].LogicalOffset != 10 {
		t.Fatalf("logical offsets %d, %d", chunks[0].LogicalOffset, chunks[1].LogicalOffset)
	}
	if chunks[0].LLen != 10 || chunks[0].CLen != 9 || chunks[0].Alg != 1 || chunks[0].KeyID != 7 {
		t.Fatalf("chunk 0 = %+v", chunks[0])
	}
	if chunks[1].Identity[0] != 0xb2 {
		t.Fatalf("chunk 1 identity = %x", chunks[1].Identity)
	}

	xa, err := s.Xattrs(3)
	if err != nil {
		t.Fatalf("xattrs: %v", err)
	}
	if len(xa) != 2 || string(xa[0].Name) != "user.a" || string(xa[1].Value) != "second" {
		t.Fatalf("xattrs = %+v", xa)
	}
	if xa, err := s.Xattrs(4); err != nil || len(xa) != 0 {
		t.Fatalf("xattrs of an inode with none: %+v err %v", xa, err)
	}
	if _, err := s.Stat(999); !errors.Is(err, ErrNotExist) {
		t.Fatalf("stat of a missing inode: err = %v, want ErrNotExist", err)
	}
}

// TestStaticIsDeterministic is the property content addressing depends
// on: the same tree must produce the same bytes, or an unchanged subtree
// gets a new identity every seal and catalog reuse silently stops. The
// previous format failed exactly here, by stamping the generation into
// its metadata.
func TestStaticIsDeterministic(t *testing.T) {
	a := buildStatic(t)
	b := buildStatic(t)
	if !bytes.Equal(a, b) {
		t.Fatalf("two builds of the same tree differ (%d and %d bytes)", len(a), len(b))
	}

	// Insertion order must not matter either: the writer sorts, so a
	// caller walking the tree differently still gets the same catalog.
	w1 := NewStaticWriter(Meta{IdentityAlgo: "blake3-256"}, 1, 2048)
	w2 := NewStaticWriter(Meta{IdentityAlgo: "blake3-256"}, 1, 2048)
	nodes := []Node{
		{Inode: 1, Type: 2, Mode: 0755},
		{Inode: 2, Type: 1, Mode: 0644},
		{Inode: 3, Type: 1, Mode: 0644},
	}
	for _, n := range nodes {
		w1.AddNode(n)
	}
	for i := len(nodes) - 1; i >= 0; i-- {
		w2.AddNode(nodes[i])
	}
	w1.AddEdge(1, []byte("a"), 2, 1)
	w1.AddEdge(1, []byte("b"), 3, 1)
	w2.AddEdge(1, []byte("b"), 3, 1)
	w2.AddEdge(1, []byte("a"), 2, 1)

	x, err := w1.Finish()
	if err != nil {
		t.Fatal(err)
	}
	y, err := w2.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatal("insertion order changed the catalog bytes")
	}
}

// TestStaticRefusesAFutureMajor pins the compatibility gate: guessing at
// an unknown layout is worse than refusing it.
func TestStaticRefusesAFutureMajor(t *testing.T) {
	blob := buildStatic(t)
	blob[8] = FormatMajor + 1
	_, err := OpenStatic(blob)
	if !errors.Is(err, ErrFormatVersion) {
		t.Fatalf("err = %v, want ErrFormatVersion", err)
	}
}

// TestStaticSurvivesCorruption is the parser's real job. Catalog bytes
// are hash-verified against a signed generation before they get here, so
// this is about a truncated download or a bad cache, not an attacker —
// but a corrupt blob must produce an error, never a panic or a read
// outside the buffer.
func TestStaticSurvivesCorruption(t *testing.T) {
	good := buildStatic(t)

	// Every truncation.
	for n := 0; n < len(good); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("truncating to %d bytes panicked: %v", n, r)
				}
			}()
			s, err := OpenStatic(append([]byte(nil), good[:n]...))
			if err != nil {
				return
			}
			exerciseAll(s)
		}()
	}

	// Every single-byte corruption in the header and section table, which
	// is where a wrong value can point a read anywhere.
	tableEnd := staticHeaderLen + int(binary.LittleEndian.Uint16(good[14:]))*sectionEntryLen
	for i := 0; i < tableEnd && i < len(good); i++ {
		for _, bit := range []byte{0x01, 0x80, 0xff} {
			blob := append([]byte(nil), good...)
			blob[i] ^= bit
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("byte %d ^ %#x panicked: %v", i, bit, r)
					}
				}()
				s, err := OpenStatic(blob)
				if err != nil {
					return
				}
				exerciseAll(s)
			}()
		}
	}
}

// exerciseAll drives every read path, ignoring results: the point is
// that nothing panics and nothing reads out of bounds.
func exerciseAll(s *Static) {
	for parent := int64(0); parent < 8; parent++ {
		_, _, _ = s.Readdir(parent)
		_, _ = s.ReaddirPlus(parent)
		_, _ = s.NestedOf(parent)
		_, _ = s.Lookup(parent, []byte("alpha"))
		_, _ = s.Lookup(parent, []byte("sub"))
	}
	for ino := int64(0); ino < 8; ino++ {
		_, _ = s.Stat(ino)
		_, _ = s.Chunks(ino)
		_, _ = s.Inline(ino)
		_, _ = s.Symlink(ino)
		_, _ = s.Xattrs(ino)
	}
	_ = s.Meta()
	_ = s.HasXattrs()
}

// TestStaticLookupReturnsBothHalvesOfATransition pins the contract the
// end-to-end seal caught me violating: a transition point has a dirent
// whose node lives in THIS catalog and an identity naming the child
// catalog its contents live in. Returning only the first made genfs
// resolve the name without ever switching catalogs; returning only the
// second made it report a transition with no dirent half.
func TestStaticLookupReturnsBothHalvesOfATransition(t *testing.T) {
	w := NewStaticWriter(Meta{IdentityAlgo: "blake3-256"}, 1, 2048)
	if err := w.AddNode(Node{Inode: 1, Type: 2, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddNode(Node{Inode: 2, Type: 2, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddEdge(1, []byte("child"), 2, 2); err != nil {
		t.Fatal(err)
	}
	childCat := bytes.Repeat([]byte{0x5e}, 32)
	if err := w.AddNested(1, []byte("child"), childCat); err != nil {
		t.Fatal(err)
	}
	blob, err := w.Finish()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStatic(blob)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.Lookup(1, []byte("child"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if res.Dirent == nil {
		t.Error("transition point returned no dirent half")
	} else if res.Dirent.Inode != 2 {
		t.Errorf("dirent inode = %d, want 2", res.Dirent.Inode)
	}
	if !bytes.Equal(res.NestedIdentity, childCat) {
		t.Errorf("nested identity = %x, want %x", res.NestedIdentity, childCat)
	}
}
