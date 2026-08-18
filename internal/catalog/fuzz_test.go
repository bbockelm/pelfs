package catalog

import (
	"bytes"
	"testing"
)

// A catalog blob is bytes fetched from a federation. They are
// hash-verified against a signed generation before a parser sees them, so
// this is not an adversary who can choose the input — but a truncated
// download, a range-mangling cache, or a torn local file all produce
// exactly this shape, and none of them may panic or read outside the
// buffer.
//
// The format deliberately does NOT verify sort order at open (O(n) would
// undo the reason it exists), so the fuzzer's job is memory safety and
// termination, not correct answers: an out-of-order catalog is allowed to
// return nonsense, never to crash.
//
//	go test -fuzz FuzzStaticCatalog ./internal/catalog/

func FuzzStaticCatalog(f *testing.F) {
	// Seed with a structurally complete catalog: every section present,
	// which is what gives the mutator something to corrupt in each of
	// them.
	w := NewStaticWriter(Meta{VolumeUUID: "u", CoveredPath: "/", IdentityAlgo: "blake3-256"}, 1, 2048)
	_ = w.AddNode(Node{Inode: 1, Type: TypeDir, Mode: 0755, Nlink: 2})
	_ = w.AddNode(Node{Inode: 2, Type: TypeFile, Mode: 0644, Length: 5})
	_ = w.AddNode(Node{Inode: 3, Type: TypeSymlink, Mode: 0777})
	_ = w.AddNode(Node{Inode: 4, Type: TypeDir, Mode: 0755, Nlink: 2})
	_ = w.AddEdge(1, []byte("file"), 2, TypeFile)
	_ = w.AddEdge(1, []byte("link"), 3, TypeSymlink)
	_ = w.AddEdge(1, []byte("child"), 4, TypeDir)
	_ = w.AddNested(1, []byte("child"), bytes.Repeat([]byte{0x5e}, 32))
	_ = w.SetInline(2, []byte("hello"))
	_ = w.SetSymlink(3, []byte("file"))
	_ = w.AddChunks(2, []ChunkRef{{Identity: bytes.Repeat([]byte{0xa1}, 32), LLen: 5, CLen: 5}})
	_ = w.AddXattr(2, []byte("user.a"), []byte("v"))
	blob, err := w.Finish()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob)

	// A header alone, a truncated body, and junk: the shapes a partial
	// transfer actually produces.
	f.Add(blob[:staticHeaderLen])
	if len(blob) > staticHeaderLen+sectionEntryLen {
		f.Add(blob[:staticHeaderLen+sectionEntryLen])
	}
	f.Add([]byte(staticMagic))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := OpenStatic(data)
		if err != nil {
			return
		}
		// Every read path, over keys inside and outside anything the seed
		// contains. Results are ignored: the contract under fuzzing is
		// that nothing panics and nothing reads out of bounds.
		for _, k := range []int64{-1, 0, 1, 2, 3, 4, 1 << 20, 1<<63 - 1} {
			_, _, _ = s.Readdir(k)
			_, _ = s.ReaddirPlus(k)
			_, _ = s.NestedOf(k)
			_, _ = s.Stat(k)
			_, _ = s.Chunks(k)
			_, _ = s.Inline(k)
			_, _ = s.Symlink(k)
			_, _ = s.Xattrs(k)
			for _, name := range [][]byte{nil, {}, []byte("file"), []byte("child"), []byte("\xff\xff")} {
				_, _ = s.Lookup(k, name)
			}
		}
		_ = s.Meta()
		_ = s.HasXattrs()
		_ = s.Close()
	})
}
