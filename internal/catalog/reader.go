package catalog

import (
	"fmt"
	"os"
)

// Reader is the read surface of a catalog, in either encoding. It is the
// whole query surface: ten lookups, every one keyed by an inode or a
// (parent, name) pair.
//
// Two implementations exist because a volume outlives a format. Catalogs
// are immutable and content-addressed, and an unchanged one is carried
// forward by reference, so switching what a WRITER emits does not touch
// what is already published — a volume simply holds both kinds, and a
// subtree migrates the next time something in it changes. That is why
// this interface exists rather than a conversion step: rewriting every
// catalog to change encoding would give each a new identity, re-upload
// the whole namespace, and lose carry-forward against every previous
// generation.
type Reader interface {
	Meta() Meta
	HasXattrs() bool
	Lookup(parent int64, name []byte) (LookupResult, error)
	Readdir(parent int64) ([]Dirent, []Nested, error)
	NestedOf(parent int64) ([]Nested, error)
	ReaddirPlus(parent int64) ([]DirentNode, error)
	Stat(inode int64) (Node, error)
	Chunks(inode int64) ([]ChunkRef, error)
	Inline(inode int64) ([]byte, error)
	Symlink(inode int64) ([]byte, error)
	Xattrs(inode int64) ([]Xattr, error)
	Close() error
}

var (
	_ Reader = (*Catalog)(nil)
	_ Reader = (*Static)(nil)
)

// Builder is the write surface, in either encoding. Finish completes the
// catalog and returns its bytes, which is what the publisher hashes into
// an identity and appends to a pack — so neither implementation leaks
// whether it went through a file on the way.
type Builder interface {
	AddNode(Node) error
	AddEdge(parent int64, name []byte, inode int64, typ uint8) error
	AddNested(parent int64, name, catalogIdentity []byte) error
	AddChunks(inode int64, refs []ChunkRef) error
	SetInline(inode int64, data []byte) error
	AddXattr(inode int64, name, value []byte) error
	SetSymlink(inode int64, target []byte) error
	Finish() ([]byte, error)
}

var (
	_ Builder = (*Writer)(nil)
	_ Builder = (*StaticWriter)(nil)
)

// OrderChecker is implemented by encodings whose read paths ASSUME an
// ordering they do not verify at open. The static format binary-searches
// sorted arrays and checking that on every open would be O(n), so the
// check is offered here for fsck to run instead. A SQLite catalog does
// not implement it: its order is a B-tree primary key, maintained by the
// engine rather than assumed by the reader.
type OrderChecker interface {
	CheckOrder() error
}

// sqliteMagic is the first 16 bytes of every SQLite database file.
const sqliteMagic = "SQLite format 3\x00"

// OpenReader opens a catalog in whichever encoding it is written in,
// deciding from the bytes rather than from a flag: a single generation
// may reference catalogs of both kinds, so the file itself is the only
// thing that can be asked.
func OpenReader(path string) (Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var head [16]byte
	n, err := f.Read(head[:])
	closeErr := f.Close()
	if err != nil && n == 0 {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	if closeErr != nil {
		return nil, closeErr
	}

	switch {
	case n >= len(staticMagic) && string(head[:len(staticMagic)]) == staticMagic:
		// The whole blob is mapped, so the reader indexes it in place.
		buf, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return OpenStatic(buf)
	case n >= len(sqliteMagic) && string(head[:len(sqliteMagic)]) == sqliteMagic:
		return Open(path)
	default:
		return nil, fmt.Errorf("%w: %s is neither a static catalog nor a SQLite database", errCorrupt, path)
	}
}
