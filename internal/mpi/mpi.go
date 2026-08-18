// Package mpi is the multi-pack index: one object answering "which pack
// holds this identity, and where" for many packs at once.
//
// It exists because locating anything currently costs one federation
// round trip PER PACK. A pack's trailer is its own index, so a reader
// with no idea which pack holds an object consults them all — and a
// mount must locate the root catalog before it can serve a single call.
// A user with 201 packs on a slow link watched a mount sit there doing
// exactly that.
//
// Git reached the same place and answered the same way: per-pack .idx
// files, then a multi-pack-index across them once pack count made
// per-pack lookup the bottleneck. The difference here sharpens the case.
// Git's .idx files are local and mapped, so consulting two hundred of
// them is microseconds of binary search; our trailers are REMOTE, so the
// identical structure costs two hundred round trips. Git added its index
// to save microseconds. We add ours to save minutes.
//
// What this is NOT: a place where identity binds to location. An index is
// DERIVED — publish writes it, repack rewrites it, and deleting one costs
// nothing but speed. Catalogs and chunkrefs go on naming identities
// alone, which is what lets a repack move bytes without rewriting
// anything that refers to them. The index is the fast way to answer a
// question the trailers can always answer again.
package mpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

const (
	magic = "PELFSMPI"
	// headerLen is 8-byte aligned, like the table it carries: this is
	// meant to be mapped and read in place.
	headerLen = 32
	// recordLen is what one entry resolves to: which pack, where in it,
	// how long, and what kind of thing it is.
	recordLen = 4 + 8 + 8 + 1
	// Dir is the key-space directory holding index objects.
	Dir = "mpi"
)

// ErrFormat reports bytes that are not an index this build understands.
var ErrFormat = fmt.Errorf("mpi: unrecognized index")

// Loc is where one identity lives.
type Loc struct {
	Pack   string
	Off    int64
	Length int64
	Type   string
}

// Builder accumulates entries across packs.
type Builder struct {
	packs   []string
	packIdx map[string]uint32
	table   *packidx.Builder
}

func NewBuilder() *Builder {
	return &Builder{packIdx: map[string]uint32{}, table: packidx.NewBuilder(recordLen)}
}

// Add records one entry. typ is the pack trailer's entry type, kept so a
// reader can tell a chunk from a catalog without fetching it.
func (b *Builder) Add(id [32]byte, pack string, off, length int64, typ string) error {
	i, ok := b.packIdx[pack]
	if !ok {
		i = uint32(len(b.packs))
		b.packs = append(b.packs, pack)
		b.packIdx[pack] = i
	}
	var v [recordLen]byte
	binary.LittleEndian.PutUint32(v[0:], i)
	binary.LittleEndian.PutUint64(v[4:], uint64(off))
	binary.LittleEndian.PutUint64(v[12:], uint64(length))
	v[20] = typeCode(typ)
	return b.table.Add(id, v[:])
}

// Len is how many entries have been added, and Packs how many packs they
// span — the two numbers a consolidation policy needs.
func (b *Builder) Len() int   { return b.table.Len() }
func (b *Builder) Packs() int { return len(b.packs) }

// Encode writes the index: a header, the pack names, then the table.
func (b *Builder) Encode() []byte {
	names := make([]byte, 0, 32*len(b.packs))
	for _, p := range b.packs {
		names = binary.LittleEndian.AppendUint16(names, uint16(len(p)))
		names = append(names, p...)
	}
	table := b.table.Encode()
	out := make([]byte, headerLen+len(names)+len(table))
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint32(out[8:], 1)
	binary.LittleEndian.PutUint32(out[12:], uint32(len(b.packs)))
	binary.LittleEndian.PutUint32(out[16:], uint32(len(names)))
	copy(out[headerLen:], names)
	copy(out[headerLen+len(names):], table)
	return out
}

// Index is one index read in place.
type Index struct {
	packs []string
	table *packidx.Table
}

// Open validates the structure without reading the entries.
func Open(b []byte) (*Index, error) {
	if len(b) < headerLen || string(b[0:8]) != magic {
		return nil, ErrFormat
	}
	if v := binary.LittleEndian.Uint32(b[8:]); v != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, v)
	}
	packCount := int(binary.LittleEndian.Uint32(b[12:]))
	nameBytes := int(binary.LittleEndian.Uint32(b[16:]))
	if headerLen+nameBytes > len(b) {
		return nil, fmt.Errorf("%w: %d bytes of pack names in a %d-byte index", ErrFormat, nameBytes, len(b))
	}
	names := b[headerLen : headerLen+nameBytes]
	packs := make([]string, 0, packCount)
	for len(names) > 0 {
		if len(names) < 2 {
			return nil, ErrFormat
		}
		n := int(binary.LittleEndian.Uint16(names))
		names = names[2:]
		if n > len(names) {
			return nil, ErrFormat
		}
		packs = append(packs, string(names[:n]))
		names = names[n:]
	}
	if len(packs) != packCount {
		return nil, fmt.Errorf("%w: header says %d packs, names hold %d", ErrFormat, packCount, len(packs))
	}
	table, err := packidx.Open(b[headerLen+nameBytes:])
	if err != nil {
		return nil, err
	}
	return &Index{packs: packs, table: table}, nil
}

// Lookup resolves one identity.
func (ix *Index) Lookup(id [32]byte) (Loc, bool) {
	v, ok := ix.table.Lookup(id)
	if !ok {
		return Loc{}, false
	}
	p := binary.LittleEndian.Uint32(v[0:])
	if int(p) >= len(ix.packs) {
		// A pack reference outside the name list is a corrupt index, and
		// the caller's fallback is a correct answer to it.
		return Loc{}, false
	}
	return Loc{
		Pack:   ix.packs[p],
		Off:    int64(binary.LittleEndian.Uint64(v[4:])),
		Length: int64(binary.LittleEndian.Uint64(v[12:])),
		Type:   typeName(v[20]),
	}, true
}

// Packs are the packs this index covers, which is what a retention sweep
// compares against the live set.
func (ix *Index) Packs() []string { return ix.packs }

// Len is the number of entries.
func (ix *Index) Len() int { return ix.table.Len() }

// At enumerates the index, for a consolidation that merges several.
func (ix *Index) At(i int) ([32]byte, Loc) {
	id, v := ix.table.At(i)
	p := binary.LittleEndian.Uint32(v[0:])
	loc := Loc{
		Off:    int64(binary.LittleEndian.Uint64(v[4:])),
		Length: int64(binary.LittleEndian.Uint64(v[12:])),
		Type:   typeName(v[20]),
	}
	if int(p) < len(ix.packs) {
		loc.Pack = ix.packs[p]
	}
	return id, loc
}

// Ref names one index object, as a superblock lists it.
type Ref struct {
	Name    string
	Hash    [32]byte
	Size    int64
	Entries uint32
	Packs   uint32
}

// Fetch reads and verifies one index object.
func Fetch(ctx context.Context, obj pelicanobj.Store, ref Ref) (*Index, error) {
	rc, err := obj.Get(ctx, Dir+"/"+ref.Name, 0, -1)
	if err != nil {
		return nil, fmt.Errorf("mpi: fetch %s: %w", ref.Name, err)
	}
	raw, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	if rerr != nil {
		return nil, fmt.Errorf("mpi: read %s: %w", ref.Name, rerr)
	}
	if cerr != nil {
		return nil, cerr
	}
	if got := blake3.Sum256(raw); got != ref.Hash {
		return nil, fmt.Errorf("mpi: %s hashes to %x, the generation says %x", ref.Name, got[:8], ref.Hash[:8])
	}
	return Open(raw)
}

// FetchAll reads every listed index CONCURRENTLY.
//
// Serial fetches would trade N round trips for a smaller N, still paid
// one after another — which is most of the problem rather than a fix. A
// generation carrying several indexes should cost one round trip's
// LATENCY, not several, so they are fetched in parallel and the caller
// waits once.
//
// A failed index is not a failed mount: an index is derived, and the
// trailers still answer. The error is returned alongside whatever
// succeeded so the caller can say so and carry on.
func FetchAll(ctx context.Context, obj pelicanobj.Store, refs []Ref) ([]*Index, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	workers := min(len(refs), max(4, runtime.GOMAXPROCS(0)))
	var (
		mu       sync.Mutex
		firstErr error
	)
	out := make([]*Index, len(refs))
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				ix, err := Fetch(ctx, obj, refs[i])
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else {
					out[i] = ix
				}
				mu.Unlock()
			}
		})
	}
	for i := range refs {
		select {
		case next <- i:
		case <-ctx.Done():
			close(next)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(next)
	wg.Wait()
	live := out[:0]
	for _, ix := range out {
		if ix != nil {
			live = append(live, ix)
		}
	}
	return live, firstErr
}

// Set is several indexes consulted as one, newest first.
type Set struct{ indexes []*Index }

func NewSet(indexes []*Index) *Set { return &Set{indexes: indexes} }

// Lookup asks each index in turn. Order matters when a chunk appears in
// more than one pack — a re-upload under the same identity, which is
// wasted bytes rather than corruption — and the later index is the one
// whose pack is most likely to still exist.
func (s *Set) Lookup(id [32]byte) (Loc, bool) {
	for i := len(s.indexes) - 1; i >= 0; i-- {
		if loc, ok := s.indexes[i].Lookup(id); ok {
			return loc, true
		}
	}
	return Loc{}, false
}

// Covers reports whether some index in the set claims this pack, which is
// how a reader knows a trailer fetch is unnecessary.
func (s *Set) Covers(pack string) bool {
	for _, ix := range s.indexes {
		for _, p := range ix.packs {
			if p == pack {
				return true
			}
		}
	}
	return false
}

// Entry types are stored as a byte rather than the trailer's string. The
// mapping is closed: an unknown code reads back as a data chunk, which is
// what an absent type has always meant.
func typeCode(t string) byte {
	switch t {
	case "catalog":
		return 1
	case "shard":
		return 2
	case "sb":
		return 3
	default:
		return 0
	}
}

func typeName(c byte) string {
	switch c {
	case 1:
		return "catalog"
	case 2:
		return "shard"
	case 3:
		return "sb"
	default:
		return ""
	}
}
