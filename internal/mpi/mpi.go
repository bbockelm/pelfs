// Package mpi is the multi-pack index: one object answering "which pack
// holds this identity" across many packs.
//
// It exists because locating anything otherwise costs one federation
// round trip PER PACK — a pack's trailer is its own index, so a reader
// with no idea which pack to ask consults them all. Git reached the same
// place and answered the same way, with per-pack .idx files and then a
// multi-pack-index across them. The asymmetry sharpens it here: git's
// .idx files are local and mapped, so consulting two hundred is
// microseconds; ours are remote, so the identical structure costs two
// hundred round trips.
//
// AN ENTRY IS 16 BYTES, and both halves of that are deliberate.
//
// 12 bytes of identity, not 32, because a truncated key can only produce
// a FALSE POSITIVE: the caller holds the full identity and checks what it
// finds. At 96 bits and a hundred million entries a collision is a
// ~10^-13 event, and the answer to one is to look in both packs — which
// is why a colliding entry stores both names rather than being refused.
//
// 4 bytes naming the pack, and NOTHING ELSE — no offset, no length, no
// type. Those are redundant with the pack the reader is about to fetch:
// genfs takes packs whole, so the pack's own trailer says where
// everything inside it is. An index that repeated them would be a second
// record to keep in agreement with the first, for bytes the reader
// already has.
//
// At 16 bytes a hundred million objects is 1.6 GB rather than 5.3, which
// still is not something to fetch. It is not meant to be: the table
// carries samples so a reader takes the header once and one ~64 KB window
// per lookup (Reader, remote.go). Fetching an index whole is an
// optimization for small ones, not the model.
//
// What this is NOT: a place where identity binds to location. An index is
// DERIVED — publish writes it, repack rewrites it, deleting one costs
// only speed. Catalogs and chunkrefs go on naming identities alone, which
// is what lets a repack move bytes without rewriting anything that refers
// to them.
package mpi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

const (
	magic = "PELFSMP2"
	// headerLen is 8-byte aligned, like the table it carries.
	headerLen = 32
	// KeyLen is how much of an identity an entry holds.
	KeyLen = 12
	// recordLen is an offset into the strings blob, and nothing else.
	recordLen = 4
	// Dir is the key-space directory holding index objects.
	Dir = "mpi"
)

// ErrFormat reports bytes that are not an index this build understands.
var ErrFormat = fmt.Errorf("mpi: unrecognized index")

// Builder accumulates identity -> pack across packs.
type Builder struct {
	// packs maps a truncated key to the packs claiming it. A key with more
	// than one is a collision, which the index records rather than
	// resolves: the reader looks in both.
	packs map[string][]string
	order []string
}

func NewBuilder() *Builder { return &Builder{packs: map[string][]string{}} }

// Add records that pack holds id.
func (b *Builder) Add(id [32]byte, pack string) {
	k := string(id[:KeyLen])
	cur, seen := b.packs[k]
	if !seen {
		b.order = append(b.order, k)
		b.packs[k] = []string{pack}
		return
	}
	for _, p := range cur {
		if p == pack {
			return
		}
	}
	b.packs[k] = append(cur, pack)
}

// Len is how many distinct keys have been added, and Packs how many packs
// they span — the two numbers a consolidation policy reads without
// fetching anything.
func (b *Builder) Len() int { return len(b.packs) }

func (b *Builder) Packs() int {
	seen := map[string]struct{}{}
	for _, ps := range b.packs {
		for _, p := range ps {
			seen[p] = struct{}{}
		}
	}
	return len(seen)
}

// Encode writes the index: a header, the strings blob, then the table.
//
// Identical pack lists share one string, which matters more than it
// sounds: every entry in a pack names the same list, so a 2 MiB pack
// holding five hundred chunks costs one copy of its name.
func (b *Builder) Encode() []byte {
	var blob []byte
	offsets := map[string]uint32{}
	intern := func(s string) uint32 {
		if off, ok := offsets[s]; ok {
			return off
		}
		off := uint32(len(blob))
		offsets[s] = off
		blob = binary.LittleEndian.AppendUint16(blob, uint16(len(s)))
		blob = append(blob, s...)
		return off
	}
	tbl := packidx.NewBuilder(KeyLen, recordLen, 0)
	sort.Strings(b.order)
	for _, k := range b.order {
		names := b.packs[k]
		sort.Strings(names)
		var v [recordLen]byte
		binary.LittleEndian.PutUint32(v[:], intern(strings.Join(names, ",")))
		// The builder rejects nothing: a key is 12 bytes by construction.
		_ = tbl.Add([]byte(k), v[:])
	}
	table := tbl.Encode()
	out := make([]byte, headerLen+len(blob)+len(table))
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint32(out[8:], 1)
	binary.LittleEndian.PutUint32(out[12:], uint32(len(blob)))
	copy(out[headerLen:], blob)
	copy(out[headerLen+len(blob):], table)
	return out
}

// Index is one index read in place.
type Index struct {
	blob  []byte
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
	blobLen := int(binary.LittleEndian.Uint32(b[12:]))
	if headerLen+blobLen > len(b) {
		return nil, fmt.Errorf("%w: %d bytes of pack names in a %d-byte index", ErrFormat, blobLen, len(b))
	}
	table, err := packidx.Open(b[headerLen+blobLen:])
	if err != nil {
		return nil, err
	}
	if table.KeyLen() != KeyLen || table.RecordLen() != recordLen {
		return nil, fmt.Errorf("%w: %d/%d entries", ErrFormat, table.KeyLen(), table.RecordLen())
	}
	return &Index{blob: b[headerLen : headerLen+blobLen], table: table}, nil
}

// Lookup returns the packs that may hold id, newest-preferring order
// undefined WITHIN one index: more than one name means a truncated-key
// collision, and the caller looks in each until the pack's own trailer
// confirms the full identity.
func (ix *Index) Lookup(id [32]byte) ([]string, bool) {
	v, ok := ix.table.Lookup(id[:KeyLen])
	if !ok {
		return nil, false
	}
	return ix.names(binary.LittleEndian.Uint32(v))
}

func (ix *Index) names(off uint32) ([]string, bool) { return names(ix.blob, off) }

// names resolves one record — an offset into the strings blob — to the
// pack list it interns. It takes the blob rather than an Index because the
// windowed reader (remote.go) holds the blob without ever holding an
// Index, and resolving a record must not mean two implementations of the
// same three bounds checks.
func names(blob []byte, off uint32) ([]string, bool) {
	if int(off)+2 > len(blob) {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(blob[off:]))
	if int(off)+2+n > len(blob) {
		return nil, false
	}
	return splitNames(string(blob[int(off)+2 : int(off)+2+n])), true
}

// splitNames is the one place that knows a record's pack list is comma
// separated, since Builder.Encode and MergeTo both join it that way.
func splitNames(s string) []string { return strings.Split(s, ",") }

// Len is the number of entries.
func (ix *Index) Len() int { return ix.table.Len() }

// Each visits every entry in key order: the truncated key, and the packs
// it names. It walks the table in place rather than materializing it, so
// a caller can check that a merged index still answers for everything its
// inputs did without holding either of them.
func (ix *Index) Each(fn func(key []byte, packs []string)) {
	for i := 0; i < ix.table.Len(); i++ {
		k, v := ix.table.At(i)
		names, ok := ix.names(binary.LittleEndian.Uint32(v))
		if !ok {
			continue
		}
		fn(k, names)
	}
}

// Packs are the packs this index names, which is what a retention sweep
// compares against the live set to decide whether to keep it.
func (ix *Index) Packs() []string {
	seen := map[string]struct{}{}
	var out []string
	ix.Each(func(_ []byte, names []string) {
		for _, p := range names {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	})
	sort.Strings(out)
	return out
}

// MergeTo merges several indexes into w, newest LAST, spooling the merged
// table rather than holding it.
//
// It advances a cursor per input rather than holding their contents, so
// merging tiers that together describe a hundred million objects costs
// memory proportional to the number of TIERS. That is what makes a large
// index buildable at all: it is never built at once, only merged — and
// it is why the write path publishes a small index per generation and
// consolidates later rather than maintaining one global index.
//
// THE STRINGS BLOB IS HELD while the table streams, and the asymmetry is
// deliberate rather than an oversight. The records are bounded by
// ENTRIES, which is the number this whole structure exists to survive;
// the blob is bounded by the number of DISTINCT PACK-NAME LISTS, and
// every entry in a pack names the same list — a 2 MiB pack holding five
// hundred chunks costs one copy of its name. A hundred million entries
// across 400,000 packs is tens of MB of blob against 1.6 GB of records.
// It also cannot stream: the header states the blob's length and lands
// before it, and that length is only known once the last entry has been
// interned.
//
// Nothing is written to w until the merge has succeeded, so a failure
// leaves an empty destination rather than a prefix of an index — except
// for a failure inside Finish, which the caller discards.
// MergeTo streams a merge to w, reporting what it wrote so a caller can
// name the object without reading it back — which would undo the point of
// streaming it out.
func MergeTo(w io.Writer, spool io.ReadWriteSeeker, indexes []*Index) (entries, packs int, err error) {
	var blob []byte
	offsets := map[string]uint32{}
	// Distinct pack names, for the ref. The blob is keyed by the joined
	// LIST a key resolves to, so its size is not the pack count.
	packNames := map[string]struct{}{}
	intern := func(s string) uint32 {
		if off, ok := offsets[s]; ok {
			return off
		}
		off := uint32(len(blob))
		offsets[s] = off
		for _, name := range strings.Split(s, ",") {
			packNames[name] = struct{}{}
		}
		blob = binary.LittleEndian.AppendUint16(blob, uint16(len(s)))
		blob = append(blob, s...)
		return off
	}
	tables := make([]*packidx.Table, len(indexes))
	for i, ix := range indexes {
		tables[i] = ix.table
	}
	sw := packidx.NewStreamWriter(spool, KeyLen, recordLen, 0)
	err = packidx.MergeKeys(tables, func(from int, key, v []byte) error {
		// Later inputs win outright: a key found in a newer tier names the
		// pack that placement is current, and an older tier's answer is at
		// best redundant and at worst a deleted pack. The offset only means
		// anything against the blob of the index that supplied it, which is
		// why the walk reports which one that was.
		names, ok := indexes[from].names(binary.LittleEndian.Uint32(v))
		if !ok || len(names) == 0 {
			// An offset that does not resolve is a corrupt index, not a
			// reason to fail a merge of the others: the key is dropped and
			// the reader falls back to the trailers for it, which is what it
			// would have done had the index never existed.
			return nil
		}
		names = sortedUnique(names)
		var rec [recordLen]byte
		binary.LittleEndian.PutUint32(rec[:], intern(strings.Join(names, ",")))
		return sw.Add(key, rec[:])
	})
	if err != nil {
		return 0, 0, err
	}
	head := make([]byte, headerLen+len(blob))
	copy(head[0:8], magic)
	binary.LittleEndian.PutUint32(head[8:], 1)
	binary.LittleEndian.PutUint32(head[12:], uint32(len(blob)))
	copy(head[headerLen:], blob)
	if _, err := w.Write(head); err != nil {
		return 0, 0, err
	}
	if _, err := sw.Finish(w); err != nil {
		return 0, 0, err
	}
	return sw.Len(), len(packNames), nil
}

// sortedUnique is what Builder.Add and Builder.Encode do between them —
// duplicates dropped, then sorted — applied to a list a merge is passing
// through rather than rebuilding, so the streaming and in-memory paths
// produce the same bytes.
func sortedUnique(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	kept := out[:0]
	for i, n := range out {
		if i > 0 && n == out[i-1] {
			continue
		}
		kept = append(kept, n)
	}
	return kept
}

// Merge is MergeTo into memory, which is what a small merge wants: most
// are one generation's index folded into the tier ahead of it, and
// asking a caller for a temp file to move kilobytes would be the wrong
// default. A merge whose output does not fit should call MergeTo with a
// file.
func Merge(indexes []*Index) []byte {
	var out bytes.Buffer
	if _, _, err := MergeTo(&out, packidx.MemSpool(), indexes); err != nil {
		// Unreachable: a memory spool and a bytes.Buffer cannot fail to be
		// written, and the merge itself only fails on a write. Returning
		// nothing rather than a truncated index leaves the caller's Open to
		// refuse it, which is the same treatment a merge that never ran
		// gets.
		return nil
	}
	return out.Bytes()
}

// The ref naming one index object is superblock.IndexRef: it is a field
// of a signed document, so its encoding is defined where every other
// signed field is (see superblock.IndexRef). This package builds and
// verifies the object the ref names.

// Fetch reads and verifies one index object whole.
//
// This is the WRITE path's reader: a merge needs every record, so it needs
// every byte, and having them all is what makes the whole-object hash
// checkable. A READER looking up one identity wants Reader (remote.go),
// which takes the header once and a window per lookup and falls back to
// this only for an index small enough that fetching it whole is cheaper
// than not.
func Fetch(ctx context.Context, obj pelicanobj.Store, ref superblock.IndexRef) (*Index, error) {
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
// Serial fetches would trade N round trips for a smaller N still paid one
// after another, which is most of the problem rather than a fix. This is
// also what makes TIERS affordable: a lookup that may have to consult
// several indexes costs one round trip of latency, not one per tier.
//
// A failed index is not a failed mount: an index is derived, the trailers
// still answer, so what verified is returned alongside the error.
func FetchAll(ctx context.Context, obj pelicanobj.Store, refs []superblock.IndexRef) ([]*Index, error) {
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

// Set is several indexes consulted as one, oldest first in the slice.
type Set struct{ indexes []*Index }

func NewSet(indexes []*Index) *Set { return &Set{indexes: indexes} }

// Lookup asks the NEWEST index first and stops at the first hit, which is
// "the most recent pack holding this object". Order matters because the
// same identity is placed again by any generation that rewrites it, and
// an older tier's answer names a pack retention is more likely to have
// swept.
func (s *Set) Lookup(id [32]byte) ([]string, bool) {
	for i := len(s.indexes) - 1; i >= 0; i-- {
		if packs, ok := s.indexes[i].Lookup(id); ok {
			return packs, true
		}
	}
	return nil, false
}

// Covers reports whether some index claims this pack, which is how a
// reader knows a trailer fetch is unnecessary.
func (s *Set) Covers(pack string) bool {
	for _, ix := range s.indexes {
		for _, p := range ix.Packs() {
			if p == pack {
				return true
			}
		}
	}
	return false
}
