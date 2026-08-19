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
// per lookup (see packidx). Fetching an index whole is an optimization
// for small ones, not the model.
//
// What this is NOT: a place where identity binds to location. An index is
// DERIVED — publish writes it, repack rewrites it, deleting one costs
// only speed. Catalogs and chunkrefs go on naming identities alone, which
// is what lets a repack move bytes without rewriting anything that refers
// to them.
package mpi

import (
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

func (ix *Index) names(off uint32) ([]string, bool) {
	if int(off)+2 > len(ix.blob) {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(ix.blob[off:]))
	if int(off)+2+n > len(ix.blob) {
		return nil, false
	}
	return strings.Split(string(ix.blob[int(off)+2:int(off)+2+n]), ","), true
}

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

// Merge streams several indexes into one, newest LAST.
//
// It advances a cursor per input rather than holding their contents, so
// merging tiers that together describe a hundred million objects costs
// memory proportional to the number of TIERS. That is what makes a large
// index buildable at all: it is never built at once, only merged — and
// it is why the write path publishes a small index per generation and
// consolidates later rather than maintaining one global index.
//
// The output records are still assembled in memory, which bounds a merge
// to the size of the tier being written rather than to the volume. A
// merge large enough to matter should spool; nothing needs that yet, and
// saying so is better than pretending the limit is not there.
func Merge(indexes []*Index) []byte {
	out := NewBuilder()
	at := make([]int, len(indexes))
	for {
		best, bestKey := -1, ""
		for i, ix := range indexes {
			if at[i] >= ix.table.Len() {
				continue
			}
			k, _ := ix.table.At(at[i])
			if best < 0 || string(k) < bestKey {
				best, bestKey = i, string(k)
			}
		}
		if best < 0 {
			break
		}
		var names []string
		for i, ix := range indexes {
			if at[i] >= ix.table.Len() {
				continue
			}
			k, v := ix.table.At(at[i])
			if string(k) != bestKey {
				continue
			}
			// Later inputs win outright: a key found in a newer tier names
			// the pack that placement is current, and an older tier's
			// answer is at best redundant and at worst a deleted pack.
			if got, ok := ix.names(binary.LittleEndian.Uint32(v)); ok {
				names = got
			}
			at[i]++
		}
		var id [32]byte
		copy(id[:], bestKey)
		for _, p := range names {
			out.Add(id, p)
		}
	}
	return out.Encode()
}

// Ref names one index object, as a superblock lists it.
type Ref struct {
	Name    string
	Hash    [32]byte
	Size    int64
	Entries uint32
	Packs   uint32
}

// Fetch reads and verifies one index object whole. Right for a small
// index; a large one should be range-read through packidx.Header.
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
// Serial fetches would trade N round trips for a smaller N still paid one
// after another, which is most of the problem rather than a fix. This is
// also what makes TIERS affordable: a lookup that may have to consult
// several indexes costs one round trip of latency, not one per tier.
//
// A failed index is not a failed mount: an index is derived, the trailers
// still answer, so what verified is returned alongside the error.
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
