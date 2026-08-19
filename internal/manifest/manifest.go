// Package manifest is the pack list, moved out of the superblock.
//
// A superblock carries every pack it references — name, trailer hash,
// size — and carries the whole list forward into the next generation. At
// a hundred million objects that is 200,000 to 400,000 packs and 12 to
// 25 MB of superblock, read on every mount, rewritten on every seal, and
// growing forever. It sits on the critical path of everything while
// serving three jobs, two of which the multi-pack index has taken over.
//
// What remains is what a signed generation must still vouch for:
//
//   - AUTHENTICATION. Chunk data is self-verifying by identity, but a
//     pack trailer is not: a reader that falls back to trailers needs a
//     hash it can trust, and the signature is what makes it trustworthy.
//   - ENUMERATION. Retention needs to know which packs a live generation
//     names, and rescue needs to find them without an index.
//
// Neither requires the list to be INSIDE the superblock. So it is a
// derived, hash-named object, listed the way an index is: the signature
// covers a hash rather than the entries, and the manifest is fetched only
// when something needs enumeration or trailer authentication — which the
// index makes rare. The superblock stops growing with pack count.
//
// It is segmented and merged like an index, for the same reason: a
// generation adds a handful of packs and should write a small object, not
// rewrite the whole set.
//
// Two things make it simpler than an index. Its key is the pack NAME,
// which is fixed-width, so there is no truncation and no collision to
// resolve. And pack names begin with a zero-padded creation timestamp, so
// sorted by name is sorted by age — which is the order retention already
// thinks in, and lets a sweep find packs older than a cutoff through the
// sampled windows without reading a segment whole.
//
// One thing makes it harder: it is the only structure here that needs
// DELETION. A stale index entry is harmless — it names a swept pack and
// the lookup falls back — but the manifest is the authority on what
// exists. The answer is the rule an index already uses rather than a new
// one: do not delete, rewrite the segment when it is mostly dead.
// Retention only deletes packs no LIVE generation names, so a stale entry
// can only survive in a retired generation's manifest, which nobody
// reads.
package manifest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

const (
	magic = "PELFSPM1"
	// headerLen is 8-byte aligned, like the table it carries.
	headerLen = 16
	// keyLen holds a pack name zero-padded. Names are 23 bytes today
	// (p-<16 hex>-<4 hex>); the room is for a future naming scheme, not
	// for the current one to grow into accidentally — a longer name is
	// refused rather than silently truncated into a collision.
	keyLen = 32
	// recordLen is a trailer hash and a size.
	recordLen = 32 + 8
	// Dir is the key-space directory holding manifest objects.
	Dir = "manifests"
)

// ErrFormat reports bytes that are not a manifest this build understands.
var ErrFormat = fmt.Errorf("manifest: unrecognized manifest")

// Builder accumulates packs.
type Builder struct{ tbl *packidx.Builder }

func NewBuilder() *Builder {
	return &Builder{tbl: packidx.NewBuilder(keyLen, recordLen, 0)}
}

// Add records one pack.
func (b *Builder) Add(p packstore.SealedPack) error {
	if len(p.Name) > keyLen {
		return fmt.Errorf("manifest: pack name %q is %d bytes, over the %d-byte key", p.Name, len(p.Name), keyLen)
	}
	var key [keyLen]byte
	copy(key[:], p.Name)
	var v [recordLen]byte
	copy(v[0:32], p.TrailerHash[:])
	binary.LittleEndian.PutUint64(v[32:], uint64(p.Size))
	return b.tbl.Add(key[:], v[:])
}

// Len is how many packs have been added.
func (b *Builder) Len() int { return b.tbl.Len() }

// Encode writes the manifest.
func (b *Builder) Encode() []byte {
	table := b.tbl.Encode()
	out := make([]byte, headerLen+len(table))
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint32(out[8:], 1)
	copy(out[headerLen:], table)
	return out
}

// Manifest is one segment read in place.
type Manifest struct{ table *packidx.Table }

// Open validates the structure without reading the entries.
func Open(b []byte) (*Manifest, error) {
	if len(b) < headerLen || string(b[0:8]) != magic {
		return nil, ErrFormat
	}
	if v := binary.LittleEndian.Uint32(b[8:]); v != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, v)
	}
	table, err := packidx.Open(b[headerLen:])
	if err != nil {
		return nil, err
	}
	if table.KeyLen() != keyLen || table.RecordLen() != recordLen {
		return nil, fmt.Errorf("%w: %d/%d entries", ErrFormat, table.KeyLen(), table.RecordLen())
	}
	return &Manifest{table: table}, nil
}

// Lookup resolves one pack name.
func (m *Manifest) Lookup(name string) (packstore.SealedPack, bool) {
	if len(name) > keyLen {
		return packstore.SealedPack{}, false
	}
	var key [keyLen]byte
	copy(key[:], name)
	v, ok := m.table.Lookup(key[:])
	if !ok {
		return packstore.SealedPack{}, false
	}
	return decode(name, v), true
}

// Len is the number of packs.
func (m *Manifest) Len() int { return m.table.Len() }

// At returns the i'th pack in NAME order, which is creation order.
func (m *Manifest) At(i int) packstore.SealedPack {
	k, v := m.table.At(i)
	return decode(trimName(k), v)
}

func decode(name string, v []byte) packstore.SealedPack {
	p := packstore.SealedPack{Name: name, Size: int64(binary.LittleEndian.Uint64(v[32:]))}
	copy(p.TrailerHash[:], v[0:32])
	return p
}

func trimName(k []byte) string {
	for i, c := range k {
		if c == 0 {
			return string(k[:i])
		}
	}
	return string(k)
}

// MergeTo merges segments into w, newest LAST, spooling the merged table
// rather than holding it. As with an index, it holds a cursor per input
// rather than their contents, so the memory a merge costs is set by the
// number of segments and the samples — not by the number of packs.
//
// A pack appears in at most one segment in practice — it is written once
// — so the later-wins rule is a tie-break rather than a policy. It
// matters only after a repack has rewritten a segment.
//
// This has no blob to hold, so unlike an index (mpi.MergeTo) the whole
// object streams: its header is two fixed fields, and the records pass
// through untouched.
func MergeTo(w io.Writer, spool io.ReadWriteSeeker, segments []*Manifest) error {
	tables := make([]*packidx.Table, len(segments))
	for i, m := range segments {
		tables[i] = m.table
	}
	sw := packidx.NewStreamWriter(spool, keyLen, recordLen, 0)
	// The keys arrive padded and the records unchanged, so nothing here
	// re-encodes what a segment already accepted: a name too long for a
	// key could not have got into one of these in the first place.
	err := packidx.MergeKeys(tables, func(_ int, key, v []byte) error { return sw.Add(key, v) })
	if err != nil {
		return err
	}
	head := make([]byte, headerLen)
	copy(head[0:8], magic)
	binary.LittleEndian.PutUint32(head[8:], 1)
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err = sw.Finish(w)
	return err
}

// Merge is MergeTo into memory, which is what a small merge wants. A
// merge whose output does not fit should call MergeTo with a file.
func Merge(segments []*Manifest) []byte {
	var out bytes.Buffer
	if err := MergeTo(&out, packidx.MemSpool(), segments); err != nil {
		// Unreachable: a memory spool and a bytes.Buffer cannot fail to be
		// written. Returning nothing rather than a truncated segment leaves
		// the caller's Open to refuse it — and for a manifest that refusal
		// is the point, since a segment missing packs is worse than none.
		return nil
	}
	return out.Bytes()
}

// The ref naming one segment is superblock.ManifestRef: it is a field of
// a signed document, so its encoding is defined where every other signed
// field is. This package builds and verifies the object it names.

// Fetch reads and verifies one segment.
func Fetch(ctx context.Context, obj pelicanobj.Store, ref superblock.ManifestRef) (*Manifest, error) {
	rc, err := obj.Get(ctx, Dir+"/"+ref.Name, 0, -1)
	if err != nil {
		return nil, fmt.Errorf("manifest: fetch %s: %w", ref.Name, err)
	}
	raw, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	if rerr != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", ref.Name, rerr)
	}
	if cerr != nil {
		return nil, cerr
	}
	if got := blake3.Sum256(raw); got != ref.Hash {
		return nil, fmt.Errorf("manifest: %s hashes to %x, the generation says %x",
			ref.Name, got[:8], ref.Hash[:8])
	}
	return Open(raw)
}

// FetchAll reads every listed segment CONCURRENTLY.
//
// Unlike an index, a failure here is NOT survivable by falling back: the
// manifest is the only record of what a generation's packs are, so a
// caller that cannot read one cannot enumerate or authenticate. The error
// is returned with whatever succeeded, and the caller decides — retention
// must refuse to sweep on a partial view, while a reader that only wanted
// one pack may still find it.
func FetchAll(ctx context.Context, obj pelicanobj.Store, refs []superblock.ManifestRef) ([]*Manifest, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	workers := min(len(refs), max(4, runtime.GOMAXPROCS(0)))
	var (
		mu       sync.Mutex
		firstErr error
	)
	out := make([]*Manifest, len(refs))
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				m, err := Fetch(ctx, obj, refs[i])
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else {
					out[i] = m
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
	for _, m := range out {
		if m != nil {
			live = append(live, m)
		}
	}
	return live, firstErr
}

// Set is a generation's segments consulted as one.
type Set struct{ segments []*Manifest }

func NewSet(segments []*Manifest) *Set { return &Set{segments: segments} }

// Lookup asks the newest segment first.
func (s *Set) Lookup(name string) (packstore.SealedPack, bool) {
	for i := len(s.segments) - 1; i >= 0; i-- {
		if p, ok := s.segments[i].Lookup(name); ok {
			return p, true
		}
	}
	return packstore.SealedPack{}, false
}

// All enumerates every pack the generation names, in creation order, with
// the newest segment's record winning. Retention walks this.
func (s *Set) All() []packstore.SealedPack {
	seen := map[string]struct{}{}
	var out []packstore.SealedPack
	for i := len(s.segments) - 1; i >= 0; i-- {
		for j := 0; j < s.segments[i].Len(); j++ {
			p := s.segments[i].At(j)
			if _, dup := seen[p.Name]; dup {
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, p)
		}
	}
	sortByName(out)
	return out
}

func sortByName(p []packstore.SealedPack) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Name < p[j-1].Name; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
