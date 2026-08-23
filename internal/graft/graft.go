// Package graft implements external subtrees: a path inside a pelfs
// volume whose bytes stay at a foreign Pelican prefix and are served by
// ranged reads, with no copy under the volume's own prefix
// (docs/design-graft.md).
//
// SPIKE. What is here proves the read path end to end — spider, block
// digest, signed superblock entry, ranged fetch, verification, kernel
// mount — and it is deliberately the smallest thing that does. The
// production gaps are listed in the design doc's ranked work; the load-
// bearing ones are that the index is fetched WHOLE rather than by the
// ranged window packidx already supports, and that the spider is
// single-threaded.
//
// # Where a graft sits in the format
//
// It is a LOCATION layer, not a content model. A catalog chunkref stores
// {identity, llen, clen, alg, keyid} and no pack name, because "location
// lives outside the catalog" is already the rule (internal/genfs,
// packLoc). A grafted file's rows are ordinary chunkref rows — nothing in
// the catalog format changes, and no catalog knows a graft exists. What
// changes is that their identities resolve through a graft index instead
// of a pack trailer.
//
// Two consequences fall out of that and both are load-bearing:
//
//   - Identity is the SAME function as everywhere else (BLAKE3-256 of the
//     plaintext block, chunkid.Hasher). So the two location layers are
//     interchangeable: if a graft block happens to equal a pack chunk,
//     either location serves the same bytes and reading from the pack is
//     simply the cheaper answer. Verification needs no new mechanism.
//   - Blocks are FIXED SIZE, not content-defined. A ranged read must be
//     able to verify exactly what it fetched, and a whole-object digest
//     cannot do that — see internal/pelicanobj's GetUnverified, which
//     records the same fact from the other direction. Fixed blocks are
//     what make a partial read verifiable, and the price is that a graft
//     never dedups against CDC-chunked packed content.
package graft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"

	"lukechampine.com/blake3"
)

const (
	magic = "PELFSGR1"
	// keyLen is a chunk identity.
	keyLen = chunkid.IdentitySize
	// recordLen is {object index, offset, length}: which object in the
	// string table, where in it, and how long. 4 GiB of objects per graft
	// and 4 GiB per block are both far past anything a block size makes
	// sensible, so uint32 is not a limit anyone reaches.
	recordLen = 4 + 8 + 4
	// headerLen is 8-byte aligned like the table it carries.
	headerLen = 32
	// Dir is the key-space directory holding graft index objects, under
	// the VOLUME's prefix. The index is the volume's own metadata about a
	// foreign tree, so it lives with the volume and not with the source —
	// which is also what makes it immutable and signature-covered while
	// the source is neither.
	Dir = "grafts"
)

// DefaultBlock is the fixed block size a spider cuts with.
//
// 1 MiB, and the reasoning is the opposite of the packed path's. A CDC
// chunk is sized to maximize dedup across edits; a graft block is sized
// to trade index size against read amplification on a random read, and
// nothing about it dedups. At 1 MiB a 1 TB graft indexes to ~1M blocks
// (~48 MB of index) and the smallest verifiable read is 1 MiB. Smaller
// blocks make a 4 KiB read cheaper and the index proportionally larger;
// this is the same trade the arena already makes for packed chunks, at
// the same order of magnitude.
const DefaultBlock int64 = 1 << 20

// ErrFormat reports bytes that are not a graft index this build reads.
var ErrFormat = errors.New("graft: unrecognized graft index")

// Loc locates one block inside the SOURCE prefix: which object, where,
// and how long. It is the graft's answer to genfs's packLoc, and it has
// the same shape for the same reason — a location is (container, offset,
// length) whichever layer resolves it.
type Loc struct {
	Key    string
	Off    int64
	Length int64
}

// Builder accumulates the identity -> Loc table for one graft.
type Builder struct {
	tbl   *packidx.Builder
	block int64
	keys  []string
	keyID map[string]uint32
	bytes int64
	// seen makes Add idempotent so Len and Bytes describe DISTINCT blocks.
	// packidx already keeps the last of each run of equal keys at Encode,
	// so the encoded table is correct either way; this is about the
	// counters, which a user reads as "how big is this graft".
	//
	// SCALE CAVEAT, and it is the spider's real memory bound: 32 bytes a
	// block plus map overhead, so ~5 GB at the 100M-block target. A
	// production spider streams identities to disk and dedups by sorting
	// (internal/extsort, which the seal path already uses for exactly this
	// shape of problem) rather than holding a set.
	seen map[chunkid.Identity]struct{}
}

// NewBuilder starts an index for a spider cutting at block bytes.
func NewBuilder(block int64) *Builder {
	if block <= 0 {
		block = DefaultBlock
	}
	return &Builder{
		tbl:   packidx.NewBuilder(keyLen, recordLen, 0),
		block: block,
		keyID: make(map[string]uint32),
		seen:  make(map[chunkid.Identity]struct{}),
	}
}

// Add records one block. A repeated identity is dropped: the same bytes
// in two places need only one location, and which one is arbitrary.
func (b *Builder) Add(id chunkid.Identity, l Loc) error {
	if _, dup := b.seen[id]; dup {
		return nil
	}
	oi, ok := b.keyID[l.Key]
	if !ok {
		oi = uint32(len(b.keys))
		b.keys = append(b.keys, l.Key)
		b.keyID[l.Key] = oi
	}
	var v [recordLen]byte
	binary.LittleEndian.PutUint32(v[0:], oi)
	binary.LittleEndian.PutUint64(v[4:], uint64(l.Off))
	binary.LittleEndian.PutUint32(v[12:], uint32(l.Length))
	if err := b.tbl.Add(id[:], v[:]); err != nil {
		return err
	}
	b.seen[id] = struct{}{}
	b.bytes += l.Length
	return nil
}

// Len is how many distinct blocks the index holds, Bytes their total.
func (b *Builder) Len() int     { return b.tbl.Len() }
func (b *Builder) Bytes() int64 { return b.bytes }
func (b *Builder) Block() int64 { return b.block }

// Encode writes the index object: header, sorted searchable table, then
// the object-key string table the records index into.
func (b *Builder) Encode() []byte {
	table := b.tbl.Encode()
	var strs []byte
	for _, k := range b.keys {
		strs = append(strs, k...)
		strs = append(strs, 0)
	}
	out := make([]byte, headerLen+len(table)+len(strs))
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint32(out[8:], 1)
	binary.LittleEndian.PutUint32(out[12:], uint32(len(b.keys)))
	binary.LittleEndian.PutUint64(out[16:], uint64(b.block))
	binary.LittleEndian.PutUint64(out[24:], uint64(len(table)))
	copy(out[headerLen:], table)
	copy(out[headerLen+len(table):], strs)
	return out
}

// Index is a decoded graft index.
type Index struct {
	table *packidx.Table
	keys  []string
	block int64
}

// Open decodes an index object.
func Open(b []byte) (*Index, error) {
	if len(b) < headerLen || string(b[0:8]) != magic {
		return nil, ErrFormat
	}
	if v := binary.LittleEndian.Uint32(b[8:]); v != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, v)
	}
	nkeys := int(binary.LittleEndian.Uint32(b[12:]))
	block := int64(binary.LittleEndian.Uint64(b[16:]))
	tlen := int64(binary.LittleEndian.Uint64(b[24:]))
	if tlen < 0 || headerLen+tlen > int64(len(b)) {
		return nil, fmt.Errorf("%w: table length %d past the object", ErrFormat, tlen)
	}
	t, err := packidx.Open(b[headerLen : headerLen+tlen])
	if err != nil {
		return nil, fmt.Errorf("graft: %w", err)
	}
	keys := make([]string, 0, nkeys)
	for _, s := range strings.Split(string(b[headerLen+tlen:]), "\x00") {
		keys = append(keys, s)
	}
	// Split leaves a trailing empty element after the last terminator.
	if n := len(keys); n > 0 && keys[n-1] == "" {
		keys = keys[:n-1]
	}
	if len(keys) != nkeys {
		return nil, fmt.Errorf("%w: header says %d objects, string table holds %d", ErrFormat, nkeys, len(keys))
	}
	return &Index{table: t, keys: keys, block: block}, nil
}

// Lookup resolves one identity.
func (ix *Index) Lookup(id []byte) (Loc, bool) {
	v, ok := ix.table.Lookup(id)
	if !ok {
		return Loc{}, false
	}
	oi := binary.LittleEndian.Uint32(v[0:])
	if int(oi) >= len(ix.keys) {
		return Loc{}, false
	}
	return Loc{
		Key:    ix.keys[oi],
		Off:    int64(binary.LittleEndian.Uint64(v[4:])),
		Length: int64(binary.LittleEndian.Uint32(v[12:])),
	}, true
}

// Len is how many blocks the index covers; Block the size it cut with.
func (ix *Index) Len() int     { return ix.table.Len() }
func (ix *Index) Block() int64 { return ix.block }

// Objects lists every source object the index locates blocks in, sorted.
// fsck's cheap mode stats exactly these.
func (ix *Index) Objects() []string {
	out := append([]string(nil), ix.keys...)
	sort.Strings(out)
	return out
}

// IndexKey is where an index object of the given hash lives under the
// volume prefix. Hash-named, like every other derived object.
func IndexKey(h [32]byte) string {
	return Dir + "/" + fmt.Sprintf("%x", h)
}

// Put uploads an index object and returns the ref to record. Immutable
// and hash-named, so an upload is idempotent and an interrupted one costs
// nothing (retention's grace window covers an orphan).
func Put(ctx context.Context, obj pelicanobj.Store, mountPath, source string, ix *Builder, treeBytes int64) (superblock.GraftEntry, error) {
	raw := ix.Encode()
	h := blake3.Sum256(raw)
	if err := obj.Put(ctx, IndexKey(h), strings.NewReader(string(raw))); err != nil {
		return superblock.GraftEntry{}, fmt.Errorf("graft: upload index: %w", err)
	}
	return superblock.GraftEntry{
		Path:   mountPath,
		Source: source,
		Index:  h,
		Size:   int64(len(raw)),
		Block:  ix.Block(),
		Blocks: uint64(ix.Len()),
		Bytes:  treeBytes,
	}, nil
}

// Fetch reads and VERIFIES one graft index against the hash the signed
// superblock records for it.
//
// The verification is the whole reason a graft can be trusted at all. The
// index is what says "these bytes live at that URL", so an unverified one
// is an attacker's chance to redirect a read; the superblock signature
// covers the hash, so checking it here extends the signature over the
// location table. This is the same argument manifest.Fetch makes, and
// unlike a pack index it is NOT a hint — there is no fallback that could
// answer the question another way.
func Fetch(ctx context.Context, obj pelicanobj.Store, g superblock.GraftEntry) (*Index, error) {
	rc, err := obj.Get(ctx, IndexKey(g.Index), 0, -1)
	if err != nil {
		return nil, fmt.Errorf("graft %s: fetch index: %w", g.Path, err)
	}
	raw, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	if rerr != nil {
		return nil, fmt.Errorf("graft %s: fetch index: %w", g.Path, rerr)
	}
	if cerr != nil {
		return nil, fmt.Errorf("graft %s: fetch index: %w", g.Path, cerr)
	}
	if h := blake3.Sum256(raw); h != g.Index {
		return nil, fmt.Errorf("graft %s: index object %x hashes to %x", g.Path, g.Index, h)
	}
	return Open(raw)
}

// InlineKeep is the size below which a spider KEEPS a file's bytes rather
// than only its digests, so publish can store it inline in the catalog.
//
// This is a real design decision and not a plumbing detail: a grafted file
// under the inline threshold is COPIED into the volume, and stops being
// grafted at all. Three reasons it is the right answer rather than a
// concession.
//
// Publish requires it. A file at or under Options.InlineMax is stored in
// the catalog by rule, and ContentProvider has no way to say "inline this
// one but here are chunk records" — the shapes are exclusive. A provider
// that declines such a file sends publish to Source.Open, and a graft has
// nothing to open.
//
// It costs nothing and buys integrity. The bytes are kilobytes; the
// catalog they land in is content-addressed and covered by the superblock
// signature, so an inlined file is verified by the same Merkle path as
// everything else and does not depend on the source staying put. A graft's
// purpose is to avoid copying BULK data, and a 200-byte file is not that.
//
// And it removes a round trip. Serving a 200-byte file from a foreign
// origin costs a request; serving it from the catalog that was fetched
// anyway costs nothing.
//
// Set above publish.DefaultInlineMax (2048) so a caller that raises the
// threshold somewhat still finds bytes in hand. A file between this and
// the caller's InlineMax falls through to Source.Open, which says so.
const InlineKeep = 64 << 10

// File is one spidered file: where it lands in the volume, how big it is,
// when it changed at the source, and the chunkref rows that describe it.
type File struct {
	Path    string
	Size    int64
	MtimeNS int64
	Refs    []catalog.ChunkRef
	// Body is the whole file, kept only for files at or under InlineKeep.
	// Nil for everything else, which is the case the graft exists for.
	Body []byte
}

// Result is one completed spider.
type Result struct {
	Files []File
	Index *Builder
	Bytes int64
	// Inlined counts files small enough to be copied into the catalog
	// instead of grafted (InlineKeep), and InlinedBytes what they weigh.
	// Reported because "how much of this graft is not actually grafted"
	// is a fact a user should not have to infer.
	Inlined      int
	InlinedBytes int64
}

// SpiderOptions configures a spider.
type SpiderOptions struct {
	// Src reads the foreign prefix.
	Src pelicanobj.Store
	// Block is the fixed cut size; zero takes DefaultBlock.
	Block int64
	// Hasher computes identities. The zero value hashes unkeyed, which is
	// the only mode a graft may use — see genfs's refusal on encrypted
	// volumes and the design doc's encryption section.
	Hasher chunkid.Hasher
	// Progress, when set, is called once per file.
	Progress func(p string, size int64)
}

// Spider walks the source prefix, streams every object ONCE, and cuts it
// into fixed blocks with an identity each.
//
// Streaming once is the cost model to hold onto: a graft is O(size of the
// source) in bandwidth at graft time and O(0) afterwards, where a copy is
// O(size) in bandwidth AND O(size) in storage forever. That single pass
// is also the only moment the source is known to be self-consistent, and
// nothing here can detect a source mutated underneath it mid-walk — the
// design doc says so plainly rather than implying a snapshot.
func Spider(ctx context.Context, o SpiderOptions) (*Result, error) {
	if o.Src == nil {
		return nil, errors.New("graft: a source store is required")
	}
	block := o.Block
	if block <= 0 {
		block = DefaultBlock
	}
	res := &Result{Index: NewBuilder(block)}
	// Bytes of the file being read, retained only while it is small enough
	// to inline. Reset per file so a large file cannot hold a buffer.
	var small []byte
	ch, err := o.Src.ListAll(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("graft: list %s: %w", o.Src, err)
	}
	var objs []*pelicanobj.Object
	for ob := range ch {
		if ob == nil {
			return nil, fmt.Errorf("graft: listing %s failed", o.Src)
		}
		if ob.IsDir {
			continue
		}
		objs = append(objs, ob)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key })
	buf := make([]byte, block)
	for _, ob := range objs {
		f := File{
			Path:    path.Clean("/" + ob.Key),
			Size:    ob.Size,
			MtimeNS: ob.Mtime.UnixNano(),
		}
		small = nil
		rc, err := o.Src.Get(ctx, ob.Key, 0, -1)
		if err != nil {
			return nil, fmt.Errorf("graft: read %s: %w", ob.Key, err)
		}
		var off int64
		for {
			n, rerr := io.ReadFull(rc, buf)
			if n > 0 {
				if off+int64(n) <= InlineKeep {
					small = append(small, buf[:n]...)
				} else {
					small = nil
				}
				id := o.Hasher.Sum(buf[:n])
				if err := res.Index.Add(id, Loc{Key: ob.Key, Off: off, Length: int64(n)}); err != nil {
					rc.Close() //nolint:errcheck
					return nil, fmt.Errorf("graft: index %s: %w", ob.Key, err)
				}
				f.Refs = append(f.Refs, catalog.ChunkRef{
					Identity: append([]byte(nil), id[:]...),
					LLen:     int64(n),
					// A grafted block is stored as it arrives: plaintext,
					// uncompressed. AlgNone with clen == llen is exactly
					// what entrycodec.Decode passes through untouched, so
					// the read path needs no branch for it.
					CLen:          int64(n),
					Alg:           0,
					KeyID:         0,
					LogicalOffset: off,
				})
				off += int64(n)
			}
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				break
			}
			if rerr != nil {
				rc.Close() //nolint:errcheck
				return nil, fmt.Errorf("graft: read %s at %d: %w", ob.Key, off, rerr)
			}
		}
		if err := rc.Close(); err != nil {
			return nil, fmt.Errorf("graft: read %s: %w", ob.Key, err)
		}
		// The listing's size and the bytes actually delivered must agree,
		// or the catalog would record a length no read can satisfy. This
		// is the first place a source mutating mid-spider is caught, and
		// it is caught rather than published.
		if off != ob.Size {
			return nil, fmt.Errorf("graft: %s listed %d bytes, delivered %d "+
				"(the source changed while it was being spidered)", ob.Key, ob.Size, off)
		}
		f.Size = off
		res.Bytes += off
		if off > 0 && off <= InlineKeep {
			// Small enough to inline, so the digests just computed for it
			// are dropped along with its index rows: an inlined file is
			// not grafted, and leaving its blocks in the index would name
			// locations nothing resolves through.
			f.Body = small
			f.Refs = nil
			res.Inlined++
			res.InlinedBytes += off
		}
		res.Files = append(res.Files, f)
		if o.Progress != nil {
			o.Progress(f.Path, f.Size)
		}
	}
	return res, nil
}

// KeyAt is the identity of the i'th block in index order. It exists for
// the callers that must enumerate what a graft holds rather than ask about
// one identity: publish's dedup exclusion, and a deep fsck.
func (ix *Index) KeyAt(i int) []byte {
	k, _ := ix.table.At(i)
	return k
}
