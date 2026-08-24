// Package graft implements external subtrees: a path inside a pelfs
// volume whose bytes stay at a foreign Pelican prefix and are served by
// ranged reads, with no copy under the volume's own prefix
// (docs/design-graft.md).
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
//
// # The index is a HINT, and that is why it may be read windowed
//
// The spike's Fetch said verifying the index against the superblock's
// hash was "the whole reason a graft can be trusted at all". That is an
// overstatement, and correcting it is what unblocks a 10 TB graft.
//
// What an index produces is a LOCATION. The bytes that come back from
// that location are then hashed and compared against the identity the
// SIGNED CATALOG names (genfs.readGraftChunk, unconditionally). So a
// substituted, corrupted or truncated index can send a reader to the
// wrong object, to no object, or to the wrong offset — every one of which
// ends in a failed read, and none of which can end in an accepted byte.
// The index is exactly as trusted as a multi-pack index is, and for
// exactly the same reason internal/mpi gives (remote.go, "THE INTEGRITY
// STORY").
//
// That is what licenses the windowed reader in remote.go: an index too
// large to fetch whole is read header-plus-window per lookup, with no
// whole-object digest, and nothing about the fail-closed guarantee moves.
// A small index is still fetched whole and still checked, because at that
// size the check is free and one round trip beats one per lookup.
//
// # Layout (version 2)
//
//	[  0: 8) magic
//	[  8:12) version
//	[ 12:16) object count
//	[ 16:24) base block size
//	[ 24:32) length of the object-key string table
//	[ 32:32+strLen) NUL-terminated source object keys
//	[32+strLen: ) a packidx table: identity -> {object index, offset, length}
//
// The string table moved AHEAD of the searchable table in version 2, and
// the move is what makes one ranged request enough to start answering
// lookups: a reader needs the whole string table resident (a record names
// an object by index) and it needs the packidx header and samples, and
// only this order puts all three in a prefix. It is the layout
// internal/mpi already uses, for the same reason.
//
// What stays resident is bounded by the number of source OBJECTS, never
// by the number of blocks: 100,000 objects with 60-character keys is a
// 6 MB string table whether the graft is 10 GB or 10 TB.
package graft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/extsort"
	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"

	"lukechampine.com/blake3"
)

const (
	magic = "PELFSGR1"
	// Version is the index layout this build writes. Version 1 (the
	// spike's) put the string table last, which no prefix can reach, and
	// is refused rather than read: nothing has published one that was not
	// republishable in seconds.
	Version = 2
	// keyLen is a chunk identity.
	keyLen = chunkid.IdentitySize
	// recordLen is {object index, offset, length}: which object in the
	// string table, where in it, and how long. The LENGTH IS PER BLOCK,
	// which is what lets one graft cut different objects at different
	// block sizes without any format change (blocks.go).
	recordLen = 4 + 8 + 4
	// headerLen is 8-byte aligned like the tables it carries.
	headerLen = 32
	// Dir is the key-space directory holding graft index objects, under
	// the VOLUME's prefix. The index is the volume's own metadata about a
	// foreign tree, so it lives with the volume and not with the source —
	// which is also what makes it immutable and signature-covered while
	// the source is neither.
	Dir = "grafts"
	// Stride is how many records one sample covers, and it is a quarter
	// of packidx.DefaultStride on purpose. A graft entry is 48 bytes
	// (32-byte identity, 16-byte record) where a multi-pack entry is 16,
	// so the default stride would make every lookup a 196 KB window.
	// 1024 records is a 48 KB window, and the samples it costs are
	// count/1024 identities — 328 KB for the 10.5 million blocks of a
	// 10 TB graft, held once for the life of the mount.
	Stride = 1024
)

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

// Block is one digested block: what it hashes to and where it lives.
type Block struct {
	ID  chunkid.Identity
	Loc Loc
}

// Writer accumulates the identity -> Loc table for one graft WITHOUT
// holding it.
//
// The spike held every record in a packidx.Builder and every identity in
// a dedup set: about 150 bytes a block, so ~1.5 GB of resident memory for
// a 10 TB graft before the object was even encoded. That is the wrong
// shape for the size of tree this feature exists to serve.
//
// Records go to internal/extsort instead — the same external sort the
// seal path already uses for exactly this problem — and come back in key
// order to a packidx.StreamWriter, which keeps only the samples. Memory
// is then the extsort budget plus the string table, both independent of
// how many blocks there are.
//
// Add is safe for concurrent callers, because the spider that feeds it is
// concurrent (spider.go).
type Writer struct {
	dir       string
	sorter    *extsort.Sorter
	blockBase int64

	mu    sync.Mutex
	keys  []string
	keyID map[string]uint32
	added int64
}

// NewWriter starts an index. spoolDir must exist and is where the sort
// runs and the encode spool live; the caller owns removing it.
func NewWriter(spoolDir string, blockBase int64) (*Writer, error) {
	if blockBase <= 0 {
		blockBase = DefaultBlock
	}
	if spoolDir == "" {
		return nil, errors.New("graft: an index writer needs a spool directory")
	}
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return nil, fmt.Errorf("graft: index spool: %w", err)
	}
	return &Writer{
		dir:       spoolDir,
		sorter:    extsort.New(spoolDir, "graftidx", keyLen, keyLen+recordLen, 0),
		blockBase: blockBase,
		keyID:     make(map[string]uint32),
	}, nil
}

// Add records one batch of blocks, which is how the spider hands over a
// whole ranged read's worth at once: the lock is taken per REQUEST, not
// per block.
//
// A repeated identity is kept rather than filtered. The sort collapses
// runs of equal keys at encode time, so the same bytes in two places
// still cost one record in the finished table — and filtering here would
// need the identity set the whole design just stopped holding.
//
// The ORDER of the calls does not reach the encoded object: Encode sorts
// the string table and picks the surviving location by rule, so a walk
// that finished its spans in a different order still writes the same
// bytes.
func (w *Writer) Add(bs []Block) error {
	if len(bs) == 0 {
		return nil
	}
	recs := make([]byte, 0, len(bs)*(keyLen+recordLen))
	w.mu.Lock()
	for _, b := range bs {
		oi, ok := w.keyID[b.Loc.Key]
		if !ok {
			oi = uint32(len(w.keys))
			w.keys = append(w.keys, b.Loc.Key)
			w.keyID[b.Loc.Key] = oi
		}
		var v [keyLen + recordLen]byte
		copy(v[0:], b.ID[:])
		binary.LittleEndian.PutUint32(v[keyLen+0:], oi)
		binary.LittleEndian.PutUint64(v[keyLen+4:], uint64(b.Loc.Off))
		binary.LittleEndian.PutUint32(v[keyLen+12:], uint32(b.Loc.Length))
		recs = append(recs, v[:]...)
	}
	w.added += int64(len(bs))
	w.mu.Unlock()
	return w.sorter.Add(recs)
}

// Added is how many blocks have been handed over, duplicates included.
// The DISTINCT count is only known once the sort has run, and Encode
// reports it.
func (w *Writer) Added() int64 { return w.added }

// Objects is how many distinct source objects the index names.
func (w *Writer) Objects() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.keys)
}

// Block is the base block size the spider cut with.
func (w *Writer) Block() int64 { return w.blockBase }

// Close drops the sort runs.
func (w *Writer) Close() error { return w.sorter.Close() }

// Encode writes the finished index object to out and reports how many
// DISTINCT blocks it holds.
//
// Nothing larger than one record is held: the sort streams, the stream
// writer spools, and the string table is bounded by the object count.
//
// The bytes it writes are a FUNCTION OF THE SOURCE AND THE POLICY, and
// nothing else — see the canonical ordering below. A hash-named object
// that varied run to run would make `--refresh` of an unchanged tree
// upload a new index and rewrite the superblock entry every time.
func (w *Writer) Encode(out io.Writer) (blocks int, err error) {
	w.mu.Lock()
	keys := append([]string(nil), w.keys...)
	w.mu.Unlock()

	// CANONICAL ORDER FOR THE STRING TABLE.
	//
	// A record names its object by an index into this table, and the
	// table was built in the order Add happened to be called — which is
	// the order concurrent spider workers finished their spans in
	// (spider.go), and is therefore different on every walk of the same
	// tree. That leaked the scheduler into the encoded object: two walks
	// of an unchanged source produced two differently-hashed indexes.
	//
	// Sorting it here and remapping the records through the permutation
	// is the fix, and this is the only place that sees the whole table.
	// The permutation costs one uint32 per OBJECT, which is the bound the
	// string table itself already carries — never the block count.
	order := make([]uint32, len(keys))
	for i := range order {
		order[i] = uint32(i)
	}
	sort.Slice(order, func(a, b int) bool { return keys[order[a]] < keys[order[b]] })
	remap := make([]uint32, len(keys))
	canon := make([]string, len(keys))
	for newID, oldID := range order {
		remap[oldID] = uint32(newID)
		canon[newID] = keys[oldID]
	}
	keys = canon

	var strs []byte
	for _, k := range keys {
		if strings.IndexByte(k, 0) >= 0 {
			return 0, fmt.Errorf("graft: source object key %q contains a NUL", k)
		}
		strs = append(strs, k...)
		strs = append(strs, 0)
	}
	head := make([]byte, headerLen)
	copy(head[0:8], magic)
	binary.LittleEndian.PutUint32(head[8:], Version)
	binary.LittleEndian.PutUint32(head[12:], uint32(len(keys)))
	binary.LittleEndian.PutUint64(head[16:], uint64(w.blockBase))
	binary.LittleEndian.PutUint64(head[24:], uint64(len(strs)))
	if _, err := out.Write(head); err != nil {
		return 0, err
	}
	if _, err := out.Write(strs); err != nil {
		return 0, err
	}

	spool, err := os.CreateTemp(w.dir, "graftidx-encode-*")
	if err != nil {
		return 0, fmt.Errorf("graft: index spool: %w", err)
	}
	defer func() {
		spool.Close()           //nolint:errcheck
		os.Remove(spool.Name()) //nolint:errcheck
	}()

	merged, err := w.sorter.Sorted()
	if err != nil {
		return 0, fmt.Errorf("graft: sort index: %w", err)
	}
	defer merged.Close() //nolint:errcheck

	sw := packidx.NewStreamWriter(spool, keyLen, recordLen, Stride)
	var (
		cur  [keyLen]byte
		best [recordLen]byte
		have bool
	)
	n := 0
	emit := func() error {
		if !have {
			return nil
		}
		if err := sw.Add(cur[:], best[:]); err != nil {
			return fmt.Errorf("graft: encode index: %w", err)
		}
		n++
		return nil
	}
	for {
		rec, ok := merged.Next()
		if !ok {
			break
		}
		var val [recordLen]byte
		copy(val[:], rec[keyLen:])
		oi := binary.LittleEndian.Uint32(val[0:])
		if int(oi) >= len(remap) {
			return 0, fmt.Errorf("graft: an index record names source object %d of %d", oi, len(remap))
		}
		binary.LittleEndian.PutUint32(val[0:], remap[oi])
		// A streaming table cannot reorder and will not accept a repeat,
		// so runs of equal identities — the same bytes in two places —
		// collapse HERE. The survivor is the LOWEST location rather than
		// whichever the sort happened to put in front, for the same
		// reason the string table is sorted: the sort's order among equal
		// keys follows the order Add was called in, which is the walk's
		// schedule. Either location serves the same bytes, so the only
		// thing at stake is that the choice be a property of the tree.
		// One record is held, never a run: a tree of identical blocks
		// must not be able to make this allocate.
		if have && string(rec[:keyLen]) == string(cur[:]) {
			if lowerLoc(val, best) {
				best = val
			}
			continue
		}
		if err := emit(); err != nil {
			return 0, err
		}
		copy(cur[:], rec[:keyLen])
		best, have = val, true
	}
	if err := merged.Err(); err != nil {
		return 0, fmt.Errorf("graft: sort index: %w", err)
	}
	if err := emit(); err != nil {
		return 0, err
	}
	if _, err := sw.Finish(out); err != nil {
		return 0, fmt.Errorf("graft: encode index: %w", err)
	}
	return n, nil
}

// IndexKey is where an index object of the given hash lives under the
// volume prefix. Hash-named, like every other derived object.
func IndexKey(h [32]byte) string {
	return Dir + "/" + fmt.Sprintf("%x", h)
}

// PublishOptions is what the superblock entry has to say beyond the table
// itself.
type PublishOptions struct {
	// Mount is where the tree lands in the volume, Source the foreign
	// prefix its bytes come from.
	Mount, Source string
	// Policy is the block-size rule this index was cut with, recorded so
	// a refresh reproduces the same cut. A different rule moves every
	// identity, which is a whole new graft rather than a refresh.
	Policy BlockPolicy
	// Bytes is the logical size of the grafted tree and Files how many
	// files it holds — reportable facts that cost nothing to record and
	// an index fetch to recompute.
	Bytes int64
	Files int
}

// Publish encodes the index, uploads it, and returns the superblock entry
// naming it.
//
// The object is built in a temp file rather than in memory: at the sizes
// this is for (505 MB for a 10 TB graft at 1 MiB blocks) the buffer would
// be the largest allocation in the process. Immutable and hash-named, so
// an upload is idempotent and an interrupted one costs nothing — the
// retention grace window covers an orphan.
func (w *Writer) Publish(ctx context.Context, obj pelicanobj.Store, o PublishOptions) (superblock.GraftEntry, error) {
	f, err := os.CreateTemp(w.dir, "graftidx-object-*")
	if err != nil {
		return superblock.GraftEntry{}, fmt.Errorf("graft: index object: %w", err)
	}
	defer func() {
		f.Close()           //nolint:errcheck
		os.Remove(f.Name()) //nolint:errcheck
	}()
	h := blake3.New(32, nil)
	blocks, err := w.Encode(io.MultiWriter(f, h))
	if err != nil {
		return superblock.GraftEntry{}, err
	}
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return superblock.GraftEntry{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return superblock.GraftEntry{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if err := obj.Put(ctx, IndexKey(sum), f); err != nil {
		return superblock.GraftEntry{}, fmt.Errorf("graft: upload index: %w", err)
	}
	p := o.Policy.withDefaults()
	return superblock.GraftEntry{
		Path:            o.Mount,
		Source:          o.Source,
		Index:           sum,
		Size:            size,
		Block:           p.Block,
		BlockMax:        p.Max,
		BlocksPerObject: uint32(p.PerObject),
		Blocks:          uint64(blocks),
		Bytes:           o.Bytes,
		Files:           uint64(o.Files),
		Objects:         uint64(w.Objects()),
	}, nil
}

// Index is a decoded graft index held whole, which is what a small one
// wants: one round trip, the whole-object hash checked, and every lookup
// afterwards free. remote.Reader decides which mode applies.
type Index struct {
	table     *packidx.Table
	keys      []string
	blockBase int64
}

// Open decodes an index object.
func Open(b []byte) (*Index, error) {
	keys, tbl, blockBase, err := parsePrefix(b, int64(len(b)), "graft index")
	if err != nil {
		return nil, err
	}
	t, err := packidx.Open(b[tbl:])
	if err != nil {
		return nil, fmt.Errorf("graft: %w", err)
	}
	return &Index{table: t, keys: keys, blockBase: blockBase}, nil
}

// parsePrefix reads the header and the string table out of a prefix of an
// index object, and reports where the searchable table starts.
//
// size is the object's SIGNED length, and it is the only bound available
// before anything is allocated — every length off the wire is held
// against it, exactly as mpi.Reader holds them against ref.Size.
func parsePrefix(b []byte, size int64, name string) (keys []string, tbl int64, blockBase int64, err error) {
	if len(b) < headerLen || string(b[0:8]) != magic {
		return nil, 0, 0, fmt.Errorf("%w: %s", ErrFormat, name)
	}
	switch v := binary.LittleEndian.Uint32(b[8:]); v {
	case Version:
	case 1:
		return nil, 0, 0, fmt.Errorf("%w: %s is a version 1 index, whose string table cannot be "+
			"read from a prefix; republish the graft with this build", ErrFormat, name)
	default:
		return nil, 0, 0, fmt.Errorf("%w: %s is version %d", ErrFormat, name, v)
	}
	nkeys := int(binary.LittleEndian.Uint32(b[12:]))
	blockBase = int64(binary.LittleEndian.Uint64(b[16:]))
	strLen := int64(binary.LittleEndian.Uint64(b[24:]))
	if strLen < 0 || headerLen+strLen > size {
		return nil, 0, 0, fmt.Errorf("%w: %s claims %d bytes of object keys in a %d-byte object",
			ErrFormat, name, strLen, size)
	}
	if int64(len(b)) < headerLen+strLen {
		return nil, 0, 0, fmt.Errorf("%w: %s needs %d bytes of prefix, has %d",
			ErrFormat, name, headerLen+strLen, len(b))
	}
	keys = splitKeys(b[headerLen : headerLen+strLen])
	if len(keys) != nkeys {
		return nil, 0, 0, fmt.Errorf("%w: %s says %d objects, the string table holds %d",
			ErrFormat, name, nkeys, len(keys))
	}
	return keys, headerLen + strLen, blockBase, nil
}

// splitKeys reads the NUL-terminated object keys.
func splitKeys(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	// Split leaves a trailing empty element after the last terminator.
	if n := len(parts); n > 0 && parts[n-1] == "" {
		parts = parts[:n-1]
	}
	return parts
}

// lowerLoc orders two encoded records by the location they name: which
// object in the (already canonical) string table, then where in it. The
// fields are little-endian, so this compares them rather than the bytes.
// Any total order would make the encode deterministic; this one makes the
// surviving location the one in the alphabetically first source object,
// which is also the one a person reading the index would expect.
func lowerLoc(a, b [recordLen]byte) bool {
	ao, bo := binary.LittleEndian.Uint32(a[0:]), binary.LittleEndian.Uint32(b[0:])
	if ao != bo {
		return ao < bo
	}
	af, bf := binary.LittleEndian.Uint64(a[4:]), binary.LittleEndian.Uint64(b[4:])
	if af != bf {
		return af < bf
	}
	return binary.LittleEndian.Uint32(a[12:]) < binary.LittleEndian.Uint32(b[12:])
}

// decodeRecord turns a table value into a Loc.
func decodeRecord(keys []string, v []byte) (Loc, bool) {
	if len(v) < recordLen {
		return Loc{}, false
	}
	oi := binary.LittleEndian.Uint32(v[0:])
	if int(oi) >= len(keys) {
		return Loc{}, false
	}
	return Loc{
		Key:    keys[oi],
		Off:    int64(binary.LittleEndian.Uint64(v[4:])),
		Length: int64(binary.LittleEndian.Uint32(v[12:])),
	}, true
}

// Lookup resolves one identity.
func (ix *Index) Lookup(id []byte) (Loc, bool) {
	v, ok := ix.table.Lookup(id)
	if !ok {
		return Loc{}, false
	}
	return decodeRecord(ix.keys, v)
}

// Len is how many blocks the index covers; Block the base size it cut
// with (blocks.go: individual objects may be cut coarser).
func (ix *Index) Len() int     { return ix.table.Len() }
func (ix *Index) Block() int64 { return ix.blockBase }

// Objects lists every source object the index locates blocks in, sorted.
// fsck's cheap mode stats exactly these, and the list comes out of the
// string table rather than out of the records — so it costs nothing at
// any index size.
func (ix *Index) Objects() []string {
	out := append([]string(nil), ix.keys...)
	sort.Strings(out)
	return out
}

// spoolPath is where a caller's temp artifacts for one graft live.
func spoolPath(stateDir, name string) string { return filepath.Join(stateDir, "graft", name) }
