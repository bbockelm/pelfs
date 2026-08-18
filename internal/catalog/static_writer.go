package catalog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// StaticWriter builds a catalog in the packed format. Records are
// collected in memory and serialized once at Finish, because a catalog is
// bounded by the split (a few MiB) and writing sorted arrays in one pass
// is the whole point: nothing is read back, nothing rebalances.
//
// It accepts records in any order and sorts at the end, so callers keep
// walking the tree in whatever order suits them.
type StaticWriter struct {
	meta Meta

	nodes     []Node
	edges     []staticEdge
	chunks    []staticChunk
	inline    []staticBlobRec
	symlinks  []staticBlobRec
	xattrs    []staticXattr
	nested    []staticNested
	rootInode int64
	inlineMax uint32

	err error
}

type staticEdge struct {
	parent, inode int64
	name          []byte
	typ           uint8
}

type staticChunk struct {
	inode    int64
	idx      uint32
	identity []byte
	llen     uint32
	clen     uint32
	alg      uint8
	keyID    uint32
}

type staticBlobRec struct {
	inode int64
	data  []byte
}

type staticXattr struct {
	inode       int64
	name, value []byte
}

type staticNested struct {
	parent   int64
	name     []byte
	identity []byte
}

// NewStaticWriter starts a catalog. RootInode and InlineMax are recorded
// in the header for readers that want them without an arena hop.
func NewStaticWriter(meta Meta, rootInode int64, inlineMax int64) *StaticWriter {
	return &StaticWriter{meta: meta, rootInode: rootInode, inlineMax: uint32(inlineMax)}
}

func (w *StaticWriter) AddNode(n Node) error {
	w.nodes = append(w.nodes, n)
	return nil
}

func (w *StaticWriter) AddEdge(parent int64, name []byte, inode int64, typ uint8) error {
	w.edges = append(w.edges, staticEdge{parent: parent, inode: inode, name: clone(name), typ: typ})
	return nil
}

func (w *StaticWriter) AddNested(parent int64, name, catalogIdentity []byte) error {
	if len(catalogIdentity) != identityLen {
		return fmt.Errorf("catalog: nested identity is %d bytes, want %d", len(catalogIdentity), identityLen)
	}
	w.nested = append(w.nested, staticNested{parent: parent, name: clone(name), identity: clone(catalogIdentity)})
	return nil
}

// AddChunks records one file's content. The index is positional, which
// is what the reader scans in; LogicalOffset is not stored because it is
// the running sum of the lengths before it.
func (w *StaticWriter) AddChunks(inode int64, refs []ChunkRef) error {
	for i, r := range refs {
		if len(r.Identity) != identityLen {
			return fmt.Errorf("catalog: chunk identity is %d bytes, want %d", len(r.Identity), identityLen)
		}
		// A chunk is bounded by the chunker's maximum, far below 4 GiB.
		// Refuse rather than truncate: a silently wrong length would be
		// indistinguishable from corruption at read time.
		if r.LLen < 0 || r.LLen > 0xffffffff || r.CLen < 0 || r.CLen > 0xffffffff {
			return fmt.Errorf("catalog: chunk length out of range (llen %d, clen %d)", r.LLen, r.CLen)
		}
		if r.Alg < 0 || r.Alg > 0xff || r.KeyID < 0 || r.KeyID > 0xffffffff {
			return fmt.Errorf("catalog: chunk alg %d or key %d out of range", r.Alg, r.KeyID)
		}
		w.chunks = append(w.chunks, staticChunk{
			inode: inode, idx: uint32(i), identity: clone(r.Identity),
			llen: uint32(r.LLen), clen: uint32(r.CLen),
			alg: uint8(r.Alg), keyID: uint32(r.KeyID),
		})
	}
	return nil
}

func (w *StaticWriter) SetInline(inode int64, data []byte) error {
	w.inline = append(w.inline, staticBlobRec{inode: inode, data: clone(data)})
	return nil
}

func (w *StaticWriter) SetSymlink(inode int64, target []byte) error {
	w.symlinks = append(w.symlinks, staticBlobRec{inode: inode, data: clone(target)})
	return nil
}

func (w *StaticWriter) AddXattr(inode int64, name, value []byte) error {
	w.xattrs = append(w.xattrs, staticXattr{inode: inode, name: clone(name), value: clone(value)})
	return nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// arena accumulates variable-length bytes and hands back offsets,
// collapsing repeats. Deduplication is deterministic because callers
// append in sorted record order, so the same input always produces the
// same arena.
type arena struct {
	buf []byte
	at  map[string]uint32
}

func newArena() *arena { return &arena{at: make(map[string]uint32)} }

func (a *arena) add(b []byte) (off uint32, ln uint32, err error) {
	if len(b) == 0 {
		return 0, 0, nil
	}
	if off, ok := a.at[string(b)]; ok {
		return off, uint32(len(b)), nil
	}
	if len(a.buf) > 0xffffffff-len(b) {
		return 0, 0, fmt.Errorf("%w: arena exceeds 4 GiB", errCorrupt)
	}
	off = uint32(len(a.buf))
	a.buf = append(a.buf, b...)
	a.at[string(b)] = off
	return off, uint32(len(b)), nil
}

// Finish serializes the catalog. The output is a pure function of the
// records added: sort orders are total, arenas are filled in sorted
// order, and every reserved byte is zero. Two builds of the same tree
// must produce identical bytes or content addressing stops deduplicating.
func (w *StaticWriter) Finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}

	sort.Slice(w.nodes, func(i, j int) bool { return w.nodes[i].Inode < w.nodes[j].Inode })
	sort.Slice(w.edges, func(i, j int) bool {
		if w.edges[i].parent != w.edges[j].parent {
			return w.edges[i].parent < w.edges[j].parent
		}
		return bytes.Compare(w.edges[i].name, w.edges[j].name) < 0
	})
	sort.Slice(w.chunks, func(i, j int) bool {
		if w.chunks[i].inode != w.chunks[j].inode {
			return w.chunks[i].inode < w.chunks[j].inode
		}
		return w.chunks[i].idx < w.chunks[j].idx
	})
	sort.Slice(w.inline, func(i, j int) bool { return w.inline[i].inode < w.inline[j].inode })
	sort.Slice(w.symlinks, func(i, j int) bool { return w.symlinks[i].inode < w.symlinks[j].inode })
	sort.Slice(w.xattrs, func(i, j int) bool {
		if w.xattrs[i].inode != w.xattrs[j].inode {
			return w.xattrs[i].inode < w.xattrs[j].inode
		}
		return bytes.Compare(w.xattrs[i].name, w.xattrs[j].name) < 0
	})
	sort.Slice(w.nested, func(i, j int) bool {
		if w.nested[i].parent != w.nested[j].parent {
			return w.nested[i].parent < w.nested[j].parent
		}
		return bytes.Compare(w.nested[i].name, w.nested[j].name) < 0
	})

	// An edge carries an index into the node array so listing a directory
	// with attributes is a scan plus direct indexing rather than a search
	// per entry — the join, removed.
	nodeIdx := make(map[int64]uint32, len(w.nodes))
	for i := range w.nodes {
		nodeIdx[w.nodes[i].Inode] = uint32(i)
	}

	names := newArena()
	blobs := newArena()
	idents := newIdentityTable()

	edges := make([]byte, len(w.edges)*edgeLen)
	for i, e := range w.edges {
		off, ln, err := names.add(e.name)
		if err != nil {
			return nil, err
		}
		if ln > 0xffff {
			return nil, fmt.Errorf("catalog: name of %d bytes exceeds the record's limit", ln)
		}
		idx, ok := nodeIdx[e.inode]
		if !ok {
			return nil, fmt.Errorf("catalog: edge %q names inode %d, which has no node record", e.name, e.inode)
		}
		r := edges[i*edgeLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(e.parent))
		binary.LittleEndian.PutUint64(r[8:], uint64(e.inode))
		binary.LittleEndian.PutUint32(r[16:], off)
		binary.LittleEndian.PutUint16(r[20:], uint16(ln))
		r[22] = e.typ
		binary.LittleEndian.PutUint32(r[24:], idx)
	}

	nodes := make([]byte, len(w.nodes)*nodeLen)
	for i, n := range w.nodes {
		if n.KeyID < 0 || n.KeyID > 0xffffffff {
			return nil, fmt.Errorf("catalog: node %d key %d out of range", n.Inode, n.KeyID)
		}
		r := nodes[i*nodeLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(n.Inode))
		binary.LittleEndian.PutUint64(r[8:], uint64(n.MtimeNS))
		binary.LittleEndian.PutUint64(r[16:], uint64(n.CtimeNS))
		binary.LittleEndian.PutUint64(r[24:], uint64(n.Length))
		binary.LittleEndian.PutUint32(r[32:], n.Mode)
		binary.LittleEndian.PutUint32(r[36:], n.UID)
		binary.LittleEndian.PutUint32(r[40:], n.GID)
		binary.LittleEndian.PutUint32(r[44:], n.Nlink)
		binary.LittleEndian.PutUint32(r[48:], n.Rdev)
		binary.LittleEndian.PutUint32(r[52:], uint32(n.KeyID))
		binary.LittleEndian.PutUint32(r[56:], n.Flags)
		r[60] = n.Type
	}

	chunks := make([]byte, len(w.chunks)*chunkLen)
	for i, c := range w.chunks {
		r := chunks[i*chunkLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(c.inode))
		binary.LittleEndian.PutUint32(r[8:], c.idx)
		binary.LittleEndian.PutUint32(r[12:], c.llen)
		binary.LittleEndian.PutUint32(r[16:], c.clen)
		binary.LittleEndian.PutUint32(r[20:], c.keyID)
		r[24] = c.alg
		copy(r[32:64], c.identity)
	}

	inlineRecs, err := blobRecords(w.inline, blobs)
	if err != nil {
		return nil, err
	}
	symlinkRecs, err := blobRecords(w.symlinks, blobs)
	if err != nil {
		return nil, err
	}

	xattrs := make([]byte, len(w.xattrs)*xattrLen)
	for i, x := range w.xattrs {
		noff, nlen, err := names.add(x.name)
		if err != nil {
			return nil, err
		}
		voff, vlen, err := blobs.add(x.value)
		if err != nil {
			return nil, err
		}
		if nlen > 0xffff {
			return nil, fmt.Errorf("catalog: xattr name of %d bytes exceeds the record's limit", nlen)
		}
		r := xattrs[i*xattrLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(x.inode))
		binary.LittleEndian.PutUint32(r[8:], noff)
		binary.LittleEndian.PutUint16(r[12:], uint16(nlen))
		binary.LittleEndian.PutUint32(r[16:], voff)
		binary.LittleEndian.PutUint32(r[20:], vlen)
	}

	nested := make([]byte, len(w.nested)*nestedLen)
	for i, n := range w.nested {
		noff, nlen, err := names.add(n.name)
		if err != nil {
			return nil, err
		}
		if nlen > 0xffff {
			return nil, fmt.Errorf("catalog: nested name of %d bytes exceeds the record's limit", nlen)
		}
		r := nested[i*nestedLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(n.parent))
		binary.LittleEndian.PutUint32(r[8:], noff)
		binary.LittleEndian.PutUint16(r[12:], uint16(nlen))
		binary.LittleEndian.PutUint32(r[16:], idents.add(n.identity))
	}

	// Metadata strings live in the blob arena; the section holds three
	// (offset, length) pairs. The GENERATION is deliberately absent: it
	// varies between otherwise identical builds, so stamping it into the
	// catalog — as the SQLite encoding's catalog_meta does — gives an
	// unchanged subtree a new identity every seal and defeats reuse.
	metaSec := make([]byte, metaLen)
	if err := putMetaString(metaSec[0:], blobs, w.meta.VolumeUUID); err != nil {
		return nil, err
	}
	if err := putMetaString(metaSec[8:], blobs, w.meta.CoveredPath); err != nil {
		return nil, err
	}
	if err := putMetaString(metaSec[16:], blobs, w.meta.IdentityAlgo); err != nil {
		return nil, err
	}

	var flags uint64
	if len(w.xattrs) > 0 {
		flags |= headerFlagAnyXattr
	}

	body := []struct {
		id   uint32
		data []byte
	}{
		{secNames, names.buf},
		{secEdges, edges},
		{secNodes, nodes},
		{secChunks, chunks},
		{secInline, inlineRecs},
		{secXattrs, xattrs},
		{secSymlinks, symlinkRecs},
		{secNested, nested},
		{secIdentities, idents.buf},
		{secBlobs, blobs.buf},
		{secMeta, metaSec},
	}
	// Empty sections are omitted rather than recorded at length zero:
	// fewer table entries, and a reader treats "absent" and "empty" the
	// same way.
	type placed struct {
		id       uint32
		data     []byte
		off, len uint64
	}
	var secs []placed
	off := uint64(staticHeaderLen)
	for _, s := range body {
		if len(s.data) == 0 {
			continue
		}
		secs = append(secs, placed{id: s.id, data: s.data})
	}
	off += uint64(len(secs)) * sectionEntryLen
	for i := range secs {
		off = align8(off)
		secs[i].off = off
		secs[i].len = uint64(len(secs[i].data))
		off += secs[i].len
	}

	out := make([]byte, off)
	h := staticHeader{
		Major: FormatMajor, Minor: FormatMinor,
		HeaderLen: staticHeaderLen, SectionCount: uint16(len(secs)),
		Flags: flags, RootInode: uint64(w.rootInode),
		EntryCount: uint64(len(w.edges)), NodeCount: uint64(len(w.nodes)),
		IdentityAlgo: identityAlgoCode(w.meta.IdentityAlgo), InlineMax: w.inlineMax,
	}
	h.encode(out)
	for i, s := range secs {
		e := out[staticHeaderLen+i*sectionEntryLen:]
		binary.LittleEndian.PutUint32(e[0:], s.id)
		binary.LittleEndian.PutUint64(e[8:], s.off)
		binary.LittleEndian.PutUint64(e[16:], s.len)
		copy(out[s.off:s.off+s.len], s.data)
	}
	return out, nil
}

func blobRecords(recs []staticBlobRec, blobs *arena) ([]byte, error) {
	out := make([]byte, len(recs)*inlineLen)
	for i, rec := range recs {
		off, ln, err := blobs.add(rec.data)
		if err != nil {
			return nil, err
		}
		r := out[i*inlineLen:]
		binary.LittleEndian.PutUint64(r[0:], uint64(rec.inode))
		binary.LittleEndian.PutUint32(r[8:], off)
		binary.LittleEndian.PutUint32(r[12:], ln)
	}
	return out, nil
}

func putMetaString(dst []byte, blobs *arena, s string) error {
	off, ln, err := blobs.add([]byte(s))
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(dst[0:], off)
	binary.LittleEndian.PutUint32(dst[4:], ln)
	return nil
}

// identityTable stores 32-byte identities once each and hands back
// indices, which is what a nested record carries.
type identityTable struct {
	buf []byte
	at  map[string]uint32
}

func newIdentityTable() *identityTable {
	return &identityTable{at: make(map[string]uint32)}
}

func (t *identityTable) add(id []byte) uint32 {
	if idx, ok := t.at[string(id)]; ok {
		return idx
	}
	idx := uint32(len(t.buf) / identityLen)
	t.buf = append(t.buf, id...)
	t.at[string(id)] = idx
	return idx
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }
