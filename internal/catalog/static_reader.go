package catalog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Static reads a catalog in the packed format. It holds the blob and
// slices of it — no parsing at open beyond structural validation, no
// allocation on a lookup, and no locks, so reads scale with cores
// instead of serializing behind an allocator.
type Static struct {
	buf []byte

	names, blobs       []byte
	edges, nodes       []byte
	chunks, xattrs     []byte
	inline, symlinks   []byte
	nested, identities []byte
	metaRaw            []byte
	meta               Meta
	header             staticHeader
}

// OpenStatic validates a catalog blob's structure and returns a reader
// over it. The blob is retained, not copied: it is expected to be mapped.
//
// Validation is deliberately partial. Structure — magic, version, the
// section table, whole records — is checked once here, and every arena
// reference is bounds-checked at access. SORT ORDER IS NOT CHECKED: it is
// O(n) over the whole catalog, which would undo the reason this format
// exists. An out-of-order catalog returns wrong answers, never unsafe
// reads, and fsck checks order where an O(n) pass belongs.
func OpenStatic(buf []byte) (*Static, error) {
	h, err := decodeHeader(buf)
	if err != nil {
		return nil, err
	}
	s := &Static{buf: buf, header: h}

	tableEnd := uint64(h.HeaderLen) + uint64(h.SectionCount)*sectionEntryLen
	if tableEnd > uint64(len(buf)) {
		return nil, fmt.Errorf("%w: section table runs past the blob", errCorrupt)
	}
	for i := 0; i < int(h.SectionCount); i++ {
		e := buf[uint64(h.HeaderLen)+uint64(i)*sectionEntryLen:]
		sec := section{
			ID:  binary.LittleEndian.Uint32(e[0:]),
			Off: binary.LittleEndian.Uint64(e[8:]),
			Len: binary.LittleEndian.Uint64(e[16:]),
		}
		if sec.Off%8 != 0 {
			return nil, fmt.Errorf("%w: section %d is not aligned", errCorrupt, sec.ID)
		}
		if sec.Off > uint64(len(buf)) || sec.Len > uint64(len(buf))-sec.Off {
			return nil, fmt.Errorf("%w: section %d runs past the blob", errCorrupt, sec.ID)
		}
		data := buf[sec.Off : sec.Off+sec.Len]
		if err := s.attach(sec.ID, data); err != nil {
			return nil, err
		}
	}
	if err := s.loadMeta(); err != nil {
		return nil, err
	}
	return s, nil
}

// attach records a section, refusing a record array that is not a whole
// number of records. An unknown id is SKIPPED, which is what lets a
// future minor version add sections this build has never heard of.
func (s *Static) attach(id uint32, data []byte) error {
	whole := func(width int) error {
		if len(data)%width != 0 {
			return fmt.Errorf("%w: section %d is %d bytes, not a multiple of %d", errCorrupt, id, len(data), width)
		}
		return nil
	}
	switch id {
	case secNames:
		s.names = data
	case secBlobs:
		s.blobs = data
	case secEdges:
		if err := whole(edgeLen); err != nil {
			return err
		}
		s.edges = data
	case secNodes:
		if err := whole(nodeLen); err != nil {
			return err
		}
		s.nodes = data
	case secChunks:
		if err := whole(chunkLen); err != nil {
			return err
		}
		s.chunks = data
	case secInline:
		if err := whole(inlineLen); err != nil {
			return err
		}
		s.inline = data
	case secXattrs:
		if err := whole(xattrLen); err != nil {
			return err
		}
		s.xattrs = data
	case secSymlinks:
		if err := whole(symlinkLen); err != nil {
			return err
		}
		s.symlinks = data
	case secNested:
		if err := whole(nestedLen); err != nil {
			return err
		}
		s.nested = data
	case secIdentities:
		if err := whole(identityLen); err != nil {
			return err
		}
		s.identities = data
	case secMeta:
		if len(data) < metaLen {
			return fmt.Errorf("%w: meta section is %d bytes", errCorrupt, len(data))
		}
		// Filled by loadMeta once the blob arena is known: sections may
		// arrive in any order, so the strings cannot be resolved here.
		s.metaRaw = data
	}
	return nil
}

func (s *Static) loadMeta() error {
	if s.metaRaw == nil {
		return nil
	}
	get := func(off int) (string, error) {
		o := binary.LittleEndian.Uint32(s.metaRaw[off:])
		l := binary.LittleEndian.Uint32(s.metaRaw[off+4:])
		b, ok := s.blobAt(o, l)
		if !ok {
			return "", fmt.Errorf("%w: meta string [%d,+%d) is outside the blob arena", errCorrupt, o, l)
		}
		return string(b), nil
	}
	var err error
	if s.meta.VolumeUUID, err = get(0); err != nil {
		return err
	}
	if s.meta.CoveredPath, err = get(8); err != nil {
		return err
	}
	if s.meta.IdentityAlgo, err = get(16); err != nil {
		return err
	}
	return nil
}

// nameAt and blobAt are the only ways into the arenas, so the bounds
// check lives in one place. It is a compare against a length already in
// hand — cheap enough that trusting the offsets instead would be a bad
// trade against a corrupt download.
func (s *Static) nameAt(off, ln uint32) ([]byte, bool) {
	if uint64(off)+uint64(ln) > uint64(len(s.names)) {
		return nil, false
	}
	return s.names[off : off+ln], true
}

func (s *Static) blobAt(off, ln uint32) ([]byte, bool) {
	if uint64(off)+uint64(ln) > uint64(len(s.blobs)) {
		return nil, false
	}
	return s.blobs[off : off+ln], true
}

func (s *Static) edgeAt(i int) []byte { return s.edges[i*edgeLen:] }
func (s *Static) edgeCount() int      { return len(s.edges) / edgeLen }
func (s *Static) edgeParent(i int) int64 {
	return int64(binary.LittleEndian.Uint64(s.edgeAt(i)))
}

func (s *Static) edgeName(i int) ([]byte, bool) {
	r := s.edgeAt(i)
	return s.nameAt(binary.LittleEndian.Uint32(r[16:]), uint32(binary.LittleEndian.Uint16(r[20:])))
}

// lowerBoundEdge finds the first edge at or after (parent, name).
func (s *Static) lowerBoundEdge(parent int64, name []byte) int {
	return sort.Search(s.edgeCount(), func(i int) bool {
		p := s.edgeParent(i)
		if p != parent {
			return p > parent
		}
		if name == nil {
			return true
		}
		n, ok := s.edgeName(i)
		if !ok {
			return true
		}
		return bytes.Compare(n, name) >= 0
	})
}

func (s *Static) Meta() Meta { return s.meta }

func (s *Static) HasXattrs() bool { return s.header.Flags&headerFlagAnyXattr != 0 }

// Lookup resolves one name under parent. A transition point has BOTH
// halves — the dirent whose node lives in this catalog, and the identity
// of the child catalog its contents live in — so both are returned when
// both are present, and a caller that gets a nested identity without a
// dirent is looking at a corrupt catalog.
func (s *Static) Lookup(parent int64, name []byte) (LookupResult, error) {
	var res LookupResult
	i := s.lowerBoundEdge(parent, name)
	if i < s.edgeCount() && s.edgeParent(i) == parent {
		if n, ok := s.edgeName(i); ok && bytes.Equal(n, name) {
			r := s.edgeAt(i)
			res.Dirent = &Dirent{
				Name:  n,
				Inode: int64(binary.LittleEndian.Uint64(r[8:])),
				Type:  r[22],
			}
		}
	}
	if j, ok := s.findNested(parent, name); ok {
		id, ok := s.identityAt(j)
		if !ok {
			return LookupResult{}, fmt.Errorf("%w: nested record names identity %d, which is absent", errCorrupt, j)
		}
		res.NestedIdentity = id
	}
	if res.Dirent == nil && res.NestedIdentity == nil {
		return LookupResult{}, ErrNotExist
	}
	return res, nil
}

func (s *Static) nestedCount() int { return len(s.nested) / nestedLen }

func (s *Static) nestedAt(i int) []byte { return s.nested[i*nestedLen:] }

func (s *Static) nestedName(i int) ([]byte, bool) {
	r := s.nestedAt(i)
	return s.nameAt(binary.LittleEndian.Uint32(r[8:]), uint32(binary.LittleEndian.Uint16(r[12:])))
}

func (s *Static) findNested(parent int64, name []byte) (int, bool) {
	i := sort.Search(s.nestedCount(), func(i int) bool {
		p := int64(binary.LittleEndian.Uint64(s.nestedAt(i)))
		if p != parent {
			return p > parent
		}
		n, ok := s.nestedName(i)
		if !ok {
			return true
		}
		return bytes.Compare(n, name) >= 0
	})
	if i < s.nestedCount() && int64(binary.LittleEndian.Uint64(s.nestedAt(i))) == parent {
		if n, ok := s.nestedName(i); ok && bytes.Equal(n, name) {
			return int(binary.LittleEndian.Uint32(s.nestedAt(i)[16:])), true
		}
	}
	return 0, false
}

func (s *Static) identityAt(idx int) ([]byte, bool) {
	off := idx * identityLen
	if off < 0 || off+identityLen > len(s.identities) {
		return nil, false
	}
	return s.identities[off : off+identityLen], true
}

func (s *Static) Readdir(parent int64) ([]Dirent, []Nested, error) {
	var ents []Dirent
	for i := s.lowerBoundEdge(parent, nil); i < s.edgeCount() && s.edgeParent(i) == parent; i++ {
		n, ok := s.edgeName(i)
		if !ok {
			return nil, nil, fmt.Errorf("%w: edge %d has a name outside the arena", errCorrupt, i)
		}
		r := s.edgeAt(i)
		ents = append(ents, Dirent{Name: n, Inode: int64(binary.LittleEndian.Uint64(r[8:])), Type: r[22]})
	}
	nested, err := s.NestedOf(parent)
	if err != nil {
		return nil, nil, err
	}
	return ents, nested, nil
}

func (s *Static) NestedOf(parent int64) ([]Nested, error) {
	i := sort.Search(s.nestedCount(), func(i int) bool {
		return int64(binary.LittleEndian.Uint64(s.nestedAt(i))) >= parent
	})
	var out []Nested
	for ; i < s.nestedCount() && int64(binary.LittleEndian.Uint64(s.nestedAt(i))) == parent; i++ {
		n, ok := s.nestedName(i)
		if !ok {
			return nil, fmt.Errorf("%w: nested %d has a name outside the arena", errCorrupt, i)
		}
		id, ok := s.identityAt(int(binary.LittleEndian.Uint32(s.nestedAt(i)[16:])))
		if !ok {
			return nil, fmt.Errorf("%w: nested %d names an absent identity", errCorrupt, i)
		}
		out = append(out, Nested{Name: n, CatalogIdentity: id})
	}
	return out, nil
}

func (s *Static) nodeCount() int { return len(s.nodes) / nodeLen }

func (s *Static) nodeRecord(i int) Node {
	r := s.nodes[i*nodeLen:]
	return Node{
		Inode:   int64(binary.LittleEndian.Uint64(r[0:])),
		MtimeNS: int64(binary.LittleEndian.Uint64(r[8:])),
		CtimeNS: int64(binary.LittleEndian.Uint64(r[16:])),
		Length:  int64(binary.LittleEndian.Uint64(r[24:])),
		Mode:    binary.LittleEndian.Uint32(r[32:]),
		UID:     binary.LittleEndian.Uint32(r[36:]),
		GID:     binary.LittleEndian.Uint32(r[40:]),
		Nlink:   binary.LittleEndian.Uint32(r[44:]),
		Rdev:    binary.LittleEndian.Uint32(r[48:]),
		KeyID:   int64(binary.LittleEndian.Uint32(r[52:])),
		Flags:   binary.LittleEndian.Uint32(r[56:]),
		Type:    r[60],
	}
}

func (s *Static) findNode(inode int64) (int, bool) {
	i := sort.Search(s.nodeCount(), func(i int) bool {
		return int64(binary.LittleEndian.Uint64(s.nodes[i*nodeLen:])) >= inode
	})
	if i < s.nodeCount() && int64(binary.LittleEndian.Uint64(s.nodes[i*nodeLen:])) == inode {
		return i, true
	}
	return 0, false
}

func (s *Static) Stat(inode int64) (Node, error) {
	i, ok := s.findNode(inode)
	if !ok {
		return Node{}, ErrNotExist
	}
	return s.nodeRecord(i), nil
}

// ReaddirPlus is a scan plus direct indexing: the edge carries the node's
// position, so the join the SQL form needed does not exist here.
func (s *Static) ReaddirPlus(parent int64) ([]DirentNode, error) {
	var out []DirentNode
	for i := s.lowerBoundEdge(parent, nil); i < s.edgeCount() && s.edgeParent(i) == parent; i++ {
		r := s.edgeAt(i)
		n, ok := s.edgeName(i)
		if !ok {
			return nil, fmt.Errorf("%w: edge %d has a name outside the arena", errCorrupt, i)
		}
		idx := int(binary.LittleEndian.Uint32(r[24:]))
		if idx < 0 || idx >= s.nodeCount() {
			return nil, fmt.Errorf("%w: edge %d indexes node %d of %d", errCorrupt, i, idx, s.nodeCount())
		}
		node := s.nodeRecord(idx)
		if node.Inode != int64(binary.LittleEndian.Uint64(r[8:])) {
			return nil, fmt.Errorf("%w: edge %d indexes a node for a different inode", errCorrupt, i)
		}
		out = append(out, DirentNode{Name: n, Node: node})
	}
	return out, nil
}

func (s *Static) chunkCount() int { return len(s.chunks) / chunkLen }

func (s *Static) Chunks(inode int64) ([]ChunkRef, error) {
	i := sort.Search(s.chunkCount(), func(i int) bool {
		return int64(binary.LittleEndian.Uint64(s.chunks[i*chunkLen:])) >= inode
	})
	var out []ChunkRef
	var logical int64
	for ; i < s.chunkCount() && int64(binary.LittleEndian.Uint64(s.chunks[i*chunkLen:])) == inode; i++ {
		r := s.chunks[i*chunkLen:]
		ref := ChunkRef{
			Identity:      r[32:64],
			LLen:          int64(binary.LittleEndian.Uint32(r[12:])),
			CLen:          int64(binary.LittleEndian.Uint32(r[16:])),
			KeyID:         int64(binary.LittleEndian.Uint32(r[20:])),
			Alg:           int64(r[24]),
			LogicalOffset: logical,
		}
		logical += ref.LLen
		out = append(out, ref)
	}
	if out == nil {
		return nil, nil
	}
	// A file's chunk lengths must account for exactly its length. The
	// check belongs on the read path rather than in fsck because a short
	// read here would silently serve a truncated file.
	n, err := s.Stat(inode)
	if err != nil {
		return nil, fmt.Errorf("catalog: inode %d has chunks but no node row: %w", inode, err)
	}
	if logical != n.Length {
		return nil, fmt.Errorf("catalog: inode %d chunk lengths sum to %d, node length is %d", inode, logical, n.Length)
	}
	return out, nil
}

// blobFor serves the inline and symlink sections, which share a record.
func (s *Static) blobFor(sec []byte, inode int64) ([]byte, bool, error) {
	count := len(sec) / inlineLen
	i := sort.Search(count, func(i int) bool {
		return int64(binary.LittleEndian.Uint64(sec[i*inlineLen:])) >= inode
	})
	if i >= count || int64(binary.LittleEndian.Uint64(sec[i*inlineLen:])) != inode {
		return nil, false, nil
	}
	r := sec[i*inlineLen:]
	b, ok := s.blobAt(binary.LittleEndian.Uint32(r[8:]), binary.LittleEndian.Uint32(r[12:]))
	if !ok {
		return nil, false, fmt.Errorf("%w: inode %d has a blob outside the arena", errCorrupt, inode)
	}
	return b, true, nil
}

// Inline returns nil, nil for an inode with no inline record. That is
// not the same convention as Symlink, which reports ErrNotExist — the two
// contracts differ in the SQLite encoding and callers depend on the
// difference, so this encoding matches them method by method rather than
// imposing a uniformity of its own.
func (s *Static) Inline(inode int64) ([]byte, error) {
	b, ok, err := s.blobFor(s.inline, inode)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return b, nil
}

func (s *Static) Symlink(inode int64) ([]byte, error) {
	b, ok, err := s.blobFor(s.symlinks, inode)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotExist
	}
	return b, nil
}

func (s *Static) Xattrs(inode int64) ([]Xattr, error) {
	count := len(s.xattrs) / xattrLen
	i := sort.Search(count, func(i int) bool {
		return int64(binary.LittleEndian.Uint64(s.xattrs[i*xattrLen:])) >= inode
	})
	var out []Xattr
	for ; i < count && int64(binary.LittleEndian.Uint64(s.xattrs[i*xattrLen:])) == inode; i++ {
		r := s.xattrs[i*xattrLen:]
		name, ok := s.nameAt(binary.LittleEndian.Uint32(r[8:]), uint32(binary.LittleEndian.Uint16(r[12:])))
		if !ok {
			return nil, fmt.Errorf("%w: xattr %d has a name outside the arena", errCorrupt, i)
		}
		val, ok := s.blobAt(binary.LittleEndian.Uint32(r[16:]), binary.LittleEndian.Uint32(r[20:]))
		if !ok {
			return nil, fmt.Errorf("%w: xattr %d has a value outside the arena", errCorrupt, i)
		}
		out = append(out, Xattr{Name: name, Value: val})
	}
	return out, nil
}

// Close exists so a Static can stand where a *Catalog stands. The blob is
// owned by whoever mapped it.
func (s *Static) Close() error { return nil }

// CheckOrder verifies every record array is sorted on its documented key
// and that each edge indexes a node for its own inode.
//
// The reader deliberately does NOT do this at open: it is O(n) over the
// whole catalog, and paying it on every open would undo the reason the
// format exists. An out-of-order catalog returns wrong answers rather
// than unsafe ones, so the check belongs where an O(n) pass is expected —
// fsck — and this is the method it calls.
func (s *Static) CheckOrder() error {
	for i := 1; i < s.edgeCount(); i++ {
		p, q := s.edgeParent(i-1), s.edgeParent(i)
		if p > q {
			return fmt.Errorf("catalog: edges out of order at %d: parent %d after %d", i, q, p)
		}
		if p < q {
			continue
		}
		a, ok := s.edgeName(i - 1)
		if !ok {
			return fmt.Errorf("catalog: edge %d has a name outside the arena", i-1)
		}
		b, ok := s.edgeName(i)
		if !ok {
			return fmt.Errorf("catalog: edge %d has a name outside the arena", i)
		}
		if bytes.Compare(a, b) >= 0 {
			return fmt.Errorf("catalog: edges out of order at %d: %q after %q under parent %d", i, b, a, p)
		}
	}
	for i := range make([]struct{}, s.edgeCount()) {
		r := s.edgeAt(i)
		idx := int(binary.LittleEndian.Uint32(r[24:]))
		if idx >= s.nodeCount() {
			return fmt.Errorf("catalog: edge %d indexes node %d of %d", i, idx, s.nodeCount())
		}
		if got, want := s.nodeRecord(idx).Inode, int64(binary.LittleEndian.Uint64(r[8:])); got != want {
			return fmt.Errorf("catalog: edge %d indexes a node for inode %d, not %d", i, got, want)
		}
	}

	ascending := func(name string, count int, key func(int) int64) error {
		for i := 1; i < count; i++ {
			if key(i-1) > key(i) {
				return fmt.Errorf("catalog: %s out of order at %d: %d after %d", name, i, key(i), key(i-1))
			}
		}
		return nil
	}
	inodeAt := func(sec []byte, width int) func(int) int64 {
		return func(i int) int64 { return int64(binary.LittleEndian.Uint64(sec[i*width:])) }
	}
	if err := ascending("nodes", s.nodeCount(), inodeAt(s.nodes, nodeLen)); err != nil {
		return err
	}
	if err := ascending("inline", len(s.inline)/inlineLen, inodeAt(s.inline, inlineLen)); err != nil {
		return err
	}
	if err := ascending("symlinks", len(s.symlinks)/symlinkLen, inodeAt(s.symlinks, symlinkLen)); err != nil {
		return err
	}
	if err := ascending("chunkrefs", s.chunkCount(), inodeAt(s.chunks, chunkLen)); err != nil {
		return err
	}
	if err := ascending("xattrs", len(s.xattrs)/xattrLen, inodeAt(s.xattrs, xattrLen)); err != nil {
		return err
	}
	// Chunk indexes must ascend within one inode, since a reader takes
	// them in stored order and computes logical offsets as a prefix sum.
	for i := 1; i < s.chunkCount(); i++ {
		prev, cur := s.chunks[(i-1)*chunkLen:], s.chunks[i*chunkLen:]
		if binary.LittleEndian.Uint64(prev) != binary.LittleEndian.Uint64(cur) {
			continue
		}
		if binary.LittleEndian.Uint32(prev[8:]) >= binary.LittleEndian.Uint32(cur[8:]) {
			return fmt.Errorf("catalog: chunkrefs out of order at %d within inode %d",
				i, int64(binary.LittleEndian.Uint64(cur)))
		}
	}
	for i := 1; i < s.nestedCount(); i++ {
		p := int64(binary.LittleEndian.Uint64(s.nestedAt(i - 1)))
		q := int64(binary.LittleEndian.Uint64(s.nestedAt(i)))
		if p > q {
			return fmt.Errorf("catalog: nested out of order at %d: parent %d after %d", i, q, p)
		}
		if p < q {
			continue
		}
		a, ok := s.nestedName(i - 1)
		if !ok {
			return fmt.Errorf("catalog: nested %d has a name outside the arena", i-1)
		}
		b, ok := s.nestedName(i)
		if !ok {
			return fmt.Errorf("catalog: nested %d has a name outside the arena", i)
		}
		if bytes.Compare(a, b) >= 0 {
			return fmt.Errorf("catalog: nested out of order at %d: %q after %q", i, b, a)
		}
	}
	return nil
}
