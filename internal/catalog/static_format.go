package catalog

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The static catalog format (docs/design-catalog.md): a packed,
// mmap-friendly layout that replaces SQLite for the immutable half of the
// namespace. Sorted record arrays plus two arenas, read by binary search
// and range scan — the ten queries a catalog serves are all point lookups
// or ordered scans on one key, which is a static layout's case.
//
// Nothing here allocates on a read path, and nothing derived from the
// environment is ever written: a catalog's identity is a hash of these
// bytes, so a stamp that varies between runs would silently defeat the
// reuse that makes an incremental seal cheap.

const (
	// staticMagic marks a catalog blob in this format.
	staticMagic = "PELFSCAT"

	// FormatMajor gates compatibility: a reader refuses a major it does
	// not implement rather than guessing at a layout. FormatMinor is
	// additive only — new sections, new flags, new header fields inside
	// headerLen — so an older reader reads a newer minor correctly, just
	// without whatever was added.
	FormatMajor = 1
	FormatMinor = 0

	staticHeaderLen = 64
	sectionEntryLen = 24
	// maxSections bounds the table so a corrupt count cannot make the
	// reader allocate or scan wildly before validation finishes.
	maxSections = 64
)

// Section identifiers. A reader SKIPS an id it does not know, which is
// the hinge that lets a minor version add sections.
const (
	secNames      = 1  // arena: entry and xattr names
	secEdges      = 2  // sorted by (parent, name)
	secNodes      = 3  // sorted by inode
	secChunks     = 4  // sorted by (inode, idx)
	secInline     = 5  // sorted by inode
	secXattrs     = 6  // sorted by (inode, name)
	secSymlinks   = 7  // sorted by inode
	secNested     = 8  // sorted by (parent, name)
	secIdentities = 9  // 32-byte identities, referenced by index
	secBlobs      = 10 // arena: inline data, xattr values, symlink targets
	secMeta       = 11 // catalog metadata (strings into secBlobs)
)

// Record widths. Every array is a whole number of records and every
// section starts 8-byte aligned, so a validated section can be indexed
// with multiplication rather than walked.
const (
	edgeLen     = 32
	nodeLen     = 64
	chunkLen    = 64
	inlineLen   = 16
	xattrLen    = 24
	symlinkLen  = 16
	nestedLen   = 24
	identityLen = 32
	metaLen     = 24
)

// headerFlagAnyXattr answers HasXattrs from the header, so the common
// no-xattr tree never touches the xattr section at all.
const headerFlagAnyXattr = 1 << 0

// ErrFormatVersion reports a catalog written by a future major version.
var ErrFormatVersion = errors.New("catalog: unsupported format version")

// errCorrupt reports structure that cannot be trusted. Catalog bytes are
// hash-verified against a signed generation before they reach a parser,
// so this means corruption — a truncated download, a bad cache — not an
// attacker choosing input.
var errCorrupt = errors.New("catalog: corrupt")

// staticHeader is the fixed 64-byte prefix of every catalog blob.
type staticHeader struct {
	Major        uint16
	Minor        uint16
	HeaderLen    uint16
	SectionCount uint16
	Flags        uint64
	RootInode    uint64
	EntryCount   uint64
	NodeCount    uint64
	IdentityAlgo uint32
	InlineMax    uint32
}

func (h *staticHeader) encode(dst []byte) {
	copy(dst[0:8], staticMagic)
	binary.LittleEndian.PutUint16(dst[8:], h.Major)
	binary.LittleEndian.PutUint16(dst[10:], h.Minor)
	binary.LittleEndian.PutUint16(dst[12:], h.HeaderLen)
	binary.LittleEndian.PutUint16(dst[14:], h.SectionCount)
	binary.LittleEndian.PutUint64(dst[16:], h.Flags)
	binary.LittleEndian.PutUint64(dst[24:], h.RootInode)
	binary.LittleEndian.PutUint64(dst[32:], h.EntryCount)
	binary.LittleEndian.PutUint64(dst[40:], h.NodeCount)
	binary.LittleEndian.PutUint32(dst[48:], h.IdentityAlgo)
	binary.LittleEndian.PutUint32(dst[52:], h.InlineMax)
	// [56,64) reserved, left zero: determinism requires every byte we do
	// not use be a byte we set.
}

func decodeHeader(b []byte) (staticHeader, error) {
	var h staticHeader
	if len(b) < staticHeaderLen {
		return h, fmt.Errorf("%w: %d bytes is shorter than a header", errCorrupt, len(b))
	}
	if string(b[0:8]) != staticMagic {
		return h, fmt.Errorf("%w: bad magic %q", errCorrupt, b[0:8])
	}
	h.Major = binary.LittleEndian.Uint16(b[8:])
	h.Minor = binary.LittleEndian.Uint16(b[10:])
	h.HeaderLen = binary.LittleEndian.Uint16(b[12:])
	h.SectionCount = binary.LittleEndian.Uint16(b[14:])
	h.Flags = binary.LittleEndian.Uint64(b[16:])
	h.RootInode = binary.LittleEndian.Uint64(b[24:])
	h.EntryCount = binary.LittleEndian.Uint64(b[32:])
	h.NodeCount = binary.LittleEndian.Uint64(b[40:])
	h.IdentityAlgo = binary.LittleEndian.Uint32(b[48:])
	h.InlineMax = binary.LittleEndian.Uint32(b[52:])

	if h.Major != FormatMajor {
		return h, fmt.Errorf("%w: catalog is format %d.%d, this build reads %d.x",
			ErrFormatVersion, h.Major, h.Minor, FormatMajor)
	}
	if int(h.HeaderLen) < staticHeaderLen || int(h.HeaderLen) > len(b) {
		return h, fmt.Errorf("%w: header length %d", errCorrupt, h.HeaderLen)
	}
	if h.SectionCount > maxSections {
		return h, fmt.Errorf("%w: %d sections", errCorrupt, h.SectionCount)
	}
	return h, nil
}

// section is one entry of the table that follows the header.
type section struct {
	ID    uint32
	Flags uint32
	Off   uint64
	Len   uint64
}

// identityAlgoCode maps the Meta.IdentityAlgo string to the header's
// numeric form. The string survives in the meta section; this is the
// value genfs switches on, so it is worth reading without an arena hop.
const (
	identityAlgoUnknown = 0
	identityAlgoPlain   = 1 // "blake3-256"
	identityAlgoKeyed   = 2 // "blake3-256-keyed"
)

func identityAlgoCode(s string) uint32 {
	switch s {
	case "blake3-256":
		return identityAlgoPlain
	case "blake3-256-keyed":
		return identityAlgoKeyed
	default:
		return identityAlgoUnknown
	}
}
