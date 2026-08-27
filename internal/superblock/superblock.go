// Package superblock implements the v2 signed superblock
// (docs/design-packfs.md, "Superblock" and "Signing and key management"):
// the single mutable object of a volume and the root of both trust and
// consistency. A superblock records one generation — its complete pack
// set, catalog/shard routing, allocator high-water mark, per-volume
// policy knobs, and KEK-wrapped confidentiality keys — parent-linked via
// a lineage hash and authenticated by an Ed25519 signature.
//
// Encoding is CBOR Core Deterministic (fxamacker/cbor CoreDetEncOptions):
// the signature is computed over the deterministic encoding with the
// Signature field zeroed, and verification re-encodes the decoded struct
// the same way — so what is verified is the canonical form of the parsed
// content, never attacker-controlled byte layout. Decoding tolerates
// unknown map keys deliberately: future format revisions may add fields,
// and an old reader must still verify and mount what it understands
// (unknown fields are dropped, so a signature made over them fails here —
// forward compat is for unsigned-yet superblocks a newer writer will
// re-sign, not a bypass). Duplicate map keys are rejected outright.
package superblock

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"lukechampine.com/blake3"
)

// FormatV2 is the FormatVersion written by this package.
const FormatV2 = 2

// KeyKind distinguishes the wrapped keys in the key table.
type KeyKind uint8

const (
	// KeyKindDEK is a data-encryption key (chunk/catalog confidentiality).
	KeyKindDEK KeyKind = 1
	// KeyKindIdentity is the keyed-BLAKE3 identity key (chunk identity on
	// encrypted volumes; forks inherit it so cross-branch dedup survives).
	KeyKindIdentity KeyKind = 2
)

// KeyAlgRSAOAEPSHA256 is the only wrap algorithm defined so far: the key
// bytes are RSA-OAEP/SHA-256 encrypted under the user KEK (see keywrap.go).
const KeyAlgRSAOAEPSHA256 uint8 = 1

// PackEntry names one pack of the generation's pack set. The pack list is
// the location layer: identity (content hashes) lives in catalogs, and GC
// pack liveness is set arithmetic over retained generations' pack lists.
// TrailerHash lets a fetched pack verify against the list even though pack
// names are time-ordered rather than content-derived.
type PackEntry struct {
	Name        string   `cbor:"name"`
	TrailerHash [32]byte `cbor:"trailer_hash"`
	Size        int64    `cbor:"size"`
}

// IndexRef names one multi-pack index object (internal/mpi) and
// ManifestRef one pack-manifest segment (internal/manifest), as a
// superblock lists them.
//
// They live HERE, in the format package, rather than in the packages that
// build the objects, for two reasons. A superblock field's encoding is
// part of the signed wire format, so the struct tags that define it belong
// beside every other struct that defines one — otherwise the shape of a
// signed document is spread across packages that are free to refactor.
// And the alternative made this pure format package depend transitively on
// the object store: mpi imports pelicanobj, so `PackIndexes []mpi.Ref`
// dragged the transport into a package that only encodes bytes. The
// dependency now points the sane way — mpi and manifest import this.
//
// Entries and Packs are counters a consolidation policy reads WITHOUT
// fetching the object; Hash is what a fetched object is verified against,
// and it is the reason a hash-named derived object can be trusted at all:
// the signature covers this ref, so it covers the object's contents.
type IndexRef struct {
	Name    string   `cbor:"name"`
	Hash    [32]byte `cbor:"hash"`
	Size    int64    `cbor:"size"`
	Entries uint32   `cbor:"entries"`
	Packs   uint32   `cbor:"packs"`
}

// ManifestRef names one segment of the generation's pack manifest. Packs
// is how many packs the segment describes — the same "read the policy
// without fetching the object" role Entries plays for an index.
type ManifestRef struct {
	Name  string   `cbor:"name"`
	Hash  [32]byte `cbor:"hash"`
	Size  int64    `cbor:"size"`
	Packs uint32   `cbor:"packs"`
}

// RefName and RefSize are the two things a consolidation policy reads out
// of a ref without fetching what it names: which object, and how big.
// They exist as methods because publish applies ONE set of tiering rules
// to both kinds of ref, and a Go type parameter can call a method but
// cannot reach a field.
func (r IndexRef) RefName() string { return r.Name }
func (r IndexRef) RefSize() int64  { return r.Size }

func (r ManifestRef) RefName() string { return r.Name }
func (r ManifestRef) RefSize() int64  { return r.Size }

// GraftBudgetBytes is what the graft list may take of the superblock write
// budget (size.go) before a seal refuses to add another.
//
// It is a share of the ~105 KiB the budget's named shares leave over, and
// it is small on purpose. A graft ROOT is an operator-scale object — a
// person types the URL — so tens are plausible and thousands are a
// misuse of the feature rather than a volume that grew. At 215 bytes for
// an entry with realistic (long) paths this carries ~76 roots, and the
// entry that would cross it
// is refused with the list's weight in the message rather than silently
// pushing the superblock toward the cliff size.go describes.
const GraftBudgetBytes = 16 << 10

// GraftEntry is one grafted subtree: a path in this volume served by
// ranged reads against a foreign Pelican prefix, with no copy of the
// bytes under the volume's own prefix.
//
// Path is where the subtree is mounted, Source is the prefix the bytes
// come from, and Index names the hash-named location table that maps the
// chunk identities under Path to (object key, offset, length) inside
// Source. Block is the fixed block size the spider cut with, recorded
// because a later refresh must cut identically or every identity moves.
//
// The signature covers all of it, which makes the source URL
// TAMPER-EVIDENT and nothing more: a reader still chose to trust whoever
// holds the volume's signing key with a URL its own network will fetch.
// That is the whole of the security argument in docs/design-graft.md, and
// it is why a mount may refuse a source it does not like.
type GraftEntry struct {
	Path   string   `cbor:"path"`
	Source string   `cbor:"source"`
	Index  [32]byte `cbor:"index"`
	// Size is the index object's length, so a reader can budget the fetch
	// before it makes it — the role IndexRef.Size plays.
	Size int64 `cbor:"size"`
	// Block is the BASE block size and BlockMax the ceiling; an object
	// larger than Block*BlocksPerObject is cut at a power-of-two multiple
	// of Block, up to BlockMax (internal/graft, blocks.go).
	//
	// The three of them are the RULE, not a description, and they are
	// recorded because a refresh that cut differently would move every
	// identity in the graft and be a new graft rather than a refresh.
	// Per-object block sizes needed no change to the index format — a
	// record already carries a per-block length, because the last block
	// of every object is short — but the rule has nowhere else to live.
	//
	// A generation written before these existed reads as BlockMax == 0
	// and BlocksPerObject == 0, which internal/graft interprets as "one
	// global size", exactly what such a generation was cut with.
	Block           int64  `cbor:"block"`
	BlockMax        int64  `cbor:"block_max,omitempty"`
	BlocksPerObject uint32 `cbor:"blocks_per_object,omitempty"`
	// Blocks is how many blocks the index holds and Bytes the logical
	// size of the grafted tree; Files and Objects how many files the
	// graft serves and how many source objects they live in. All four are
	// reportable facts (`pelfs graft --list`, fsck, `--prefetch`) that
	// cost nothing to record and an index fetch to recompute — and
	// Bytes is what a prefetch budget has to size a graft from, since a
	// graft has no pack sizes.
	Blocks  uint64 `cbor:"blocks"`
	Bytes   int64  `cbor:"bytes"`
	Files   uint64 `cbor:"files,omitempty"`
	Objects uint64 `cbor:"objects,omitempty"`
}

func (g GraftEntry) RefName() string { return g.Path }
func (g GraftEntry) RefSize() int64  { return g.Size }

// ImportBudgetBytes is what the import list may take of the superblock
// write budget (size.go) before a seal refuses to add another.
//
// It is sized like GraftBudgetBytes and for the same reason: an import is
// an operator-scale event — a person types a source prefix and waits
// hours — so tens are plausible and thousands are a misuse. An entry with
// a realistic path and a handful of lineage rows encodes to roughly 250
// bytes, so this carries about 65.
//
// UNLIKE the graft list, THIS ONE CANNOT BE TRIMMED TO MAKE ROOM, and
// that is the thing to know before raising or lowering it. Every entry
// carries a lineage claim, and a lineage claim is PERMANENT: the numbers
// were handed out to files that are in the tree and in every tag and
// retired generation that names it, so dropping the row would let a later
// `pelfs branch` draw the same slice and start allocating numbers this
// volume has already used. A volume that fills this budget has to stop
// importing, not start forgetting.
const ImportBudgetBytes = 16 << 10

// LineagePair is one row of an import's inode renumbering: the lineage a
// SOURCE inode was allocated from, and the lineage of this volume it was
// renumbered into (internal/inodemap).
//
// The map is per-lineage rather than per-inode because that is the only
// form that fits. A tree holds hundreds of millions of inodes and a
// handful of lineages, and the renumbering leaves the low 40 bits — the
// allocation counter — untouched, so a lineage pair describes every inode
// that lineage ever allocated in five bytes.
type LineagePair struct {
	From uint32 `cbor:"from"`
	To   uint32 `cbor:"to"`
}

// ImportEntry is the provenance of one `pelfs import`: which volume's
// generation was copied in, where it landed, and the inode renumbering it
// was given.
//
// # It is deliberately NOT a Fork
//
// A Fork says "a generation of THIS volume", and merge reads it that way
// (Fork.Base is fetched and diffed against). An imported generation
// belongs to a different volume, signed by a different key, and is not a
// base for anything here. Recording it as a Fork would make the next
// merge take a foreign tree as its common ancestor, which is a wrong
// answer rather than a missing one.
//
// # The two jobs it does
//
//   - IT IS THE LINEAGE CLAIM, and this is the load-bearing one. Nothing
//     else in the format records the set of lineages a tree contains:
//     Fork.Lineage names what a generation ALLOCATES FROM, Catalogs[].Inode
//     samples whichever directories happen to root a catalog, and Shards
//     cover only promoted inodes. So a volume that has imported and
//     records nothing would let the next `pelfs branch` draw a lineage the
//     imported tree is already using, and the two would hand out the same
//     numbers for different files — the exact collision per-branch
//     lineages exist to prevent. `pickLineage` reads Lineages from here.
//   - It answers "where did this come from", which after an import is a
//     question nothing else can answer. An import copies the bytes and
//     re-signs under our key, so the tree is indistinguishable from one
//     this volume produced. Source, SourceVolumeID, SourceGeneration and
//     SourceHash are what a later reader has to go on.
//
// # Why entries are never removed
//
// Deleting the imported subtree does not release its lineages. The
// numbers were handed out, and every tag, every retired generation and
// every reader still on an older generation is entitled to keep using
// them. So Path is PROVENANCE and not a live locator — it says where the
// tree landed when it was imported, and stays true about that even after
// the tree is moved or deleted.
type ImportEntry struct {
	// Path is where the imported tree landed in this volume.
	Path string `cbor:"path"`
	// Source is the prefix it was read from, SourceBranch the ref or tag
	// within it. Both are for a human; neither is resolved at read time,
	// because an import depends on nothing after it lands.
	Source       string `cbor:"source"`
	SourceBranch string `cbor:"source_branch,omitempty"`
	// SourceVolumeID, SourceGeneration and SourceHash identify the exact
	// generation that was copied. SourceHash is the wire hash of that
	// superblock, which is what makes the claim checkable by anyone who
	// still has the source volume.
	SourceVolumeID   [16]byte `cbor:"source_volume_id"`
	SourceGeneration uint64   `cbor:"source_generation"`
	SourceHash       [32]byte `cbor:"source_hash"`
	// SourcePub is the Ed25519 key the source generation was signed by,
	// verified at import time. Recorded so a later reader can tell which
	// custody the bytes arrived from without holding the source volume.
	SourcePub [32]byte `cbor:"source_pub"`
	// ImportedUnixNano is when it landed.
	ImportedUnixNano int64 `cbor:"imported_unix_nano"`
	// Lineages is the renumbering, ascending by From. Every lineage named
	// in To is taken by this volume forever (see the type comment).
	Lineages []LineagePair `cbor:"lineages"`
	// Files, Inodes and Bytes are what was copied — reportable facts that
	// cost nothing to record and a whole-tree walk to recompute.
	Files  uint64 `cbor:"files,omitempty"`
	Inodes uint64 `cbor:"inodes,omitempty"`
	Bytes  int64  `cbor:"bytes,omitempty"`
}

func (i ImportEntry) RefName() string { return i.Path }
func (i ImportEntry) RefSize() int64  { return int64(len(i.Path)) }

// CondemnedPack records a pack repack removed from the pack list: the
// name and when it was condemned. Publish carries entries forward until
// they age past Params.TGraceSeconds, then drops them; GC retains
// condemned packs younger than the grace window so readers pinned to a
// recent anonymous generation keep their packs
// (docs/design-packfs.md, "Retention and GC"). This replaces walking
// lineage ancestors, whose superblocks are not reliably fetchable.
// Maint is what MAINTENANCE has already done to this branch, carried
// forward by every ordinary publish and written only by a repack.
//
// It exists so that "is a repack worth running" can be answered from the
// head alone. Answering it truthfully costs a reachability sweep — a read
// of every catalog and every trailer — which is far too much to pay on a
// schedule just to be told there is nothing to do. This is the cheap
// gate in front of that: git's `gc --auto` shape, where a COUNT that
// accumulates decides whether to pay for the real analysis, and the real
// analysis decides what to do.
//
// It deliberately does NOT estimate garbage. A generation cannot know
// what it orphaned without asking what else still references it, which is
// the sweep again; a field claiming to hold dead bytes would be a number
// nobody could compute and everybody would trust. What is here is only
// what is exactly knowable at zero cost: where the branch was when
// maintenance last ran.
type Maint struct {
	// RepackGeneration is the generation a repack last published, and
	// RepackPacks how many packs the branch held at that moment. The
	// difference between that count and the current one is how much has
	// accumulated since — the trigger.
	RepackGeneration uint64 `cbor:"repack_generation"`
	RepackPacks      uint32 `cbor:"repack_packs"`
	// RepackUnixNano is when it ran, for a floor on how often a volume
	// re-sweeps regardless of churn.
	RepackUnixNano int64 `cbor:"repack_unix_nano"`
}

// Fork is where a branch came from, carried by every generation on it.
//
// It exists so that a merge does not have to GUESS its base. Nothing else
// in the format can supply one: refs and tags are the only addressable
// entry points, so PrevHash chains cannot be walked back to where two
// branches meet, and the superblock backups in packs are built over a
// different pack set so their hashes are not the hashes those chains
// record. Without this, every merge takes the base as a hand-typed
// argument and a wrong answer silently mis-attributes change.
//
// It also carries the two numbers that make an inode collision decidable
// rather than guessable — see Lineage and BaseNextInode.
type Fork struct {
	// Base is the wire hash of the generation this branch started at, and
	// BaseGeneration its number. Together they name the merge base for
	// any branch cut from the same point.
	Base           [32]byte `cbor:"base"`
	BaseGeneration uint64   `cbor:"base_generation"`
	// BaseNextInode is the inode high-water mark at the fork. It is the
	// exact cut between numbers that meant the same file on both sides
	// and numbers each side allocated for itself, because NextInode never
	// reuses a value.
	BaseNextInode uint64 `cbor:"base_next_inode"`
	// From names the ref this branch was cut from, for a human reading a
	// superblock. Not load-bearing: the ref may since have moved or gone.
	From string `cbor:"from,omitempty"`
	// Tag is a tag pinning the base generation, and it is what makes the
	// base READABLE rather than merely named.
	//
	// Base identifies the generation; it does not say where to get it, and
	// a generation is only addressable through a ref or a tag. The moment
	// the source branch seals again, the fork point is no longer any
	// branch's head — which happens in the most ordinary flow there is, so
	// without a pin a merge would almost always have nothing to read. A
	// tag also keeps retention from collecting it, which is the other half
	// of the same requirement.
	//
	// Empty on a branch created before this existed, or by a writer that
	// could not create the tag; the base is then findable only if some
	// other ref happens to name it.
	Tag string `cbor:"tag,omitempty"`
	// Lineage is the partition of the inode space this branch allocates
	// from, and it is what makes merges cheap instead of impossible.
	//
	// Two branches that allocate from one counter assign the same number
	// to different files, so merging them means renumbering a whole side —
	// every catalog naming those inodes, the shard ranges that route
	// hardlink content by inode, and the hardlink grouping that IS inode
	// equality. Giving each branch its own high-order slice means that
	// never happens, and it costs nothing but sparse inode numbers.
	//
	// Zero is the original lineage of every volume, which is why an
	// unforked volume needs no Fork record at all.
	Lineage uint32 `cbor:"lineage"`
}

// InodeLineageShift splits an inode into a lineage and a counter: the
// high bits say which branch allocated it, the low 40 bits say which
// allocation it was.
//
// 40 bits is a trillion inodes per lineage, three orders of magnitude past
// the hundred million objects the format is designed for.
const InodeLineageShift = 40

// MaxLineage is the largest lineage, and it is 23 bits rather than the 24
// the shift leaves room for so that EVERY INODE FITS IN A SIGNED 64-BIT
// INTEGER.
//
// Inodes are uint64 in the format and int64 in storage: the catalog and
// the overlay are SQLite, whose integers are signed. A lineage with the
// top bit set produces an inode above 2^63, which round-trips as a
// negative int64 and fails to scan back — "converting driver.Value type
// int64 (-2130844738536865790) to a uint64", found by the first test that
// drew a high lineage.
//
// Half the address space for nothing, and 8.4 million branches is still
// far past use.
const MaxLineage = 1<<23 - 1

// LineageOf reports which lineage allocated an inode.
func LineageOf(inode uint64) uint32 { return uint32(inode >> InodeLineageShift) }

// FirstInode is where a lineage starts allocating. Inode 1 is the root in
// every lineage's numbering, so a fresh lineage begins above it.
func FirstInode(lineage uint32) uint64 {
	return uint64(lineage)<<InodeLineageShift + 2
}

type CondemnedPack struct {
	Name            string `cbor:"name"`
	CondemnedAtUnix int64  `cbor:"condemned_at_unix"`
}

// CondemnedRef is CondemnedPack for the DERIVED key spaces: a pack index
// (internal/mpi) or a pack manifest (internal/manifest) that a generation
// stopped listing, and when it stopped. Same two columns, same lifecycle
// — publish carries an entry forward until it ages past
// Params.TGraceSeconds, GC counts a young entry as live — because it is
// the same problem. Consolidation merges several refs into one and simply
// stops naming the inputs; the generation that still names them is
// retired, and a retired generation is addressable only by hash, so
// NOTHING A SWEEP CAN ENUMERATE speaks for those objects. Without a
// ledger they are deleted the moment they age.
//
// The cost of losing one is not symmetric, which is why this arrived when
// manifests did. An index is derived from a pack set stated elsewhere, so
// a reader pinned to that generation falls back to pack trailers and is
// slow. A manifest IS that statement, so the generation can no longer say
// what packs it references: unreadable, and the packs it alone named go
// on the sweep after.
//
// THE LIMIT, stated here because this narrows the hole rather than
// closing it: the window is T_grace, not forever. A reader pinned to a
// generation whose refs were condemned longer ago than that still loses
// them, with exactly the consequences above. Retention's live set is
// head-plus-tags and no ledger changes that — a workflow that needs a
// longer pin must TAG, which pins exactly and indefinitely.
type CondemnedRef struct {
	Name            string `cbor:"name"`
	CondemnedAtUnix int64  `cbor:"condemned_at_unix"`
}

// ShardEntry routes one inode-range shard holding promoted (nlink > 1)
// records. Ranges are inclusive and must not overlap; the shard body is
// the content-addressed blob named by Identity.
type ShardEntry struct {
	FirstInode uint64   `cbor:"first_inode"`
	LastInode  uint64   `cbor:"last_inode"`
	Identity   [32]byte `cbor:"identity"`
}

// CatalogEntry describes one catalog of the generation's catalog tree:
// the directory inode it is rooted at, the identity of its bytes, the
// path it covers, and the split weight of the subtree it stands for.
//
// The tree is already navigable by descent (nested rows), so this list
// adds no reachability. What it adds is the ability to decide what NOT to
// do without fetching anything: a publisher building the next generation
// can see from the superblock alone that a subtree is unchanged, keep the
// catalog named here — carried forward by reference, the way a git commit
// keeps the tree objects it did not change — and still reach the same
// split decision in the parent, which needs Weight, the one number that
// stands in for a subtree nobody walked.
//
// Promoted counts nlink>1 files inside the catalog's span. Their content
// records live in inode SHARDS, which are rebuilt whole from the walk
// every generation; a span holding none can be skipped entirely, and one
// holding some cannot.
type CatalogEntry struct {
	Inode    uint64   `cbor:"inode"`
	Identity [32]byte `cbor:"identity"`
	Path     string   `cbor:"path"`
	Weight   int64    `cbor:"weight"`
	Promoted uint32   `cbor:"promoted"`
}

// RootHint says where the root catalog's stored bytes SAT when this
// generation was published: which pack, at what offset, for how many
// stored bytes. It is a hint, and the word is load-bearing.
//
// Identity remains the truth. A repack moves objects between packs and
// rewrites neither the catalogs nor the chunkrefs that name them — that
// separation is the premise of the format — so nothing keeps this in step
// with reality, and a generation published before a repack carries a hint
// pointing into a pack that no longer holds those bytes. A reader must
// therefore read what it points at, check the bytes against RootCatalog,
// and on any disagreement resolve the root the ordinary way (pack
// trailers). The cost of a stale hint is that fallback; it can never be a
// wrong answer.
//
// It exists because locating the root catalog is the one lookup a mount
// cannot avoid and cannot defer: the identity-to-location map lives in
// pack trailers, so a cold mount that guesses wrong pays a round trip per
// pack of the generation before it can answer anything. The root is
// special in a way no other entry is — it is asked for exactly once, first,
// by everyone — which is why only the root gets one. Locations for the
// whole catalog list would recouple identity to location and be
// invalidated wholesale by a single repack.
type RootHint struct {
	Pack   string `cbor:"pack"`
	Off    int64  `cbor:"off"`
	Length int64  `cbor:"length"`
}

// KeyEntry is one row of the key table: a 32-byte key wrapped by the user
// KEK. Key-id 0 is reserved to mean plaintext and never appears here.
type KeyEntry struct {
	ID      uint32  `cbor:"id"`
	Kind    KeyKind `cbor:"kind"`
	Alg     uint8   `cbor:"alg"`
	Wrapped []byte  `cbor:"wrapped"`
}

// Params are the per-volume knobs recorded in the superblock so writers,
// readers, and GC agree on policy (catalog split/merge thresholds, inline
// threshold, GC grace window, anonymous-generation retention).
type Params struct {
	SMaxBytes     int64  `cbor:"s_max_bytes"`
	SMinBytes     int64  `cbor:"s_min_bytes"`
	InlineMax     int64  `cbor:"inline_max"`
	TGraceSeconds int64  `cbor:"t_grace_seconds"`
	RetainK       uint32 `cbor:"retain_k"`
}

// The grace window, T_grace, is a per-volume PARAMETER and not a constant.
// It is recorded in TGraceSeconds, and everything that ages an object
// against it — retention's two guards, repack's planner, the three
// condemned ledgers — reads it from the document. These two bound what a
// writer may record.
//
// DefaultTGrace is what a volume gets when nobody says otherwise, and what
// a reader assumes for a document that states nothing. Every v0.1.0
// superblock stated 72h, so a volume from before the knob existed keeps
// exactly the window it already had.
//
// MinTGrace is a FOOTGUN FLOOR, and it is the part of this that is not a
// matter of taste. The window is what makes the sweep safe to run against
// live writers with no coordination: a pack younger than it may be one a
// concurrent writer is about to reference from a generation the sweep never
// saw, and a hash-named object younger than it may be one publish has
// uploaded but not yet flipped a ref to name. At zero both of those become
// "delete it", so `--grace 0` would be a volume whose next sweep can race a
// live writer into data loss. An hour is far more than either of those
// windows needs — they are one publish long — and far less than any
// workflow's pin, so refusing below it costs nothing real.
const (
	DefaultTGrace = 72 * time.Hour
	MinTGrace     = time.Hour
)

// Grace is the window this generation records, or DefaultTGrace when it
// records none. Every reader of the window comes through here, so that
// "what does this document say" has exactly one answer.
func (p Params) Grace() time.Duration {
	if p.TGraceSeconds <= 0 {
		return DefaultTGrace
	}
	return time.Duration(p.TGraceSeconds) * time.Second
}

// Superblock is one generation of a volume. All fields participate in the
// signature except Signature itself (zeroed for signing). CreatedUnixNano
// is supplied by the caller — encoding never reads a clock, so a given
// struct always encodes to the same bytes.
//
// Evolution rule: every future field MUST be omitempty (pointer or
// nilable), because Verify re-encodes the decoded struct — a zero-valued
// non-omitempty addition would change the re-encoding of every older
// document and break its signature. A reader that drops fields it does
// not know rejects the document at Verify (the safe direction: old
// readers refuse newer superblocks instead of silently ignoring signed
// content); lineage hashes are immune either way, being defined over
// wire bytes (see VerifyChain).
type Superblock struct {
	FormatVersion   uint     `cbor:"format_version"`
	VolumeID        [16]byte `cbor:"volume_id"`
	Generation      uint64   `cbor:"generation"`
	PrevHash        [32]byte `cbor:"prev_hash"` // BLAKE3 of the previous generation's encoding; zero for generation 0
	CreatedUnixNano int64    `cbor:"created_unix_nano"`

	RootCatalog [32]byte `cbor:"root_catalog"`
	// PackList is the generation's pack set INLINE, and it is the older of
	// two ways to say the same thing. A generation that records Manifests
	// leaves this empty — see Manifests for why, and PacksAreInManifests
	// for how a reader tells the two apart.
	PackList  []PackEntry  `cbor:"pack_list"`
	Shards    []ShardEntry `cbor:"shards"`
	NextInode uint64       `cbor:"next_inode"`
	Params    Params       `cbor:"params"`
	KeyTable  []KeyEntry   `cbor:"key_table"`
	// Condemned lists recently repacked-away packs still inside the GC
	// grace window (omitempty per the evolution rule below).
	Condemned []CondemnedPack `cbor:"condemned,omitempty"`
	// Maint records what maintenance has done to this branch (see Maint).
	// Absent on a volume no repack has touched, which reads as "never",
	// and that is the correct starting point rather than a special case.
	Maint *Maint `cbor:"maint,omitempty"`
	// Fork is where this branch came from (see Fork). Absent on a volume
	// that has never been branched, which reads as "the original lineage"
	// and is the correct starting point rather than a special case.
	Fork *Fork `cbor:"fork,omitempty"`
	// Branch names the ref this generation was SEALED ONTO. It is a
	// statement about the writer, not about where the bytes currently sit:
	// `pelfs branch dev` copies main's head verbatim under a second name,
	// and a tag copies a head into tags/, so both hold documents that still
	// say "main" — truthfully, because main is what sealed them.
	//
	// WHY A SIGNED FIELD AND NOT A TRAILER COLUMN. The only consumer is the
	// retain window (internal/retention/lastk.go), which reconstructs
	// retired generations from the disaster-recovery backups buried in
	// packs. A backup is found by LOOKING — its offset comes from an
	// unauthenticated trailer, nothing points at it — so the only thing that
	// makes a scavenged document usable is that the volume's own key signed
	// it. Attribution decides which branch's window a document is allowed to
	// FILL, and filling a window with the wrong document drops the right one
	// out of the root set, which is data loss rather than wasted bytes. A
	// column that anyone able to append to a pack could write would be a way
	// to aim that loss. So it lives inside the signature or it does not
	// exist.
	//
	// WHAT IT BUYS. A generation number counts steps along one lineage:
	// branch a volume at N and both children seal N+1, and before this field
	// their backups were indistinguishable (same volume id, same key, same
	// number). The window scan therefore had to keep EVERY candidate for a
	// wanted number and could not stop at the first complete answer. With
	// the branch recorded, a backup this branch sealed is identified by
	// (branch, generation), and the scan stops once every generation in the
	// window has one.
	//
	// WHAT IT DOES NOT BUY, twice over. A branch's window reaches back past
	// its own fork point, and those generations were sealed by the PARENT
	// branch — dev inherits main's generations 1..N and their backups say
	// "main". They are dev's history all the same, so a generation with no
	// candidate of its own falls back to the old keep-every-candidate rule
	// rather than being declared unresolved. And a branch NAME reused for a
	// different line of history — delete dev, recreate it from an older
	// generation, seal the same numbers again — collides exactly as a bare
	// number did. Both residuals are argued in lastk.go.
	//
	// omitempty per the evolution rule below, and that is not decoration: a
	// v0.1.0 superblock decodes with Branch empty, re-encodes without the
	// key, and verifies unchanged. Pinned by TestAV010SuperblockStillVerifies
	// against wire bytes captured from the v0.1.0 encoder.
	Branch string `cbor:"branch,omitempty"`
	// CatalogKeyID names the key-table entry that encrypts catalog,
	// shard, and superblock-backup pack entries this generation (0 =
	// plaintext). Catalog references (nested rows, RootCatalog, shard
	// identities) carry no per-entry alg/keyid the way chunkrefs do, so
	// their encoding is fixed — always zstd, this one key — and stated
	// here rather than sniffed.
	CatalogKeyID uint32 `cbor:"catalog_key_id,omitempty"`
	// Catalogs describes the generation's catalog tree so the NEXT publish
	// can skip the parts of it that did not change. Omitted by writers
	// that do not maintain it; a reader needs nothing from it, and a
	// publisher that finds it absent simply rebuilds every catalog.
	Catalogs []CatalogEntry `cbor:"catalogs,omitempty"`
	// Grafts names the external subtrees this generation serves: a path
	// inside the volume, and the foreign Pelican prefix whose bytes fill
	// it (internal/graft, docs/design-graft.md).
	//
	// LIKE Manifests AND UNLIKE PackIndexes, these are NOT hints. A graft
	// is the ONLY record of where a grafted file's bytes live — the
	// chunkrefs naming them resolve in no pack — so a reader that cannot
	// resolve a graft must fail the read, never fall through to the pack
	// index, which would report content missing that was never in a pack.
	//
	// Only the ROOTS live here, bounded by GraftBudgetBytes; the
	// identity -> (object, offset, length) table is the hash-named Index
	// object each entry names, exactly as a manifest segment is. The
	// superblock must not grow with the number of grafted FILES.
	Grafts []GraftEntry `cbor:"grafts,omitempty"`
	// Imports is the provenance of every `pelfs import` this branch has
	// taken, and the inode renumbering each was given (ImportEntry).
	//
	// UNLIKE Grafts, IT NAMES NO DEPENDENCY. An import copies the bytes
	// into this volume's own packs and re-signs under this volume's key,
	// so nothing here is resolved at read time and a reader that ignores
	// the field mounts and reads correctly. What it would lose is the
	// LINEAGE CLAIM, which is why this is carried forward by every seal
	// and never trimmed: see ImportEntry.
	Imports []ImportEntry `cbor:"imports,omitempty"`
	// RootCatalogHint, when set, is where the root catalog was written (see
	// RootHint). Optional in both directions: a writer that does not track
	// it omits it, and a reader that finds it absent — or finds it stale —
	// resolves the root through the pack index instead.
	RootCatalogHint *RootHint `cbor:"root_catalog_hint,omitempty"`
	// PackIndexes names the multi-pack indexes covering this generation:
	// objects under mpi.Dir that answer "which pack holds this identity"
	// for many packs at once, instead of one round trip per pack trailer
	// (internal/mpi, docs/design-packfs.md "Locating things").
	//
	// They are HINTS, exactly as RootCatalogHint is, and for the same
	// reason: an index is DERIVED — publish writes it, repack rewrites it,
	// losing one costs speed and nothing else — so a reader verifies what
	// an index sends it to and falls back to pack trailers when the answer
	// does not hold up. Nothing here may turn into a wrong read or a
	// failed mount.
	//
	// Publish carries the previous generation's refs forward alongside its
	// own, the way PackList is carried, so an index a live generation
	// names stays live. A seal also CONSOLIDATES the newest of them into
	// one, which drops the inputs off this list — see CondemnedIndexes for
	// what keeps those objects alive afterwards. Retiring an index whose
	// packs are mostly gone is repack's job and is not implemented yet.
	PackIndexes []IndexRef `cbor:"pack_indexes,omitempty"`
	// Manifests names the segments of this generation's pack manifest:
	// objects under manifest.Dir holding what PackList used to hold —
	// every pack's name, trailer hash and size — as a derived, hash-named,
	// segmented object instead of inline bytes (internal/manifest,
	// docs/design-packfs.md "The pack list moves out of the superblock").
	//
	// UNLIKE PackIndexes, THESE ARE NOT HINTS. An index is derived from a
	// pack set the superblock states some other way, so losing one costs
	// speed; the manifest IS that statement, so a generation recording it
	// here has no other record of what it references. A reader that cannot
	// fetch these cannot enumerate and cannot authenticate a trailer, and
	// must FAIL — never fall through to an empty pack set, which reads as
	// "this volume has no data" and would let a sweep act on it.
	//
	// THE FORMAT DECISION, stated once, here: a generation that records
	// manifest refs STOPS writing PackList. Not "as well as" — the point
	// is that a superblock stops growing with pack count, and carrying
	// both would keep every byte this removes. So:
	//
	//   - A reader prefers the manifest and falls back to PackList only
	//     when Manifests is empty. Every generation written before this
	//     change has an inline list and no manifest refs, so it keeps
	//     working forever: no migration, no rewrite, no flag day.
	//   - A reader OLDER than this change cannot read a manifest-only
	//     generation. It does not silently mount an empty volume, which is
	//     the one failure worth engineering against: this package's
	//     decoder drops unknown map keys and Verify re-encodes what it
	//     decoded, so an old binary loses "manifests" and fails the
	//     SIGNATURE — a hard refusal at the trust boundary. An
	//     ErrBadSignature on a generation newer than the binary is this
	//     and nothing else.
	//
	// That break is ACCEPTED: the format is pre-release, and generations
	// in the old shape exist in test fixtures rather than in the wild. It
	// is the one-way door in this change, and it is written here because
	// this is the struct someone reads when they hit it.
	Manifests []ManifestRef `cbor:"manifests,omitempty"`
	// CondemnedIndexes and CondemnedManifests are the derived key spaces'
	// ledgers: refs this generation STOPPED listing, with when it stopped,
	// so retention keeps those objects for the grace window instead of
	// deleting them the moment nothing addressable names them
	// (CondemnedRef; docs/design-packfs.md, "Retention and GC").
	//
	// Two things get recorded here. Consolidation's inputs, which a seal
	// merges into one ref and then stops naming. And the superblock
	// BACKUP's in-flight manifest segment: the backup rides in the last
	// pack and so must state its pack set before the seal finishes, and
	// the final superblock supersedes that segment the instant it lands.
	// Neither is deleted by publish — retention decides that, and these
	// are what it decides it from.
	//
	// Both omitempty, per the evolution rule above, and purely additive: a
	// superblock written before these existed decodes with empty ledgers
	// and sweeps exactly as it always did.
	//
	// The cost to know about: unlike the pack ledger, whose entries a
	// repack produces rarely, a consolidating seal condemns a ref or two
	// EVERY time, and names here are 64-character content hashes. A mount
	// checkpointing every few minutes therefore carries a few thousand
	// entries — low hundreds of KB — for T_grace before they age off. That
	// is a fraction of the inline pack list this design removed, and the
	// alternative is deleting objects live generations still need, but it
	// is the reason to keep T_grace honest rather than generous.
	CondemnedIndexes   []CondemnedRef `cbor:"condemned_indexes,omitempty"`
	CondemnedManifests []CondemnedRef `cbor:"condemned_manifests,omitempty"`

	// SigningPub is informational — it names the key that produced
	// Signature so tooling can report custody, but Verify never trusts it
	// (trusting the embedded key would make signing pointless).
	SigningPub [32]byte `cbor:"signing_pub"`
	// NextPub, when set, announces a successor signing key: the next
	// generation may be signed by it instead (custody-chain rotation).
	NextPub   *[32]byte `cbor:"next_pub,omitempty"`
	Signature [64]byte  `cbor:"signature"`
}

// PacksAreInManifests reports which of the two shapes this generation
// uses: true when the pack set lives in the manifest objects Manifests
// names, false when it is inline in PackList.
//
// It is a method rather than a len() at each call site because it is the
// predicate the whole fallback turns on, and one place to read is one
// place to be wrong. Resolving the packs themselves is manifest.Packs,
// which needs an object store and so cannot live here.
func (sb *Superblock) PacksAreInManifests() bool { return len(sb.Manifests) > 0 }

// TakenLineages is every inode lineage this generation is KNOWN to have
// handed numbers out of: the original lineage 0, the lineage this branch
// allocates from, and every lineage an import renumbered a foreign tree
// into.
//
// "Known" is the honest word and the limit is worth stating where the
// method is. Lineage 0 is always included because every volume began
// there and inode 1 is in it on every volume there has ever been.
// Fork.Lineage is what this branch allocates from now. Imports are what
// this branch bought from elsewhere. What is NOT here — and cannot be,
// because the format does not record it — is a lineage this tree gained
// by MERGING a branch that has since been deleted: the merged inodes are
// in the tree, and no field names their lineage. That residue is
// docs/known-issues.md KL-7's other half, and the only thing that closes
// it is a walk.
//
// So this is a floor on what is taken, never a ceiling, and every caller
// is a caller that must not REUSE a taken lineage — where a floor is the
// safe direction.
func (sb *Superblock) TakenLineages() map[uint32]bool {
	out := map[uint32]bool{0: true}
	if sb == nil {
		return out
	}
	if sb.Fork != nil {
		out[sb.Fork.Lineage] = true
	}
	out[LineageOf(sb.NextInode)] = true
	for _, im := range sb.Imports {
		for _, l := range im.Lineages {
			out[l.To] = true
		}
	}
	return out
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(err)
	}
	// Unknown fields tolerated (default) — see the package comment.
	// Duplicate keys rejected: a signed document must parse one way.
	if decMode, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode(); err != nil {
		panic(err)
	}
}

// Encode returns the deterministic CBOR encoding of sb, Signature included.
// This is the byte stream stored under refs/<branch>, hashed for lineage
// (PrevHash of the next generation), and embedded in packs as a backup.
func (sb *Superblock) Encode() ([]byte, error) {
	return encMode.Marshal(sb)
}

// Decode parses an encoded superblock. Unknown fields are ignored,
// duplicate keys are an error; no signature check happens here — callers
// must Verify (or VerifyChain) before trusting anything.
func Decode(data []byte) (*Superblock, error) {
	sb := new(Superblock)
	if err := decMode.Unmarshal(data, sb); err != nil {
		return nil, fmt.Errorf("decode superblock: %w", err)
	}
	return sb, nil
}

// Hash is the lineage hash: plain BLAKE3-256 of an encoded superblock.
func Hash(encoded []byte) [32]byte {
	return blake3.Sum256(encoded)
}

// signingMessage is the deterministic encoding with Signature zeroed —
// the exact bytes Ed25519 signs and verifies.
func (sb *Superblock) signingMessage() ([]byte, error) {
	unsigned := *sb // arrays copy by value; shared slices are read-only here
	unsigned.Signature = [64]byte{}
	return encMode.Marshal(&unsigned)
}

// Sign sets SigningPub from priv and computes Signature over the
// deterministic encoding (with Signature zeroed). Sign must run after
// every other field is final; any later mutation invalidates the signature.
func (sb *Superblock) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("sign superblock: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	copy(sb.SigningPub[:], priv.Public().(ed25519.PublicKey))
	msg, err := sb.signingMessage()
	if err != nil {
		return fmt.Errorf("sign superblock: %w", err)
	}
	copy(sb.Signature[:], ed25519.Sign(priv, msg))
	return nil
}

// ErrBadSignature reports a signature that does not verify under the key
// the caller trusts.
var ErrBadSignature = errors.New("superblock signature verification failed")

// Verify checks Signature against trusted — the key the reader pinned
// (--volume-pubkey or TOFU), never the embedded SigningPub. The embedded
// key is informational only; verifying against it would let any holder of
// any keypair forge superblocks.
func (sb *Superblock) Verify(trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return fmt.Errorf("verify superblock: trusted key is %d bytes, want %d", len(trusted), ed25519.PublicKeySize)
	}
	msg, err := sb.signingMessage()
	if err != nil {
		return fmt.Errorf("verify superblock: %w", err)
	}
	if !ed25519.Verify(trusted, msg, sb.Signature[:]) {
		return ErrBadSignature
	}
	return nil
}

// VerifyChain checks that cur is a legitimate successor of the superblock
// encoded in prevRaw under the custody-chain rules: the predecessor must
// verify under trusted; cur must be the immediate next generation with a
// lineage hash over prevRaw — the WIRE bytes, never a re-encoding, since a
// decoder tolerating unknown fields cannot reproduce a newer writer's
// exact bytes; and cur must verify under trusted, or — only if the
// predecessor announced a successor via NextPub — under that successor
// key. Rotation a predecessor never announced is rejected: custody flows
// solely through signed NextPub announcements (compromise recovery is
// out-of-band re-pinning).
func VerifyChain(prevRaw []byte, cur *Superblock, trusted ed25519.PublicKey) error {
	if cur == nil {
		return errors.New("verify chain: nil superblock")
	}
	prev, err := Decode(prevRaw)
	if err != nil {
		return fmt.Errorf("verify chain: predecessor: %w", err)
	}
	if err := prev.Verify(trusted); err != nil {
		return fmt.Errorf("verify chain: predecessor: %w", err)
	}
	if cur.Generation != prev.Generation+1 {
		return fmt.Errorf("verify chain: generation %d does not succeed %d", cur.Generation, prev.Generation)
	}
	if want := Hash(prevRaw); cur.PrevHash != want {
		return fmt.Errorf("verify chain: lineage hash mismatch at generation %d", cur.Generation)
	}
	if err := cur.Verify(trusted); err == nil {
		return nil
	} else if !errors.Is(err, ErrBadSignature) {
		return fmt.Errorf("verify chain: %w", err)
	}
	if prev.NextPub == nil {
		return fmt.Errorf("verify chain: generation %d not signed by the trusted key and no successor was announced: %w",
			cur.Generation, ErrBadSignature)
	}
	if err := cur.Verify(ed25519.PublicKey(prev.NextPub[:])); err != nil {
		return fmt.Errorf("verify chain: generation %d not signed by the trusted key or the announced successor: %w",
			cur.Generation, err)
	}
	// Belt and braces: a rotated generation must claim the key it rotated
	// to, or lineage reporting drifts from reality.
	if !bytes.Equal(cur.SigningPub[:], prev.NextPub[:]) {
		return fmt.Errorf("verify chain: generation %d signed by the announced successor but embeds a different signing key", cur.Generation)
	}
	return nil
}
