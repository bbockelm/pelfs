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

// CondemnedPack records a pack repack removed from the pack list: the
// name and when it was condemned. Publish carries entries forward until
// they age past Params.TGraceSeconds, then drops them; GC retains
// condemned packs younger than the grace window so readers pinned to a
// recent anonymous generation keep their packs
// (docs/design-packfs.md, "Retention and GC"). This replaces walking
// lineage ancestors, whose superblocks are not reliably fetchable.
type CondemnedPack struct {
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
	// names stays live. Consolidating and retiring them is repack's job
	// and is not implemented yet.
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
