// Package publish implements the v2 publish pipeline. It reads a Source —
// a write overlay under seal, or the empty root of a new volume — and runs
// TRANSFORM (walk the tree, chunk file content, build split path catalogs
// and inode shards, append everything to packs), UPLOAD (pack seals), and
// FLIP (write the signed superblock to refs/<branch>). See
// docs/design-packfs.md, "Publish: the transactional pipeline", and on the
// catalog-native mount, where the write path is overlay + seal.
//
// Publish IS the durability step for staged content: until it runs, a
// session's writes exist only in the overlay's staging files on local
// disk. Nothing downstream of the walk changes what is published, so the
// walk is the whole of what a generation means.
//
// How much of the tree a publish touches, and the deliberate
// simplifications, each marked at its site:
//
//   - INCREMENTAL TRANSFORM, on three levels, each needing the source to
//     say what it changed. A file whose bytes are untouched keeps the
//     content records the previous generation published (ContentReuser).
//     A catalog whose whole subtree is untouched is carried forward by
//     reference rather than rebuilt (CatalogReuser), the way a git commit
//     keeps the tree objects it did not change. And a subtree whose
//     catalog is being carried is not walked at all. What remains is
//     proportional to the change: the catalogs from the changed directory
//     to the root, and nothing else. See catalogreuse.go for the safety
//     argument, which is mostly about retention.
//
//     SHARDS are the exception and still regenerate whole: they are keyed
//     by inode range across the volume, so one promoted inode changing
//     rewrites a shard, and a shard rebuild needs every promoted inode's
//     records. A subtree holding one is therefore never skipped.
//
//   - Chunk dedup is within-publish only (see packer) plus the local
//     sidecar index (dedup.go). A re-uploaded chunk is wasted bytes under
//     the same identity, never corruption.
//
//   - Holes materialize as zero bytes through the chunker instead of NULL
//     chunkref rows: content stays byte-exact, sparseness is not preserved.
//
//   - Promoted (nlink > 1) inodes keep their node row in every referencing
//     path catalog AND in their inode shard; only the content records
//     (chunkrefs, inline, xattrs) are shard-exclusive. Stat from a path
//     catalog needs no shard fetch, and the shard stays authoritative for
//     content.
package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/scratch"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// Defaults and policy constants.
const (
	// DefaultInlineMax is the inline threshold. Measured across a real
	// kernel tree (docs/design-writepath.md): inlining is what makes
	// catalogs NUMEROUS rather than large, and catalog count is what makes
	// an incremental seal cheap — at 4096 one changed file rebuilds 23% of
	// the namespace, at 1024 it rebuilds 63%.
	//
	// 2048 is the deliberate middle. Catalog bytes are the part of a seal
	// that cannot move before exit, and this halves them against 4096
	// (11.2 MiB against 19.9 on that tree) while a one-file change still
	// rebuilds only 41% of the namespace. Raising it trades exit latency
	// for read locality; lowering it trades incremental seal cost for it.
	DefaultInlineMax = 2048
	// DefaultTargetPackSize is the cut size, and since a reader fetches
	// packs WHOLE it is also the granularity of every transfer that reader
	// makes. It is the publisher's answer to "what does one small file
	// cost", which is not a question the reader can answer for itself.
	//
	// Swept against a Linux 6.6 checkout (81,690 files, 255 MiB stored) at
	// a modelled 20 ms round trip, against the same reads on coalesced
	// ranges — the floor on bytes moved:
	//
	//	cut     packs  cold mount    walk 2026 files    100 scattered files
	//	 1 MiB    256   3 GET  2.4M  1.3s 36.4M (1.0x)  2.2s  81.8M ( 2.0x)
	//	 2 MiB    131   3 GET  2.4M  0.9s 21.8M (1.1x)  1.7s  95.0M ( 3.8x)
	//	 4 MiB     65   2 GET  4.1M  0.8s 15.8M (1.3x)  1.2s 138.9M ( 8.2x)
	//	 8 MiB     33   2 GET  6.0M  0.8s 20.4M (2.5x)  1.0s 197.5M (15.0x)
	//	16 MiB     17   2 GET 13.6M  0.7s 36.0M (4.7x)  1.0s 245.6M (19.3x)
	//	64 MiB      5   3 GET 62.5M  0.7s 66.8M (11.0x) 0.6s 195.7M (17.5x)
	//
	// The multipliers are against that floor. The walk — the workload the
	// whole-pack policy exists for — runs about 40x faster than ranged
	// reads at every cut size, so the only open question is what those
	// bytes cost, and at 2 MiB it is 10%. The scattered case is where the
	// policy loses, and the cut size is the whole dial: a factor of two at
	// 1 MiB against a factor of seventeen at 64.
	//
	// 2 MiB is the balance point. 4 MiB moves the fewest bytes on a walk
	// and suits a volume read in bulk; 1 MiB halves the scattered penalty
	// again for four times the objects, and below it the fixed 128 KiB
	// trailer probe starts to dominate what locating a pack costs at all.
	//
	// The cost that does not appear above: every pack is a row in this
	// generation's pack list and in every superblock after it, because
	// publish carries the list forward. 131 packs is 11 KiB of superblock;
	// the list grows as volume size over this number, so a volume orders of
	// magnitude larger wants a proportionally larger cut.
	DefaultTargetPackSize = 2 << 20
	// DefaultFirstPackSize is the size the FIRST pack is cut at; the cut
	// size then doubles until it reaches TargetPackSize. Nothing can be
	// uploaded until a whole pack exists, so a seal that only ever cuts at
	// the target leaves the uplink idle through its first packful of
	// walking and then has to drain the remainder after the walk has
	// finished. Starting small is the same trade as TCP slow start: pay a
	// handful of extra objects to stop waiting for the window to fill.
	DefaultFirstPackSize = 1 << 20
	// DefaultUploadConcurrency is how many packs may be in flight at once.
	// Each upload is one long transfer, so this is about covering round
	// trips rather than about CPU: on a bandwidth-bound uplink extra
	// streams only divide the same pipe, while on a long-fat path a single
	// stream is window-limited and cannot fill it alone.
	DefaultUploadConcurrency = 4
	// RefPrefix is the key-space directory of mutable branch heads.
	RefPrefix = "refs/"

	// entryWeight is the structural cost of one directory entry in the
	// catalog weight function W = 200·entries + inline_bytes (+ xattrs).
	entryWeight int64 = 200
	// chunkRowWeight approximates one chunkref row when sizing shards.
	chunkRowWeight int64 = 100
	// shardTargetWeight bounds one inode shard; the promoted-inode space
	// splits into contiguous ranges when it grows past this.
	shardTargetWeight int64 = 5 << 20

	// Retention defaults recorded in the superblock (design doc,
	// "Retention and GC").
	defaultRetainK uint32 = 8
)

// DefaultGrace is the T_grace a volume gets when its creator says nothing,
// and MinGrace the floor a creator may not go under. Both belong to the
// format (superblock.DefaultTGrace / MinTGrace, which is also where the
// argument for the floor lives); they are named here because the command
// offering the knob talks to this package, and a caller validating a flag
// should not have to know which package owns the field.
const (
	DefaultGrace = superblock.DefaultTGrace
	MinGrace     = superblock.MinTGrace
)

// Options configures one Publish run.
type Options struct {
	// Overlay is the write overlay this generation publishes: its merged
	// base+dirty view defines the contents. Prev is required — the
	// overlay sits over exactly that generation, which is where the
	// volume identity comes from. See Seal.
	Overlay *overlay.FS
	// OverlaySnapshot seals a frozen view instead of the live overlay.
	// A checkpoint uses this so the published generation corresponds to
	// an instant, which is the precondition for rebasing inodes back to
	// clean afterwards. Mutually exclusive with Overlay.
	OverlaySnapshot *overlay.Snapshot
	// Source publishes an arbitrary tree instead of an overlay, and is
	// mutually exclusive with both fields above. Prev is still required:
	// a generation is a successor to one, and that is where the volume
	// identity comes from.
	//
	// It exists because the overlay is one producer of a tree, not the
	// definition of one. A source that has already chunked and uploaded
	// its own content (ContentProvider) is the case that matters — the
	// write path packs during the session, and a seal of it should
	// neither read nor re-chunk what is already in packs.
	Source Source
	// Inner is the raw transport: pack uploads and the ref write.
	Inner pelicanobj.Store
	// SpoolDir holds pack spools and catalog build files.
	SpoolDir string
	// Branch is the ref name; default "main".
	Branch string
	// SigningKey signs the superblock.
	SigningKey ed25519.PrivateKey
	// IdentityKey selects keyed BLAKE3 chunk identity (encrypted volumes);
	// nil hashes unkeyed. Must be nil or 32 bytes.
	IdentityKey []byte
	// DEK encrypts pack entries (AES-256-GCM); nil writes plaintext.
	DEK []byte
	// KeyID is recorded in catalog chunkref rows when DEK is set. Key id 0
	// is reserved for plaintext.
	KeyID uint32
	// KeyTable is the prebuilt superblock key table; wrapping the DEK and
	// identity key under the user KEK is the caller's business.
	KeyTable []superblock.KeyEntry
	// Prev/PrevRaw are the previous generation and its wire bytes (for the
	// lineage hash); both nil for the first publish.
	Prev    *superblock.Superblock
	PrevRaw []byte
	// InlineMax is the inline threshold in bytes (default 4096).
	InlineMax int64
	// TargetPackSize cuts packs (default 64 MiB).
	TargetPackSize int64
	// FirstPackSize cuts the first pack, after which the cut size doubles
	// toward TargetPackSize (default DefaultFirstPackSize). Setting it to
	// TargetPackSize disables the ramp.
	FirstPackSize int64
	// UploadConcurrency bounds packs in flight; zero uses
	// DefaultUploadConcurrency. It is settable because the right number is
	// a property of the link, not of the code: a laptop on a home uplink
	// is bandwidth-bound and gains nothing past one or two, while a node
	// on a long-fat path needs several streams to fill the pipe.
	UploadConcurrency int
	// SMax overrides the catalog split threshold; zero selects
	// catalog.SMax. Tests shrink it to force nested catalogs on small trees.
	SMax int64
	// CreatedUnixNano stamps the superblock; zero reads the clock.
	CreatedUnixNano int64
	// DedupIndexPath is the local cross-generation dedup sidecar (see
	// dedup.go); empty disables it. Missing/stale/foreign indexes are
	// ignored — re-uploads are harmless duplicates.
	DedupIndexPath string
	// VolumeID identifies a volume being created by InitVolume. Every
	// other path takes identity from the previous generation.
	VolumeID [16]byte
	// Grace records T_grace on the generation this publishes
	// (Params.TGraceSeconds). Zero CARRIES THE PARENT'S FORWARD, which is
	// what every ordinary seal wants: the window is a property of the
	// volume, chosen once when it is created, and a seal that quietly
	// re-stated the build-time default would move a window readers,
	// sweepers and ledgers had all agreed on.
	//
	// So in practice only `pelfs init` sets it. Below MinGrace it is
	// refused rather than clamped (applyDefaults): a caller who asked for
	// no window at all has misunderstood what the window is for, and
	// silently giving them an hour would hide that.
	Grace time.Duration
	// SQLiteCatalogs emits catalogs as SQLite databases instead of the
	// packed static format (docs/design-catalog.md), which is the default.
	// Measured on an 80k-file tree, the static format reseals the whole
	// tree in 0.61s against 3.03s, seals a one-file change in 217ms
	// against 535ms, and lets a mount fetch 1.2 MiB instead of 1.8.
	//
	// This affects only what a publish WRITES. Catalogs are immutable and
	// content-addressed, so anything an earlier generation published stays
	// exactly as it was, and a reader picks an implementation per catalog
	// from the bytes. A volume is mixed until every subtree has been
	// touched, which is the intended migration — converting in bulk would
	// give every catalog a new identity and re-upload the whole namespace.
	SQLiteCatalogs bool
	// CatalogConcurrency bounds how many catalogs are built at once; zero
	// uses the machine's parallelism. It changes only how long the step
	// takes, never what it produces — the appends stay in plan order (see
	// writeCatalogs), which is exactly why it is settable: a test can seal
	// one tree at 1 and at N and compare the bytes.
	CatalogConcurrency int

	// emptySource selects the empty-root source (InitVolume).
	emptySource bool
}

// Stats summarizes one publish.
type Stats struct {
	Dirs, Files, Symlinks, Specials int
	InlineFiles, ChunkedFiles       int
	PromotedInodes                  int
	ChunksAdded, ChunksDeduped      int
	DedupIndexChunks                int // identities preloaded from the sidecar
	// ProvidedFiles/ProvidedChunks count content the SOURCE had already
	// chunked and uploaded, which the seal neither read nor packed. It is
	// the measure of how much of a seal the write path moved off the exit
	// path and into the session.
	ProvidedFiles, ProvidedChunks int
	// ReusedFiles/ReusedChunks count content carried forward from the
	// previous generation instead of read and re-chunked — the files this
	// seal never opened.
	ReusedFiles, ReusedChunks int
	ChunkBytes                int64
	Catalogs, Shards          int
	// CatalogsReused counts catalogs carried forward from the previous
	// generation by reference instead of rebuilt: the subtree they cover
	// did not change, so their bytes — already in a pack this generation
	// still lists — are referenced, never rewritten.
	CatalogsReused int
	// SubtreesPruned counts directories the walk stopped at: subtrees this
	// seal never read at all, because the catalog covering them is being
	// carried forward whole. It is the difference between "did not rewrite
	// the tree" and "did not look at the tree".
	SubtreesPruned int
}

// Result is a successful publish.
type Result struct {
	Superblock *superblock.Superblock
	Raw        []byte // the wire bytes written to refs/<branch>
	NewPacks   []packstore.SealedPack
	Stats      Stats
	// Upload says when the packs were on the wire, which is what turns
	// "uploads overlap packing" from a claim into something the person
	// who waited for the seal can check.
	Upload UploadReport
}

// Seal publishes a write overlay into catalogs, packs, and a signed
// superblock. Options.Overlay and Options.Prev are required; everything
// downstream of the walk is the ordinary pipeline.
func Seal(ctx context.Context, o Options) (*Result, error) {
	if o.Overlay == nil && o.OverlaySnapshot == nil {
		return nil, errors.New("publish: Seal requires Options.Overlay")
	}
	return Publish(ctx, o)
}

// Publish runs TRANSFORM/UPLOAD/FLIP over the source and returns the
// flipped generation. On error nothing mutable has changed; any packs
// already uploaded are unreferenced orphans for GC (crash analysis in the
// design doc — publish is idempotent end to end).
func Publish(ctx context.Context, o Options) (*Result, error) {
	if err := applyDefaults(&o); err != nil {
		return nil, err
	}
	src, volUUID, closeSrc, err := openSource(o)
	if err != nil {
		return nil, err
	}
	defer closeSrc()

	volID, err := parseVolumeID(volUUID)
	if err != nil {
		return nil, err
	}
	gen := uint64(0)
	if o.Prev != nil {
		gen = o.Prev.Generation + 1
		if o.Prev.VolumeID != volID {
			return nil, fmt.Errorf("publish: source volume %x does not match previous generation's %x",
				volID, o.Prev.VolumeID)
		}
	}

	// Named with this process's pid (internal/scratch), so that the next
	// mount of this state directory can tell a spool whose process died —
	// the `kill -9` mid-seal, gigabytes of packs — from one a live sibling
	// is still packing into. The `defer` below is the happy path and it is
	// the only one this process gets.
	tmpDir, err := scratch.Make(o.SpoolDir, scratch.Publish)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	p := &pipeline{
		o:           o,
		src:         src,
		pk:          newPacker(o.Inner, tmpDir, o.TargetPackSize, o.FirstPackSize, o.UploadConcurrency),
		hasher:      chunkid.NewHasher(o.IdentityKey),
		gen:         gen,
		volUUID:     volUUID,
		volID:       volID,
		tmpDir:      tmpDir,
		dirs:        make(map[uint64][]edge),
		recs:        make(map[uint64]*rec),
		chunkSeen:   make(map[chunkid.Identity]chunkInfo),
		dnIno:       make(map[*catalog.DirNode]uint64),
		pathOf:      make(map[uint64]string),
		isCatRoot:   make(map[uint64]bool),
		catIdentity: make(map[uint64]chunkid.Identity),

		subtreeDirty: make(map[uint64]bool),
		pruned:       make(map[uint64]superblock.CatalogEntry),
		carried:      make(map[uint64]superblock.CatalogEntry),
		catWeight:    make(map[uint64]int64),
		catPromoted:  make(map[uint64]int),
		catChildren:  make(map[uint64][]uint64),
	}
	defer p.pk.abort()
	// The first pack on the wire is the moment publication starts, and
	// until it was said out loud the only sign of upload activity was the
	// cost line printed after everything had already finished. Announced
	// once per publish, from the packer, so a seal that cuts a hundred
	// packs still says it once. Creating a volume is exempt: it publishes
	// one small pack of nothing, and announcing that a publication has
	// begun would be noise on the one path where nobody is waiting.
	if !o.emptySource {
		p.pk.onFirstUpload = func(d time.Duration) {
			ui.Info("publishing: the first pack is on the wire {elapsed} into this seal", "elapsed", d)
		}
	}

	// Before the walk: the walk itself skips what this settles is
	// unchanged (catalogreuse.go).
	if err := p.armReuse(); err != nil {
		return nil, err
	}
	if err := p.walk(ctx); err != nil {
		return nil, err
	}
	p.stats.SubtreesPruned = len(p.pruned)
	if err := p.loadDedupIndex(); err != nil {
		return nil, err
	}
	// The plan runs before TRANSFORM so TRANSFORM can skip the content it
	// is about to discard; see catalogreuse.go.
	if err := p.plan(); err != nil {
		return nil, err
	}
	if err := p.transform(ctx); err != nil {
		return nil, err
	}
	// After TRANSFORM, not during: a provider may still be cutting packs
	// while it answers, so the list is only complete once nothing more
	// will be asked of it.
	if cp, ok := src.(ContentProvider); ok {
		if p.providedPacks, err = cp.ProvidedPacks(ctx); err != nil {
			return nil, fmt.Errorf("publish: source packs: %w", err)
		}
	}
	shards, err := p.writeShards(ctx)
	if err != nil {
		return nil, err
	}
	rootID, err := p.writeCatalogs(ctx)
	if err != nil {
		return nil, err
	}

	// Superblock backup rides in the last pack (disaster recovery). It is
	// built before the final seal, so the pack set it names lacks the very
	// pack that carries it — rescue treats it as "the newest generation
	// minus its tail", exactly the documented fall-back-a-step behavior.
	// It states that tail INLINE and everything older through the refs it
	// carries from its parent (backupPackList). Stored raw (uncompressed,
	// unencrypted): rescue must read it before holding any keys, and the
	// KEK-wrapped key table is harmless to expose.
	_, bkRaw, err := p.buildSuperblock(p.backupPackList(), shards, rootID, p.prevPackIndexes(), p.prevManifests())
	if err != nil {
		return nil, err
	}
	bkHash := superblock.Hash(bkRaw)
	if err := p.pk.add(ctx, hex.EncodeToString(bkHash[:]), packstore.EntrySuperblock, bkRaw); err != nil {
		return nil, fmt.Errorf("publish: superblock backup: %w", err)
	}

	newPacks, err := p.pk.finish(ctx)
	if err != nil {
		return nil, fmt.Errorf("publish: seal pack: %w", err)
	}
	// After the last cut, because an entry is attributed to a pack only
	// once that pack has a name; before the flip, because a reader that
	// sees the new generation must be able to fetch what it names.
	manifests, err := p.sealManifests(ctx, newPacks)
	if err != nil {
		return nil, err
	}
	sb, raw, err := p.buildSuperblock(p.sealedPackList(newPacks, manifests), shards, rootID,
		p.sealPackIndexes(ctx), manifests)
	if err != nil {
		return nil, err
	}
	// This is the document that becomes the branch head, so it answers to
	// the writer's invariants; the backup built above is exempt from both of
	// them by construction and each says why (superblock.Validate,
	// superblock.CheckSize).
	//
	// The size is checked on the way OUT, which is the only place it can be
	// checked at all: nothing about the fields says how many bytes they came
	// to, and a superblock past the read cap is unreadable by the very
	// publish that would fix it. A refused seal costs the uploads it already
	// did and leaves the volume exactly as mountable as it was.
	if err := sb.Validate(); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}
	if err := sb.CheckSize(len(raw)); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}
	if err := flip(ctx, o, raw); err != nil {
		return nil, err
	}
	// The flip already happened: a sidecar write failure must not fail
	// the publish (the next run just re-uploads some chunks).
	if err := p.saveDedupIndex(sb.Generation); err != nil {
		ui.Warn("publish: dedup index not saved: {error}", "error", err)
	}
	return &Result{
		Superblock: sb, Raw: raw, NewPacks: newPacks, Stats: p.stats,
		Upload: p.pk.uploadReport(),
	}, nil
}

// openSource opens the tree this publish reads and reports the volume
// UUID every catalog is stamped with. An overlay does not carry the
// superblock it shadows, so its identity comes from the previous
// generation. The returned func releases source resources.
func openSource(o Options) (Source, string, func(), error) {
	if o.emptySource {
		return &emptyRoot{nextInode: 2}, formatVolumeID(o.VolumeID), func() {}, nil
	}
	if o.Source != nil {
		// A source that is not an overlay: it brings its own tree and, if
		// it implements ContentProvider, its own already-packed content.
		// The volume identity still comes from the generation being built
		// on, because that is what a generation IS a successor to.
		return o.Source, formatVolumeID(o.Prev.VolumeID), func() {}, nil
	}
	var view overlayView = o.Overlay
	if o.OverlaySnapshot != nil {
		view = o.OverlaySnapshot
	}
	// A seal reads every inode's rows, so the overlay reads its dirty
	// tables once into memory rather than answering a point query per
	// inode. It is armed here and dropped by the returned func because it
	// costs memory proportional to the dirty state, which no other caller
	// should be made to hold.
	if err := view.PrepareSeal(); err != nil {
		return nil, "", nil, fmt.Errorf("publish: prepare source: %w", err)
	}
	return &overlaySource{fs: view}, formatVolumeID(o.Prev.VolumeID), view.ReleaseSeal, nil
}

func applyDefaults(o *Options) error {
	switch {
	case o.emptySource:
		// InitVolume supplies the tree itself.
	case o.Source != nil:
		if o.Overlay != nil || o.OverlaySnapshot != nil {
			return errors.New("publish: Source and Overlay are mutually exclusive")
		}
		if o.Prev == nil {
			return errors.New("publish: sealing a Source requires Prev (the generation it succeeds)")
		}
	case o.Overlay == nil && o.OverlaySnapshot == nil:
		return errors.New("publish: Overlay, OverlaySnapshot, or Source is required")
	case o.Overlay != nil && o.OverlaySnapshot != nil:
		return errors.New("publish: Overlay and OverlaySnapshot are mutually exclusive")
	case o.Prev == nil:
		// An overlay always shadows a base generation; that generation is
		// the only place the volume identity and lineage come from.
		return errors.New("publish: sealing an overlay requires Prev (its base generation)")
	}
	if o.Inner == nil {
		return errors.New("publish: Inner store is required")
	}
	if o.SpoolDir == "" {
		return errors.New("publish: SpoolDir is required")
	}
	if o.Grace != 0 && o.Grace < MinGrace {
		return fmt.Errorf("publish: a grace window of %s is under the %s floor; the window is what makes "+
			"the sweep safe against a concurrent writer with no coordination, so a volume under it can "+
			"have its next gc delete a pack a live writer is about to reference", o.Grace, MinGrace)
	}
	if len(o.SigningKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("publish: signing key is %d bytes, want %d", len(o.SigningKey), ed25519.PrivateKeySize)
	}
	if len(o.IdentityKey) != 0 && len(o.IdentityKey) != chunkid.IdentitySize {
		return fmt.Errorf("publish: identity key is %d bytes, want nil or %d", len(o.IdentityKey), chunkid.IdentitySize)
	}
	if len(o.DEK) != 0 && len(o.DEK) != entrycodec.KeySize {
		return fmt.Errorf("publish: DEK is %d bytes, want nil or %d", len(o.DEK), entrycodec.KeySize)
	}
	if len(o.DEK) != 0 && o.KeyID == 0 {
		return errors.New("publish: KeyID 0 is reserved for plaintext; encrypted publishes need a real key id")
	}
	if (o.Prev == nil) != (len(o.PrevRaw) == 0) {
		return errors.New("publish: Prev and PrevRaw must be supplied together")
	}
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.InlineMax <= 0 {
		o.InlineMax = DefaultInlineMax
	}
	if o.TargetPackSize <= 0 {
		o.TargetPackSize = DefaultTargetPackSize
	}
	if o.FirstPackSize <= 0 {
		o.FirstPackSize = DefaultFirstPackSize
	}
	if o.SMax <= 0 {
		o.SMax = catalog.SMax
	}
	if o.CreatedUnixNano == 0 {
		o.CreatedUnixNano = time.Now().UnixNano()
	}
	return nil
}

// edge is one directory entry from the source walk.
type edge struct {
	name  string
	inode uint64
	typ   uint8 // catalog.Type*
}

// rec is everything the pipeline knows about one inode.
type rec struct {
	n        SrcNode
	xattrs   []catalog.Xattr
	symlink  []byte
	inline   []byte
	chunks   []catalog.ChunkRef
	promoted bool // nlink > 1 regular file: content records live in a shard
}

type chunkInfo struct {
	clen  int64
	alg   uint8
	keyID int64 // the key the STORED bytes were encrypted under — a
	// chunk deduped across a DEK rotation keeps its original key id
}

type pipeline struct {
	o       Options
	src     Source
	pk      *packer
	hasher  chunkid.Hasher
	gen     uint64
	volUUID string
	volID   [16]byte
	tmpDir  string

	dirs     map[uint64][]edge
	recs     map[uint64]*rec
	maxInode uint64
	promoted []uint64

	// providedPacks are the source's own packs, collected once after
	// TRANSFORM so the superblock can list what provided records name.
	providedPacks []packstore.SealedPack

	// droppedIndexes and droppedManifests are the derived refs this seal
	// STOPPED listing — consolidation's inputs, and the backup's in-flight
	// manifest segment. They accumulate as the seal runs and become the
	// superblock's condemned ledgers (condemnedrefs.go), which is what
	// stops retention deleting objects that only non-enumerable
	// generations still name.
	droppedIndexes   []string
	droppedManifests []string

	// rootLoc is where writeCatalogs appended the root catalog, or nil when
	// this publish did not write one (the whole tree was carried forward).
	// It becomes the superblock's root-catalog hint.
	rootLoc *entryLoc

	chunkSeen   map[chunkid.Identity]chunkInfo
	dnIno       map[*catalog.DirNode]uint64
	pathOf      map[uint64]string
	isCatRoot   map[uint64]bool
	catIdentity map[uint64]chunkid.Identity

	// The plan (catalogreuse.go): what this seal must build rather than
	// carry forward. reuseArmed says the source and the previous
	// generation agree on enough for any of it to be sound; with it false
	// every inode reads as dirty and the whole tree is rebuilt.
	reuseArmed   bool
	dirty        map[uint64]struct{}
	scope        map[uint64]struct{}
	baseCats     map[uint64]superblock.CatalogEntry
	pruned       map[uint64]superblock.CatalogEntry
	subtreeDirty map[uint64]bool
	carried      map[uint64]superblock.CatalogEntry
	carriedList  []superblock.CatalogEntry
	writeOrder   []uint64
	catChildren  map[uint64][]uint64
	needContent  map[uint64]bool
	catWeight    map[uint64]int64
	catPromoted  map[uint64]int

	stats Stats
}

// walk loads the source's tree into memory: per-directory edges, per-inode
// attributes, xattrs, symlink targets, and the promoted (nlink > 1) set.
// The descent is strictly parent-before-child (Readdir per directory) — the
// order a residency-by-lookup source requires; edges are sorted afterwards,
// so no source's own listing order is observable in the output.
//
// It stops at directories the plan says are being carried forward whole
// (see prunable): their contents are already published, already
// described, and reading them back only to hash them into the identical
// catalog is the whole-tree cost this pipeline exists to stop paying.
func (p *pipeline) walk(ctx context.Context) error {
	rootIno := p.src.Root()
	root, err := p.src.Stat(ctx, rootIno)
	if err != nil {
		return fmt.Errorf("publish: stat root: %w", err)
	}
	p.recs[rootIno] = &rec{n: root}
	p.pathOf[rootIno] = "/"
	p.maxInode = rootIno
	expanded := make(map[uint64]bool)
	var descend func(ino uint64, pth string) error
	descend = func(ino uint64, pth string) error {
		if expanded[ino] {
			return nil
		}
		expanded[ino] = true
		entries, err := p.src.Readdir(ctx, ino)
		if err != nil {
			return fmt.Errorf("publish: readdir inode %d: %w", ino, err)
		}
		for _, e := range entries {
			n := e.Node
			p.dirs[ino] = append(p.dirs[ino], edge{name: e.Name, inode: n.Inode, typ: n.Type})
			if n.Inode > p.maxInode {
				p.maxInode = n.Inode
			}
			if _, ok := p.recs[n.Inode]; !ok {
				p.recs[n.Inode] = &rec{n: n}
			}
			if n.Type == catalog.TypeDir {
				childPath := path.Join(pth, e.Name)
				p.pathOf[n.Inode] = childPath
				if p.pruneSubtree(n.Inode, childPath) {
					continue
				}
				if err := descend(n.Inode, childPath); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := descend(rootIno, "/"); err != nil {
		return err
	}
	// Sort edges by name so catalog row order — and therefore catalog
	// bytes and identities — is deterministic for identical trees.
	for _, es := range p.dirs {
		sort.Slice(es, func(i, j int) bool { return es[i].name < es[j].name })
	}
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		xa, err := p.src.Xattrs(ctx, ino)
		if err != nil {
			return fmt.Errorf("publish: xattrs of inode %d: %w", ino, err)
		}
		r.xattrs = sortedXattrs(xa)
		switch r.n.Type {
		case catalog.TypeDir:
			// A directory's link count is a function of the namespace
			// ("." and "..", plus one ".." per subdirectory), not a stored
			// attribute. Recomputing it from surviving edges is what makes
			// a sealed overlay — which deliberately does not maintain
			// parent link counts (internal/overlay, Mkdir) — and a
			// translated cut publish the same number.
			//
			// A pruned directory is the exception: its entries were never
			// read, so there is nothing to recompute from. The value the
			// source reported is the base generation's own node row, which
			// the base publish computed the same way over the same entries
			// — the subtree is unchanged, which is why it was pruned.
			if _, pruned := p.pruned[ino]; !pruned {
				subdirs := 0
				for _, e := range p.dirs[ino] {
					if e.typ == catalog.TypeDir {
						subdirs++
					}
				}
				r.n.Nlink = uint32(2 + subdirs)
			}
			p.stats.Dirs++
		case catalog.TypeSymlink:
			target, err := p.src.Readlink(ctx, ino)
			if err != nil {
				return fmt.Errorf("publish: readlink inode %d: %w", ino, err)
			}
			r.symlink = []byte(target)
			p.stats.Symlinks++
		case catalog.TypeFile:
			p.stats.Files++
			if r.n.Nlink > 1 {
				r.promoted = true
				p.promoted = append(p.promoted, ino)
			}
		default:
			p.stats.Specials++
		}
	}
	sort.Slice(p.promoted, func(i, j int) bool { return p.promoted[i] < p.promoted[j] })
	p.stats.PromotedInodes = len(p.promoted)
	return nil
}

// transform produces the content records this seal will actually write:
// inline bytes at or below the threshold, CDC chunk lists (with pack
// appends) above it. Files the source can prove untouched keep the
// records the previous generation already published, and are never opened
// at all; files inside a catalog being carried forward are not consulted
// at all, since the carried bytes already describe them (see the plan in
// catalogreuse.go).
func (p *pipeline) transform(ctx context.Context) error {
	reuse := p.contentReuser()
	provide, _ := p.src.(ContentProvider)
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		if r.n.Type != catalog.TypeFile || r.n.Length == 0 {
			continue
		}
		if !p.needsContent(ino) {
			// Every catalog that would hold this file's records is being
			// carried forward, records and all. Deriving them again would
			// mean proving the file untouched and fetching what the base
			// generation already says — to throw the answer away.
			continue
		}
		if reuse != nil {
			reused, err := p.reuseContent(ctx, reuse, r)
			if err != nil {
				return err
			}
			if reused {
				continue
			}
		}
		// A source that packed its own content answers before the chunker
		// is reached at all. Asked AFTER reuse, because reuse is cheaper
		// still — it costs nothing at either end, while providing has
		// already paid for chunking during the session.
		if provide != nil {
			provided, err := p.provideContent(ctx, provide, r)
			if err != nil {
				return err
			}
			if provided {
				continue
			}
		}
		if r.n.Length <= p.o.InlineMax {
			rd, err := p.src.Open(ctx, ino, r.n.Length)
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			data, err := io.ReadAll(rd)
			rd.Close() //nolint:errcheck
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			if int64(len(data)) != r.n.Length {
				return fmt.Errorf("publish: inode %d read %d bytes, want %d", ino, len(data), r.n.Length)
			}
			r.inline = data
			p.stats.InlineFiles++
			continue
		}
		refs, err := p.chunkFile(ctx, ino, r.n.Length)
		if err != nil {
			return err
		}
		r.chunks = refs
		p.stats.ChunkedFiles++
	}
	return nil
}

// contentReuser reports the source's reuse capability, but only when the
// source answers from the EXACT generation this publish grows from.
//
// That equality is the whole safety argument for carrying content records
// forward. A chunkref names bytes by identity and nothing else; the bytes
// are locatable only through the pack list of a generation that holds
// them, and buildSuperblock carries Prev's pack list forward verbatim, so
// records reused from Prev are always locatable in what is being built.
// Records from any OTHER generation could name a pack this one does not
// list — and retention (internal/retention) deletes any pack no live
// superblock names, so the result would be a signed generation that
// becomes unreadable at the next sweep, discovered by a reader long after
// the seal that caused it.
func (p *pipeline) contentReuser() ContentReuser {
	if p.o.Prev == nil {
		return nil
	}
	cr, ok := p.src.(ContentReuser)
	if !ok {
		return nil
	}
	if cr.BaseGeneration() != p.o.Prev.RootCatalog {
		return nil
	}
	return cr
}

// reuseContent installs the previous generation's records for r when the
// source vouches for them, reporting whether it did. Anything unproven
// returns false and is chunked the ordinary way: a redundant re-chunk
// costs time, a wrong content record costs the file.
func (p *pipeline) reuseContent(ctx context.Context, cr ContentReuser, r *rec) (bool, error) {
	c, ok, err := cr.ExistingContent(ctx, r.n.Inode)
	if err != nil || !ok {
		return false, err
	}
	// Length is the one fact the source's proof does not itself compare.
	// It should never disagree — every overlay path that changes a length
	// also stages content — so this is a cheap standing check that the two
	// halves of the merged view describe the same file.
	if c.Length != r.n.Length {
		return false, nil
	}
	switch inlineNow := r.n.Length <= p.o.InlineMax; {
	case c.Inline != nil && inlineNow:
		r.inline = c.Inline
		p.stats.InlineFiles++
	case c.Refs != nil && !inlineNow:
		r.chunks = c.Refs
		p.rememberReusedChunks(c.Refs)
		p.stats.ChunkedFiles++
		p.stats.ReusedChunks += len(c.Refs)
	default:
		// The inline threshold moved since the base generation, so the
		// record on hand has the wrong shape for the catalog being built.
		// Rare enough to be worth re-reading rather than special-casing.
		return false, nil
	}
	p.stats.ReusedFiles++
	return true, nil
}

// provideContent installs content the source packed itself, reporting
// whether it did. Unlike reuse, there is no generation to gate on: the
// records name packs this session uploaded, and buildSuperblock lists
// them (see ProvidedPacks). What is checked is the same standing
// agreement between the two halves of the merged view — a length that
// disagrees means the namespace and the content describe different files,
// and re-chunking is the safe answer.
func (p *pipeline) provideContent(ctx context.Context, cp ContentProvider, r *rec) (bool, error) {
	c, ok, err := cp.ProvidedContent(ctx, r.n.Inode)
	if err != nil || !ok {
		return false, err
	}
	if c.Length != r.n.Length {
		return false, nil
	}
	switch inlineNow := r.n.Length <= p.o.InlineMax; {
	case c.Inline != nil && inlineNow:
		r.inline = c.Inline
		p.stats.InlineFiles++
	case c.Refs != nil && !inlineNow:
		// The lengths must account for the whole file before the rows go in.
		// Everything else here is a mismatch between the two halves of the
		// merged view, which re-chunking settles; this one is the SOURCE
		// contradicting itself, and re-chunking cannot settle it because the
		// bytes it would read are the bytes these rows describe. A catalog
		// whose chunk lengths sum short of the node's length is a file no
		// reader will open — "chunk lengths sum to X, node length is Y" —
		// so the seal refuses to sign one instead of producing it.
		var covered int64
		for _, ref := range c.Refs {
			covered += ref.LLen
		}
		if covered != r.n.Length {
			return false, fmt.Errorf("publish: inode %d: the content source offered %d bytes of chunk "+
				"records for a %d-byte file", r.n.Inode, covered, r.n.Length)
		}
		r.chunks = c.Refs
		p.rememberReusedChunks(c.Refs)
		p.stats.ChunkedFiles++
		p.stats.ProvidedChunks += len(c.Refs)
	default:
		return false, nil
	}
	p.stats.ProvidedFiles++
	return true, nil
}

// rememberReusedChunks folds carried-forward identities into the
// within-publish dedup set. They live in packs this generation lists, so a
// NEWLY written file that happens to share one must not upload it again —
// and the sidecar index saved at the end is exactly this set, so dropping
// them would shrink the dedup domain a little more with every seal.
func (p *pipeline) rememberReusedChunks(refs []catalog.ChunkRef) {
	for _, ref := range refs {
		if len(ref.Identity) != chunkid.IdentitySize {
			continue // a hole, which stores nothing
		}
		id := chunkid.Identity(ref.Identity)
		if _, seen := p.chunkSeen[id]; seen {
			continue
		}
		p.chunkSeen[id] = chunkInfo{clen: ref.CLen, alg: uint8(ref.Alg), keyID: ref.KeyID}
	}
}

func (p *pipeline) chunkFile(ctx context.Context, ino uint64, length int64) ([]catalog.ChunkRef, error) {
	rd, err := p.src.Open(ctx, ino, length)
	if err != nil {
		return nil, fmt.Errorf("publish: read inode %d: %w", ino, err)
	}
	defer rd.Close() //nolint:errcheck
	ck := chunkid.NewChunker(rd, chunkid.Options{})
	var refs []catalog.ChunkRef
	var total int64
	for {
		c, err := ck.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("publish: chunk inode %d: %w", ino, err)
		}
		id := p.hasher.Sum(c.Data)
		info, ok := p.chunkSeen[id]
		if !ok {
			stored, alg, err := entrycodec.Encode(c.Data, p.o.DEK)
			if err != nil {
				return nil, fmt.Errorf("publish: encode chunk of inode %d: %w", ino, err)
			}
			if err := p.pk.add(ctx, id.Hex(), packstore.EntryData, stored); err != nil {
				return nil, fmt.Errorf("publish: pack chunk of inode %d: %w", ino, err)
			}
			info = chunkInfo{clen: int64(len(stored)), alg: alg, keyID: p.keyID()}
			p.chunkSeen[id] = info
			p.stats.ChunksAdded++
			p.stats.ChunkBytes += int64(len(c.Data))
		} else {
			p.stats.ChunksDeduped++
		}
		refs = append(refs, catalog.ChunkRef{
			Identity: append([]byte(nil), id[:]...),
			LLen:     int64(len(c.Data)),
			CLen:     info.clen,
			Alg:      int64(info.alg),
			KeyID:    info.keyID,
		})
		total += int64(len(c.Data))
	}
	if total != length {
		return nil, fmt.Errorf("publish: inode %d chunked %d bytes, want %d", ino, total, length)
	}
	return refs, nil
}

// writeShards partitions the promoted-inode space into contiguous ranges
// and writes one shard SQLite per range (inode-keyed tables only).
func (p *pipeline) writeShards(ctx context.Context) ([]superblock.ShardEntry, error) {
	if len(p.promoted) == 0 {
		return nil, nil
	}
	var parts [][]uint64
	var cur []uint64
	var w int64
	for _, ino := range p.promoted {
		iw := p.inodeShardWeight(ino)
		if len(cur) > 0 && w+iw > shardTargetWeight {
			parts = append(parts, cur)
			cur, w = nil, 0
		}
		cur = append(cur, ino)
		w += iw
	}
	parts = append(parts, cur)

	var out []superblock.ShardEntry
	for i, part := range parts {
		first, last := part[0], part[len(part)-1]
		fp := filepath.Join(p.tmpDir, fmt.Sprintf("shard-%d.db", i))
		cw, err := p.newCatalogBuilder(fp, catalog.Meta{
			VolumeUUID:   p.volUUID,
			CoveredPath:  fmt.Sprintf("inodes:%d-%d", first, last),
			Generation:   p.gen,
			IdentityAlgo: p.identityAlgo(),
		}, first)
		if err != nil {
			return nil, fmt.Errorf("publish: create shard: %w", err)
		}
		seen := make(map[uint64]bool)
		for _, ino := range part {
			if err := p.emitInode(cw, seen, ino, true); err != nil {
				return nil, fmt.Errorf("publish: shard inode %d: %w", ino, err)
			}
		}
		id, err := p.packCatalog(ctx, cw, packstore.EntryShard)
		if err != nil {
			return nil, fmt.Errorf("publish: pack shard: %w", err)
		}
		out = append(out, superblock.ShardEntry{FirstInode: first, LastInode: last, Identity: [32]byte(id)})
		p.stats.Shards++
	}
	return out, nil
}

// catalogBuild is one finished catalog's outcome: its identity, or why it
// has none.
type catalogBuild struct {
	id  chunkid.Identity
	err error
}

// writeCatalogs builds the catalogs the plan says are not being carried
// forward and returns the root catalog identity, which is a carried one
// when the whole tree is unchanged.
//
// Building is CONCURRENT and appending is not, and the split is what makes
// the result independent of scheduling. A catalog is a pure function of
// its own span plus the identities of the catalogs at its boundaries, and
// distinct catalogs share nothing — no rows, no files, no state — so
// several can be built at once. What they must not share is the packer:
// pack membership and entry order are the order add() is called in, so a
// generation built on a 12-core machine would otherwise lay its packs out
// differently from the same generation built on one core. The appends
// therefore run here, in p.writeOrder, exactly as they did serially.
//
// The one real dependency is the catalog tree itself: a parent records its
// children's identities, so it cannot start until they are finished.
// p.writeOrder is already descendants-before-ancestors, so dispatching in
// that order and waiting on each catalog's children is enough.
func (p *pipeline) writeCatalogs(ctx context.Context) (chunkid.Identity, error) {
	order := p.writeOrder
	pos := make(map[uint64]int, len(order))
	for i, ino := range order {
		pos[ino] = i
	}
	built := make([]catalogBuild, len(order))
	// The encoded bytes live apart from the rest so the consumer can drop
	// each one as soon as it is appended, without touching a struct the
	// dispatcher still reads identities out of.
	stored := make([][]byte, len(order))
	done := make([]chan struct{}, len(order))
	for i := range done {
		done[i] = make(chan struct{})
	}
	// A slot is taken when a build starts and given back when its bytes
	// have been appended, so the encoded catalogs held in memory at once
	// are bounded by the worker count rather than by the tree.
	sem := make(chan struct{}, p.catalogWorkers(len(order)))
	dispatched := make(chan struct{})

	go func() {
		defer close(dispatched)
		for i, ino := range order {
			childIDs := make(map[uint64]chunkid.Identity)
			var childErr error
			for _, c := range p.catChildren[ino] {
				j, building := pos[c]
				if !building {
					// A carried child: planReuse recorded its identity
					// before any of this started.
					childIDs[c] = p.catIdentity[c]
					continue
				}
				<-done[j]
				if built[j].err != nil {
					childErr = built[j].err
					break
				}
				childIDs[c] = built[j].id
			}
			sem <- struct{}{}
			go func(i int, ino uint64, childIDs map[uint64]chunkid.Identity, childErr error) {
				defer close(done[i])
				if childErr != nil {
					built[i].err = childErr
					return
				}
				built[i].id, stored[i], built[i].err = p.buildCatalog(ino, childIDs)
			}(i, ino, childIDs, childErr)
		}
	}()

	var firstErr error
	for i, ino := range order {
		<-done[i]
		entry := stored[i]
		stored[i] = nil
		<-sem
		if firstErr != nil {
			continue
		}
		if built[i].err != nil {
			firstErr = built[i].err
			continue
		}
		loc, err := p.pk.addLocated(ctx, built[i].id.Hex(), packstore.EntryCatalog, entry)
		if err != nil {
			firstErr = fmt.Errorf("publish: pack catalog %s: %w", p.pathOf[ino], err)
			continue
		}
		if ino == p.src.Root() {
			// Where the root catalog landed, for the superblock's hint. This
			// is the one moment it is known for free; a reader that had to
			// work it out would be fetching pack trailers to do it, which is
			// the cost the hint exists to skip.
			p.rootLoc = loc
		}
		p.stats.Catalogs++
	}
	// Nothing may write catIdentity while the dispatcher is still reading
	// it for carried children.
	<-dispatched
	if firstErr != nil {
		return chunkid.Identity{}, firstErr
	}
	for i, ino := range order {
		p.catIdentity[ino] = built[i].id
	}
	rootID, ok := p.catIdentity[p.src.Root()]
	if !ok {
		return chunkid.Identity{}, errors.New("publish: no catalog was produced for the tree root")
	}
	return rootID, nil
}

// defaultCatalogWorkers is how wide catalog building goes when Options
// does not say.
//
// Deliberately far below the core count, because the ceiling is not the
// cores. Most of a catalog build is the pure-Go SQLite, and every
// allocation it makes goes through one process-global mutex in
// modernc.org/libc — so the SQLite half of N builds serializes no matter
// how many goroutines run it, and past a handful the extra workers only
// spin on that lock. What DOES overlap is the rest: BLAKE3 over the
// finished file, zstd, and AES on an encrypted volume. Four covers that
// without paying for contention nobody gets anything back from.
const defaultCatalogWorkers = 4

// catalogWorkers bounds catalog building.
func (p *pipeline) catalogWorkers(catalogs int) int {
	n := p.o.CatalogConcurrency
	if n <= 0 {
		n = min(runtime.GOMAXPROCS(0), defaultCatalogWorkers)
	}
	if n > catalogs {
		n = catalogs
	}
	if n < 1 {
		n = 1
	}
	return n
}

// buildDirNode computes the catalog weight tree (W = 200·entries +
// inline_bytes + xattr bytes; promoted inodes' content weight lives in
// shards, so only their entry cost counts here) and, on the same descent,
// which subtrees hold anything the source changed.
//
// The inline contribution is read off the node's LENGTH rather than off
// bytes TRANSFORM produced: a file at or below the threshold contributes
// exactly its length by definition. That is what lets the split — and
// therefore the reuse plan — run before TRANSFORM instead of after it,
// which is the whole point of the plan.
func (p *pipeline) buildDirNode(ino uint64, pth string) *catalog.DirNode {
	d := &catalog.DirNode{}
	p.dnIno[d] = ino
	p.pathOf[ino] = pth
	if ce, ok := p.pruned[ino]; ok {
		// The walk stopped here, so there is no subtree to weigh: stand in
		// for it with the weight the generation that DID walk it recorded,
		// and pin it as a catalog root, since its contents are not present
		// to be merged into anything.
		d.OwnWeight = ce.Weight
		d.Pinned = true
		p.subtreeDirty[ino] = false
		return d
	}
	d.OwnWeight = xattrBytes(p.recs[ino].xattrs)
	dirty := p.isDirty(ino)
	for _, e := range p.dirs[ino] {
		d.OwnWeight += entryWeight
		r := p.recs[e.inode]
		if p.isDirty(e.inode) {
			dirty = true
		}
		switch e.typ {
		case catalog.TypeDir:
			d.Children = append(d.Children, p.buildDirNode(e.inode, path.Join(pth, e.name)))
			if p.subtreeDirty[e.inode] {
				dirty = true
			}
		case catalog.TypeFile:
			if !r.promoted {
				d.OwnWeight += p.inlineLen(r) + xattrBytes(r.xattrs)
			}
		case catalog.TypeSymlink:
			d.OwnWeight += int64(len(r.symlink)) + xattrBytes(r.xattrs)
		default:
			d.OwnWeight += xattrBytes(r.xattrs)
		}
	}
	p.subtreeDirty[ino] = dirty
	return d
}

// inlineLen is the number of bytes a file will contribute to its
// catalog's inline table: its whole length at or below the threshold,
// nothing above it (those bytes go to packs as chunks).
func (p *pipeline) inlineLen(r *rec) int64 {
	if r.n.Type == catalog.TypeFile && r.n.Length <= p.o.InlineMax {
		return r.n.Length
	}
	return 0
}

// buildCatalog produces one catalog's identity and its encoded pack entry.
// It touches no shared mutable state — the pipeline maps it reads are
// finished by the time the plan is settled — so several may run at once;
// childIDs is this catalog's own copy of the identities at its boundaries,
// rather than a read of the shared map the caller is still filling in.
func (p *pipeline) buildCatalog(rootIno uint64, childIDs map[uint64]chunkid.Identity) (chunkid.Identity, []byte, error) {
	fp := filepath.Join(p.tmpDir, fmt.Sprintf("catalog-%d.db", rootIno))
	cw, err := p.newCatalogBuilder(fp, catalog.Meta{
		VolumeUUID:   p.volUUID,
		CoveredPath:  p.pathOf[rootIno],
		Generation:   p.gen,
		IdentityAlgo: p.identityAlgo(),
	}, rootIno)
	if err != nil {
		return chunkid.Identity{}, nil, fmt.Errorf("publish: create catalog %s: %w", p.pathOf[rootIno], err)
	}
	seen := make(map[uint64]bool)
	var emit func(ino uint64) error
	emit = func(ino uint64) error {
		if err := p.emitInode(cw, seen, ino, true); err != nil {
			return err
		}
		for _, e := range p.dirs[ino] {
			if e.typ == catalog.TypeDir && p.isCatRoot[e.inode] {
				id, ok := childIDs[e.inode]
				if !ok {
					return fmt.Errorf("child catalog %s not yet written (split order bug)", p.pathOf[e.inode])
				}
				// A transition point carries BOTH halves in the parent:
				// the dirent and node row (lookup/stat of the directory
				// itself never fetch the child catalog) and the nested
				// locator (descending into its entries does). The child
				// catalog holds the directory's entries, not its identity.
				if err := cw.AddEdge(int64(ino), []byte(e.name), int64(e.inode), catalog.TypeDir); err != nil {
					return err
				}
				if err := p.emitInode(cw, seen, e.inode, true); err != nil {
					return err
				}
				if err := cw.AddNested(int64(ino), []byte(e.name), id[:]); err != nil {
					return err
				}
				continue
			}
			ct, err := catType(e.typ)
			if err != nil {
				return err
			}
			if err := cw.AddEdge(int64(ino), []byte(e.name), int64(e.inode), ct); err != nil {
				return err
			}
			if e.typ == catalog.TypeDir {
				if err := emit(e.inode); err != nil {
					return err
				}
			} else if err := p.emitInode(cw, seen, e.inode, !p.recs[e.inode].promoted); err != nil {
				return err
			}
		}
		return nil
	}
	if err := emit(rootIno); err != nil {
		return chunkid.Identity{}, nil, fmt.Errorf("publish: catalog %s: %w", p.pathOf[rootIno], err)
	}
	id, stored, err := encodeCatalog(cw, p.hasher, p.o.DEK)
	if err != nil {
		return chunkid.Identity{}, nil, fmt.Errorf("publish: encode catalog %s: %w", p.pathOf[rootIno], err)
	}
	return id, stored, nil
}

// emitInode writes one inode's node row (once per writer) and, when
// content is true, its content records. Promoted inodes pass content=false
// in path catalogs — node row only — and content=true in their shard.
func (p *pipeline) emitInode(w catalog.Builder, seen map[uint64]bool, ino uint64, content bool) error {
	if seen[ino] {
		return nil
	}
	seen[ino] = true
	r := p.recs[ino]
	typ, err := catType(r.n.Type)
	if err != nil {
		return err
	}
	if err := w.AddNode(catalog.Node{
		Inode:   int64(ino),
		Type:    typ,
		Mode:    r.n.Mode,
		UID:     r.n.UID,
		GID:     r.n.GID,
		MtimeNS: r.n.MtimeNS,
		CtimeNS: r.n.CtimeNS,
		Nlink:   r.n.Nlink,
		Length:  r.n.Length,
		Rdev:    r.n.Rdev,
	}); err != nil {
		return err
	}
	if !content {
		return nil
	}
	for _, x := range r.xattrs {
		if err := w.AddXattr(int64(ino), x.Name, x.Value); err != nil {
			return err
		}
	}
	switch r.n.Type {
	case catalog.TypeSymlink:
		return w.SetSymlink(int64(ino), r.symlink)
	case catalog.TypeFile:
		if r.inline != nil {
			return w.SetInline(int64(ino), r.inline)
		}
		if r.chunks != nil {
			return w.AddChunks(int64(ino), r.chunks)
		}
	}
	return nil
}

// newCatalogBuilder opens a builder in whichever encoding this publish
// emits. Existing catalogs are untouched either way: they are immutable
// and content-addressed, so a volume simply holds both kinds and a
// subtree migrates the next time something in it changes.
func (p *pipeline) newCatalogBuilder(fp string, meta catalog.Meta, rootIno uint64) (catalog.Builder, error) {
	if p.o.SQLiteCatalogs {
		return catalog.Create(fp, meta)
	}
	return catalog.NewStaticWriter(meta, int64(rootIno), p.o.InlineMax), nil
}

// packCatalog encodes a catalog/shard and appends it to a pack. Always
// zstd: nested rows and the superblock carry no alg column, so the
// encoding must be fixed.
func (p *pipeline) packCatalog(ctx context.Context, cw catalog.Builder, typ string) (chunkid.Identity, error) {
	id, stored, err := encodeCatalog(cw, p.hasher, p.o.DEK)
	if err != nil {
		return chunkid.Identity{}, err
	}
	if err := p.pk.add(ctx, id.Hex(), typ, stored); err != nil {
		return chunkid.Identity{}, err
	}
	return id, nil
}

// encodeCatalog finishes a catalog/shard builder, hashes its bytes into
// an identity, and encodes the pack entry.
//
// It is deliberately free of the pipeline: everything it touches is its
// own builder and two immutable values, so catalog builds can run side by
// side. Appending to a pack is the caller's job, because that is the step
// whose ORDER is observable in the output.
func encodeCatalog(cw catalog.Builder, hasher chunkid.Hasher, dek []byte) (chunkid.Identity, []byte, error) {
	raw, err := cw.Finish()
	if err != nil {
		return chunkid.Identity{}, nil, err
	}
	id := hasher.Sum(raw)
	stored, err := entrycodec.EncodeZstd(raw, dek)
	if err != nil {
		return chunkid.Identity{}, nil, err
	}
	return id, stored, nil
}

// buildSuperblock assembles and signs one superblock. The pack list is the
// CALLER's decision, because the two documents this builds state their
// pack sets differently and only the caller knows which one it is holding:
// a branch head says it once, either inline or through manifest refs
// (sealedPackList), while the disaster-recovery backup says the tail
// inline and the rest through carried refs (backupPackList). Both rules
// live in manifest.go, next to the format decision they implement.
func (p *pipeline) buildSuperblock(packList []superblock.PackEntry, shards []superblock.ShardEntry, rootID chunkid.Identity,
	packIndexes []superblock.IndexRef, manifests []superblock.ManifestRef) (*superblock.Superblock, []byte, error) {
	// The high-water mark prefers the source's real allocator counter;
	// max-inode-seen covers only sources that keep none (Source.NextInode
	// reports 0). Never regress below the previous generation's
	// (crash-burned numbers stay burned).
	// The allocator mark. Normally inferred from the tree — max inode
	// seen, plus whatever counter the source keeps — but a source that
	// assembled its tree from elsewhere knows better than the inference
	// can (InodeMarker), because the tree then holds inodes from another
	// lineage entirely.
	var nextInode uint64
	if m, ok := p.src.(InodeMarker); ok {
		nextInode = m.InodeMark()
	} else {
		nextInode = p.maxInode + 1
		if v := p.src.NextInode(); v > nextInode {
			nextInode = v
		}
	}
	// Floored at the predecessor's either way: a branch may never reuse a
	// number it has already handed out.
	if p.o.Prev != nil && p.o.Prev.NextInode > nextInode {
		nextInode = p.o.Prev.NextInode
	}
	// Branch is stamped on BOTH documents this function builds, and the
	// BACKUP is the one it exists for. A retired generation is described
	// only by the backup its seal buried in a pack, and a backup is found by
	// looking rather than by being pointed at — so without this the only
	// thing saying which generation it describes is a number that counts
	// steps along one lineage, and both children of a fork seal N+1
	// (internal/retention/lastk.go). applyDefaults has already defaulted
	// o.Branch to "main", so every document a current writer produces
	// carries one and an empty Branch means a v0.1.0 writer.
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		VolumeID:        p.volID,
		Generation:      p.gen,
		Branch:          p.o.Branch,
		CreatedUnixNano: p.o.CreatedUnixNano,
		RootCatalog:     [32]byte(rootID),
		PackList:        packList,
		Shards:          shards,
		NextInode:       nextInode,
		Catalogs:        p.catalogList(),
		PackIndexes:     packIndexes,
		Manifests:       manifests,
		Params: superblock.Params{
			SMaxBytes:     p.o.SMax,
			SMinBytes:     catalog.SMin,
			InlineMax:     p.o.InlineMax,
			TGraceSeconds: p.graceSeconds(),
			RetainK:       defaultRetainK,
		},
		KeyTable: p.o.KeyTable,
	}
	// Maintenance state is the parent's, untouched: an ordinary publish
	// does no maintenance, and forgetting to carry it would make every
	// seal look like a volume that has never been repacked.
	if p.o.Prev != nil && p.o.Prev.Maint != nil {
		m := *p.o.Prev.Maint
		sb.Maint = &m
	}
	// Where the branch came from is the parent's too, and untouched for a
	// stronger reason than maintenance state: a seal that dropped it would
	// leave the branch unable to say what it was cut from, and a merge
	// would be back to taking its base as a hand-typed argument.
	if p.o.Prev != nil && p.o.Prev.Fork != nil {
		f := *p.o.Prev.Fork
		sb.Fork = &f
	}
	// The condemned ledgers for the derived key spaces: what this seal
	// stopped listing, plus the parent's entries still inside the grace
	// window. The clock is the generation's own CreatedUnixNano, not
	// time.Now(), so a superblock stays a pure function of its inputs.
	// Grace is the window this superblock itself states — which, since the
	// window became a per-volume parameter, is the parent's recorded value
	// and not a constant. Everything that ages a row against it reads it
	// from the document (superblock.Params.Grace), so a volume created with
	// `--grace 12h` ages its ledgers at twelve hours from the first seal.
	now := time.Unix(0, p.o.CreatedUnixNano)
	grace := sb.Params.Grace()
	sb.CondemnedIndexes = condemnLedger(p.prevCondemnedIndexes(), p.droppedIndexes, packIndexes, now, grace, "index")
	sb.CondemnedManifests = condemnLedger(p.prevCondemnedManifests(), p.droppedManifests, manifests, now, grace, "manifest")
	// And the pack ledger, which a seal only ever CARRIES — repack is its
	// sole writer. A seal that forgot it left a repack's packs protected
	// until the next checkpoint instead of for the grace window; see
	// condemnPackLedger for what that cost. The packs this document ADDS
	// are what listed-wins needs, and sealedSoFar answers that for both
	// documents this builds — the packs cut so far for the backup, all of
	// them for the head — without either caller having to say which it is.
	sb.Condemned = condemnPackLedger(p.prevCondemnedPacks(),
		addedPackNames(p.pk.sealedSoFar(), p.providedPacks), now, grace)
	sb.RootCatalogHint = p.rootCatalogHint(rootID)
	if p.o.DEK != nil {
		// Catalog/shard/backup entries have no per-entry keyid column;
		// the superblock states the one key that encrypts them all.
		sb.CatalogKeyID = p.o.KeyID
	}
	if p.o.Prev != nil {
		sb.PrevHash = superblock.Hash(p.o.PrevRaw)
	}
	// The catalog list is the one big field a seal may decline to write,
	// so it is the first thing spent when the budget runs out: a slow next
	// seal beats a superblock past the read cap, which is a volume that
	// can never be mounted or published again (superblock.TrimCatalogs).
	if n := sb.TrimCatalogs(); n > 0 {
		ui.Warn("publish: generation {gen}'s catalog list is {bytes} bytes, past its {budget}-byte share of "+
			"the superblock budget, so this generation omits it; the next seal rebuilds every catalog "+
			"instead of carrying unchanged subtrees forward",
			"gen", sb.Generation, "bytes", n, "budget", int64(superblock.CatalogBudgetBytes))
	}
	if err := sb.Sign(p.o.SigningKey); err != nil {
		return nil, nil, fmt.Errorf("publish: %w", err)
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("publish: encode superblock: %w", err)
	}
	// NO SIZE CHECK HERE. The write budget governs the object a reader
	// fetches through pelicanobj.ReadMutable — refs/<branch> and
	// tags/<name>, which are capped at 1 MiB — and this function builds two
	// documents, only one of which ever lands there. The caller that flips
	// a head checks it (Seal); the disaster-recovery backup is an entry
	// inside a pack, read by whole-pack fetch with no cap at all, and
	// checking it would refuse seals that are perfectly sound. See
	// superblock.CheckSize.
	return sb, raw, nil
}

// graceSeconds is the window this generation records, and the order of the
// three sources is the whole rule.
//
// AN EXPLICIT OPTION WINS, which in practice means `pelfs init --grace`:
// the window is chosen when the volume is created, by the person who knows
// how long their readers hold a generation.
//
// OTHERWISE THE PARENT'S VALUE IS CARRIED, and this is the half that makes
// the knob real rather than decorative. A seal that re-stated a build-time
// constant would silently move the window on every checkpoint — a volume
// created at 12h would be back at 72h one seal later, its ledgers would age
// against a window its own gc did not use, and the parameter would exist
// only in generation 0. Carrying it also means the value survives an
// upgrade that changes the default.
//
// THE DEFAULT IS THE LAST RESORT, for generation 0 of a volume whose
// creator said nothing, and for a parent that recorded nothing at all
// (which no writer has ever produced, but a zero is a zero).
//
// The FLOOR is enforced in applyDefaults, not here: this runs deep inside a
// publish that has already uploaded packs, and refusing there would refuse
// after the expensive part. A carried-forward value is not re-checked
// against the floor — it is what the volume already agreed on, and a writer
// that lowered someone's recorded window to satisfy a newer floor would be
// changing policy behind them.
func (p *pipeline) graceSeconds() int64 {
	if p.o.Grace > 0 {
		return int64(p.o.Grace / time.Second)
	}
	if p.o.Prev != nil && p.o.Prev.Params.TGraceSeconds > 0 {
		return p.o.Prev.Params.TGraceSeconds
	}
	return int64(DefaultGrace / time.Second)
}

// rootCatalogHint is where a reader should LOOK for the root catalog
// first, or nil when this publish cannot say.
//
// Two sources, in the order they are trustworthy. This publish's own
// append is exact — it put the bytes there. Otherwise the root catalog is
// one the previous generation published (nothing else can produce a root
// this seal did not write), so its hint still describes the same object,
// and only if it names the same identity: carrying a hint across a
// changed root would point a reader at the wrong bytes, which costs a
// wasted read and a fallback but is pure waste.
//
// Either way it is only a hint, never a claim. The pack a hint names is
// listed by this generation when written, but a later repack may move the
// bytes out of it without rewriting anything that names them by identity,
// so the reader verifies and falls back.
func (p *pipeline) rootCatalogHint(rootID chunkid.Identity) *superblock.RootHint {
	if p.rootLoc != nil && p.rootLoc.pack != "" {
		return &superblock.RootHint{Pack: p.rootLoc.pack, Off: p.rootLoc.off, Length: p.rootLoc.length}
	}
	if p.o.Prev != nil && p.o.Prev.RootCatalogHint != nil && p.o.Prev.RootCatalog == [32]byte(rootID) {
		h := *p.o.Prev.RootCatalogHint
		return &h
	}
	return nil
}

// flip writes the new generation to refs/<branch>. Best-effort CAS: the
// transport-level ETag If-Match guard lands with the pelicanobj wiring
// (StatKey already surfaces ETags); until then the current ref is compared
// against the generation this publish grew from, so a concurrent writer
// aborts loudly instead of being silently clobbered.
func flip(ctx context.Context, o Options, raw []byte) error {
	key := RefPrefix + o.Branch
	// The CAS reads through a store that BYPASSES federation caches, which
	// a plain read does not. A ref is the one mutable object in the
	// format, so a cached copy of it is stale by construction — and the
	// staleness is not benign here: a session that checkpoints repeatedly
	// publishes a new generation every few minutes, the cache keeps
	// serving the one before it, and the compare then fails against the
	// session's OWN last flip while blaming a concurrent writer that does
	// not exist. Every checkpoint after the first would abort at the flip,
	// having already done and uploaded all of its work.
	//
	// internal/refs bypasses caches for the same reason; publish did not,
	// which is what made this show up only under a checkpointing mount.
	inner := o.Inner
	if d, ok := pelicanobj.AsDirectReader(inner); ok {
		inner = d.DirectVariant()
	}
	if o.Prev == nil {
		if _, err := inner.StatKey(ctx, key); err == nil {
			return fmt.Errorf("publish: %s already exists; pass its current generation as Prev", key)
		}
	} else if cur, err := pelicanobj.ReadMutable(ctx, inner, key); err == nil && !bytes.Equal(cur, o.PrevRaw) {
		// A missing ref is tolerated (recovering a lost ref is legitimate);
		// a DIFFERENT ref means a concurrent writer won.
		return fmt.Errorf("publish: %s changed since the previous generation was read: %s",
			key, describeRefSkew(cur, o.Prev))
	}
	if err := o.Inner.Put(ctx, key, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("publish: flip %s: %w", key, err)
	}
	// And read it back, through the same cache-bypassing store the compare
	// used. The compare above is check-then-put, so a writer that lands
	// between the two wins by arriving later — and that used to be
	// indistinguishable from success from in here: this function returned
	// nil, the seal reported a generation, and the generation was not on the
	// branch. One extra Get of a ~1 KB object, at the end of a publish that
	// has just uploaded packs, buys the loser the news.
	if err := pelicanobj.VerifyPut(ctx, inner, key, raw); err != nil {
		if errors.Is(err, pelicanobj.ErrClobbered) {
			return fmt.Errorf("publish: %s was overwritten between this seal's check and its write "+
				"(%w); this generation may be superseded and must be considered LOST. nothing local "+
				"is gone: re-read the branch head and reseal on top of it", key, err)
		}
		return fmt.Errorf("publish: %s was written but could not be read back (%w); re-read the branch "+
			"head to see which generation it holds", key, err)
	}
	return nil
}

// describeRefSkew says WHICH generation the branch holds against the one
// this publish grew from. The bare "it changed" left no way to tell a real
// concurrent writer from a stale read of our own work without going and
// fetching the ref by hand.
func describeRefSkew(cur []byte, prev *superblock.Superblock) string {
	got, err := superblock.Decode(cur)
	if err != nil {
		return fmt.Sprintf("it holds %d bytes this session cannot parse, not generation %d", len(cur), prev.Generation)
	}
	switch {
	case got.Generation < prev.Generation:
		return fmt.Sprintf("it holds generation %d, OLDER than the generation %d this seal grew from — "+
			"a stale read rather than a concurrent writer", got.Generation, prev.Generation)
	case got.Generation == prev.Generation:
		return fmt.Sprintf("it holds a different generation %d than the one this seal grew from "+
			"(concurrent writer?)", got.Generation)
	default:
		return fmt.Sprintf("it holds generation %d, newer than the generation %d this seal grew from "+
			"(concurrent writer?)", got.Generation, prev.Generation)
	}
}

// ---- small helpers ----

func (p *pipeline) sortedInodes() []uint64 {
	out := make([]uint64, 0, len(p.recs))
	for ino := range p.recs {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (p *pipeline) keyID() int64 {
	if len(p.o.DEK) != 0 {
		return int64(p.o.KeyID)
	}
	return 0
}

func (p *pipeline) identityAlgo() string {
	if len(p.o.IdentityKey) != 0 {
		return "blake3-256-keyed"
	}
	return "blake3-256"
}

func (p *pipeline) inodeShardWeight(ino uint64) int64 {
	r := p.recs[ino]
	return entryWeight + int64(len(r.inline)) + xattrBytes(r.xattrs) + int64(len(r.chunks))*chunkRowWeight
}

func xattrBytes(xs []catalog.Xattr) int64 {
	var n int64
	for _, x := range xs {
		n += int64(len(x.Name) + len(x.Value))
	}
	return n
}

func sortedXattrs(m map[string][]byte) []catalog.Xattr {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]catalog.Xattr, 0, len(names))
	for _, name := range names {
		out = append(out, catalog.Xattr{Name: []byte(name), Value: m[name]})
	}
	return out
}

// catType range-checks a node type on its way into a catalog row. Sources
// already speak the catalog type space (see Source), so this is validation,
// not translation.
func catType(t uint8) (uint8, error) {
	switch t {
	case catalog.TypeFile, catalog.TypeDir, catalog.TypeSymlink, catalog.TypeFIFO,
		catalog.TypeBlockDev, catalog.TypeCharDev, catalog.TypeSocket:
		return t, nil
	}
	return 0, fmt.Errorf("publish: unknown inode type %d", t)
}

func parseVolumeID(uuid string) ([16]byte, error) {
	var id [16]byte
	h := strings.ReplaceAll(uuid, "-", "")
	if len(h) != 32 {
		return id, fmt.Errorf("publish: malformed volume UUID %q", uuid)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return id, fmt.Errorf("publish: malformed volume UUID %q: %w", uuid, err)
	}
	copy(id[:], b)
	return id, nil
}

// formatVolumeID renders a superblock volume id as the canonical dashed
// UUID catalog_meta records (parseVolumeID's inverse).
func formatVolumeID(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
