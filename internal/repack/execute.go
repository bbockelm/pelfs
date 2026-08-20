package repack

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/reach"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Executing a plan.
//
// The whole operation rests on one property of the format, and it is
// worth saying before the code: CHUNKREFS NAME IDENTITIES, NOT PLACES. A
// catalog says "this file is chunks a, b, c"; it never says which pack
// they sit in. So moving bytes between packs rewrites NOTHING in the
// namespace — not a catalog, not a shard, not the root. What has to
// change is only the structures that answer "where does identity X live":
// the pack manifest, and the multi-pack index.
//
// That is why a repack can be a small, self-contained generation rather
// than a republish of the tree. It is also why it is safe to interrupt:
// until the ref flips, everything written is unreferenced garbage that
// GC collects on its own schedule.
//
// # What it does, in order
//
//  1. Sweep, refusing to continue unless the sweep was clean. The
//     reachable set it produces decides which entries are worth carrying.
//  2. Copy each condemned pack's live entries into new packs. The bytes
//     are copied STORED — already compressed, already encrypted — so a
//     repack needs no data-encryption key and cannot corrupt content it
//     cannot read.
//  3. Write a new manifest naming the surviving packs plus the new ones.
//  4. Write one multi-pack index segment for the moved identities, listed
//     LAST so it wins over the stale entries in older segments.
//  5. Publish a superblock that condemns the old packs, and flip the ref.
//
// # What it does not do
//
// It does not retire index or manifest objects on their own account
// (Plan.Refs). Replacing the manifest wholesale already drops every
// superseded segment, and index retirement is a separate decision about
// objects whose only cost is fetch time.
//
// It does not touch catalogs, shards, or the namespace in any way. A
// repacked generation has the same tree as its parent, byte for byte, and
// a test asserts exactly that.

// ExecOptions configures Execute. The sweep half mirrors Options, because
// executing a plan means computing one first — from a sweep this call
// runs itself, for the reason Compute does.
type ExecOptions struct {
	Options

	// Refs and Branch name the mutable head this publishes onto, and
	// SigningKey signs the generation. A repack produces a signed
	// superblock like any other publisher, and is refused without a key
	// rather than producing an unsigned one.
	Refs       *refs.Store
	Branch     string
	SigningKey ed25519.PrivateKey

	// SpoolDir holds packs being built. Empty takes a temporary directory
	// removed on return.
	SpoolDir string

	// TargetPackSize cuts the rewritten packs. Zero takes the same target
	// a seal uses.
	TargetPackSize int64

	// DryRun computes and reports without writing anything. It is the
	// default for the command, and it is here rather than in the caller so
	// that "what would happen" and "what happened" come from one code
	// path.
	DryRun bool
}

// Result is what an execution did.
type Result struct {
	// Plan is what was decided. On a dry run it is the whole answer.
	Plan *Plan
	// NewPacks are the packs written, CondemnedPacks the names dropped.
	NewPacks       []packstore.SealedPack
	CondemnedPacks []string
	// MovedEntries and MovedBytes are what was actually carried, which
	// may be under the plan's estimate: an identity placed in two
	// condemned packs is carried once.
	MovedEntries, MovedBytes int64
	// ReclaimedBytes is the size of the condemned objects less what the
	// new packs cost, so it is the real figure rather than the estimate.
	ReclaimedBytes int64
	// Generation is the generation published, zero on a dry run.
	Generation uint64
	// DryRun echoes the option, so a caller reporting a Result cannot
	// present a rehearsal as a change.
	DryRun bool
}

// Execute computes a plan and carries it out.
//
// A refused plan — an incomplete sweep — is returned with no error and
// nothing done, exactly as Compute reports it: the caller decides whether
// "nothing could be decided" is worth an exit code, and this must not
// look like success at the API level by silently doing nothing.
func Execute(ctx context.Context, o ExecOptions) (*Result, error) {
	if o.Inner == nil {
		return nil, errors.New("repack: Inner is required")
	}
	if !o.DryRun {
		if o.Refs == nil || o.Branch == "" {
			return nil, errors.New("repack: Refs and Branch are required to publish")
		}
		if len(o.SigningKey) == 0 {
			return nil, errors.New("repack: a signing key is required to publish")
		}
	}
	// CollectReachable is what makes this different from a plan: the
	// executor needs the identity set, not only the counts.
	sweepOpts := o.Options
	sweepOpts.collectReachable = true
	plan, rep, err := compute(ctx, sweepOpts)
	if err != nil {
		return nil, err
	}
	defer rep.Close() //nolint:errcheck
	res := &Result{Plan: plan, DryRun: o.DryRun}
	if plan.Refused() || plan.Empty() || o.DryRun {
		return res, nil
	}
	if rep == nil || rep.Reachable == nil {
		// Unreachable: a non-refused plan came from a clean sweep, and a
		// clean sweep asked for the set produces one. Refusing rather than
		// carrying on, because the alternative is deciding what to keep
		// with no idea what is live.
		return nil, errors.New("repack: the sweep produced no reachable set; refusing to rewrite anything")
	}
	return res, execute(ctx, o, res, rep)
}

// execute is the writing half, separated so that everything above it is
// decisions and everything below it is consequences.
func execute(ctx context.Context, o ExecOptions, res *Result, rep *reach.Report) error {
	spool := o.SpoolDir
	if spool == "" {
		tmp, err := os.MkdirTemp("", "pelfs-repack-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp) //nolint:errcheck
		spool = tmp
	}

	head, err := o.Refs.Fetch(ctx, o.Branch)
	if err != nil {
		return fmt.Errorf("repack: read the branch head: %w", err)
	}
	// The plan was computed against a live set the caller supplied. If the
	// head moved since, the plan describes a volume that no longer exists
	// and its liveness numbers are stale — a pack it calls dead may be one
	// the new head references. Refused rather than rebased: rebasing means
	// re-sweeping, which is the whole operation.
	if !headMatches(o.Live, head.Superblock) {
		return fmt.Errorf("repack: %w: the branch moved to generation %d while this plan was computed",
			refs.ErrStaleFlip, head.Superblock.Generation)
	}

	// The pack set of every live generation, unioned, because a candidate
	// may be one only an older generation names. The trailer hash comes
	// from here so that what is read is verified against a SIGNED
	// statement rather than trusted — the same rule the sweep follows.
	known, err := livePacks(ctx, o.Inner, o.Live)
	if err != nil {
		return err
	}
	condemn := make(map[string]bool, len(res.Plan.Packs))
	for _, c := range res.Plan.Packs {
		condemn[c.Name] = true
	}
	moved, err := rewritePacks(ctx, o, spool, rep, condemn, known, res)
	if err != nil {
		return err
	}
	sb, raw, err := repackedSuperblock(ctx, o, head.Superblock, head.Raw, condemn, moved, res)
	if err != nil {
		return err
	}
	if err := o.Refs.Flip(ctx, o.Branch, raw, head.ETag); err != nil {
		return fmt.Errorf("repack: %w", err)
	}
	res.Generation = sb.Generation
	return nil
}

// headMatches reports whether the branch head is one of the generations
// the plan was computed over.
func headMatches(live []*superblock.Superblock, head *superblock.Superblock) bool {
	for _, sb := range live {
		if sb.Generation == head.Generation && sb.VolumeID == head.VolumeID {
			return true
		}
	}
	return false
}

// placement is where a moved identity ended up.
type placement struct {
	pack        string
	off, length int64
}

// rewritePacks copies the live entries of every condemned pack into new
// packs, and returns where each identity landed.
//
// Bytes are copied STORED, which is the property that makes this safe:
// the entry is compressed and encrypted exactly as it was, so a repack
// needs no data key, cannot mis-encode, and cannot silently change what a
// chunkref resolves to. Its identity still names its plaintext, and
// nothing that references it by identity has to be touched.
func rewritePacks(ctx context.Context, o ExecOptions, spool string, rep *reach.Report,
	condemn map[string]bool, known map[string]superblock.PackEntry, res *Result) (map[[32]byte]placement, error) {

	target := o.TargetPackSize
	if target <= 0 {
		target = defaultTargetPackSize
	}
	moved := make(map[[32]byte]placement)

	var w *packstore.PackWriter
	// pending holds the identities in the open pack, whose placements are
	// only known once it is sealed and named.
	var pending []struct {
		id  [32]byte
		off int64
		n   int64
	}
	closeOut := func() error {
		if w == nil {
			return nil
		}
		sp, err := w.Seal(ctx, o.Inner)
		w = nil
		if err != nil {
			return err
		}
		for _, p := range pending {
			moved[p.id] = placement{pack: sp.Name, off: p.off, length: p.n}
		}
		pending = pending[:0]
		res.NewPacks = append(res.NewPacks, sp)
		res.ReclaimedBytes -= sp.Size
		return nil
	}
	defer func() {
		if w != nil {
			w.Abort()
		}
	}()

	for _, c := range res.Plan.Packs {
		pe, ok := known[c.Name]
		if !ok {
			// A candidate no live generation names cannot be verified, and
			// an unverified trailer is a location map nothing vouches for.
			return nil, fmt.Errorf("repack: %s is a candidate but no live generation names it", c.Name)
		}
		entries, err := packstore.FetchTrailerVerified(ctx, o.Inner, c.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			return nil, fmt.Errorf("repack: read %s: %w", c.Name, err)
		}
		for _, e := range entries {
			id, err := parseIdentity(e.Key)
			if err != nil {
				// The sweep already refused a trailer key that is not an
				// identity, so reaching this means the pack changed under
				// us. Stop rather than drop an entry nobody can name.
				return nil, fmt.Errorf("repack: %s entry %q: %w", c.Name, e.Key, err)
			}
			if !worthCarrying(rep, id, e.Type) {
				continue
			}
			if _, dup := moved[id]; dup {
				// The same bytes in two condemned packs collapse to one
				// copy. Nothing is lost: identity IS the content.
				continue
			}
			stored, err := readEntry(ctx, o.Inner, c.Name, e.Off, e.Length)
			if err != nil {
				return nil, fmt.Errorf("repack: read %s entry %s: %w", c.Name, e.Key, err)
			}
			if w != nil && w.Size() > 0 && w.Size()+int64(len(stored)) > target {
				if err := closeOut(); err != nil {
					return nil, fmt.Errorf("repack: seal a rewritten pack: %w", err)
				}
			}
			if w == nil {
				if w, err = packstore.NewPackWriter(spool); err != nil {
					return nil, err
				}
			}
			off := w.Size()
			if err := w.Add(e.Key, e.Type, stored); err != nil {
				return nil, fmt.Errorf("repack: write %s: %w", e.Key, err)
			}
			pending = append(pending, struct {
				id  [32]byte
				off int64
				n   int64
			}{id, off, int64(len(stored))})
			res.MovedEntries++
			res.MovedBytes += int64(len(stored))
		}
		res.CondemnedPacks = append(res.CondemnedPacks, c.Name)
		res.ReclaimedBytes += c.Size
	}
	if err := closeOut(); err != nil {
		return nil, fmt.Errorf("repack: seal a rewritten pack: %w", err)
	}
	return moved, nil
}

// worthCarrying decides whether one entry survives the rewrite.
//
// Two kinds do. Anything the sweep reached is referenced by a live
// generation. And a SUPERBLOCK BACKUP is live for as long as its
// generation is, while being reachable only by scavenging — nothing names
// it by identity, so the reachable set cannot speak for it, and dropping
// it would quietly remove the disaster-recovery copy this pack was
// carrying.
func worthCarrying(rep *reach.Report, id [32]byte, typ string) bool {
	if typ == packstore.EntrySuperblock {
		return true
	}
	rec, _, _ := rep.Reachable.Lookup(id[:])
	return rec != nil
}

func parseIdentity(key string) ([32]byte, error) {
	var id [32]byte
	if len(key) != 2*len(id) {
		return id, fmt.Errorf("is %d chars, want %d hex", len(key), 2*len(id))
	}
	if _, err := hex.Decode(id[:], []byte(key)); err != nil {
		return id, err
	}
	return id, nil
}

// livePacks unions the pack sets of every live generation, resolved the
// way the sweep resolves them — through the manifest when there is one
// and the inline list otherwise.
func livePacks(ctx context.Context, obj pelicanobj.Store, live []*superblock.Superblock) (map[string]superblock.PackEntry, error) {
	out := make(map[string]superblock.PackEntry)
	for _, sb := range live {
		packs, err := manifest.Packs(ctx, obj, sb)
		if err != nil {
			return nil, fmt.Errorf("repack: resolve generation %d's pack set: %w", sb.Generation, err)
		}
		for _, pe := range packs {
			out[pe.Name] = pe
		}
	}
	return out, nil
}

func readEntry(ctx context.Context, obj pelicanobj.Store, pack string, off, length int64) ([]byte, error) {
	rc, err := obj.Get(ctx, packstore.PackDirKey+"/"+pack, off, length)
	if err != nil {
		return nil, err
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, length))
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	// Transfer-engine transports may report failure only at Close (the
	// packstore lesson); never swallow it.
	if cerr != nil {
		return nil, cerr
	}
	if int64(len(buf)) != length {
		return nil, fmt.Errorf("short read: %d of %d bytes", len(buf), length)
	}
	return buf, nil
}

// repackedSuperblock builds and signs the generation this repack
// publishes: the parent's namespace exactly, with new location structures
// and the dropped packs condemned.
func repackedSuperblock(ctx context.Context, o ExecOptions, prev *superblock.Superblock, prevRaw []byte,
	condemn map[string]bool, moved map[[32]byte]placement, res *Result) (*superblock.Superblock, []byte, error) {

	now := time.Now()
	sb := *prev
	sb.Generation = prev.Generation + 1
	sb.CreatedUnixNano = now.UnixNano()
	sb.PrevHash = superblock.Hash(prevRaw)
	sb.Signature = [64]byte{}

	// The pack set: everything the parent named that is not condemned,
	// plus what this wrote.
	prevPacks, err := manifest.Packs(ctx, o.Inner, prev)
	if err != nil {
		return nil, nil, fmt.Errorf("repack: resolve the parent's pack set: %w", err)
	}
	mb := manifest.NewBuilder()
	kept := 0
	for _, pe := range prevPacks {
		if condemn[pe.Name] {
			continue
		}
		if err := mb.Add(packstore.SealedPack{Name: pe.Name, TrailerHash: pe.TrailerHash, Size: pe.Size}); err != nil {
			return nil, nil, err
		}
		kept++
	}
	for _, sp := range res.NewPacks {
		if err := mb.Add(sp); err != nil {
			return nil, nil, err
		}
	}
	mref, err := putManifest(ctx, o.Inner, mb)
	if err != nil {
		return nil, nil, err
	}
	// One segment replaces every previous one, so all of them are
	// condemned together (see the ledger note below). A repack is rare and
	// the manifest is the authority on what exists: rewriting it whole is
	// the version that cannot leave a stale entry naming a pack this very
	// change deleted.
	sb.PackList = nil
	sb.Manifests = []superblock.ManifestRef{mref}
	sb.CondemnedManifests = condemnRefs(prev.CondemnedManifests, refNames(prev.Manifests), now, graceOf(prev))

	// One index segment for what moved, listed LAST so it wins: a Set
	// asks the newest index first, and the older segments still name the
	// packs this change deleted.
	if len(moved) > 0 {
		iref, err := putIndex(ctx, o.Inner, moved)
		if err != nil {
			return nil, nil, err
		}
		sb.PackIndexes = append(append([]superblock.IndexRef{}, prev.PackIndexes...), iref)
	}

	// The condemned ledger for the packs themselves. This is the entry
	// retention reads to keep a pack alive through the grace window for
	// readers still pinned to a generation that names it.
	sb.Condemned = condemnPacks(prev.Condemned, res.CondemnedPacks, now, graceOf(prev))

	// The root-catalog hint is a hint, verified against the identity and
	// falling back to the index — but a hint pointing into a pack this
	// change deletes is a guaranteed wasted round trip, so it is either
	// moved with the bytes or dropped.
	sb.RootCatalogHint = movedRootHint(prev, condemn, moved)

	if err := sb.Sign(o.SigningKey); err != nil {
		return nil, nil, fmt.Errorf("repack: %w", err)
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("repack: encode superblock: %w", err)
	}
	return &sb, raw, nil
}

func graceOf(sb *superblock.Superblock) time.Duration {
	return time.Duration(sb.Params.TGraceSeconds) * time.Second
}

func refNames(refs []superblock.ManifestRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name)
	}
	return out
}

// condemnPacks carries the parent's ledger forward, dropping entries past
// the grace window, and adds what this change stopped naming.
func condemnPacks(prev []superblock.CondemnedPack, dropped []string, now time.Time, grace time.Duration) []superblock.CondemnedPack {
	out := make([]superblock.CondemnedPack, 0, len(prev)+len(dropped))
	for _, c := range prev {
		if now.Sub(time.Unix(c.CondemnedAtUnix, 0)) < grace {
			out = append(out, c)
		}
	}
	for _, name := range dropped {
		out = append(out, superblock.CondemnedPack{Name: name, CondemnedAtUnix: now.Unix()})
	}
	return out
}

func condemnRefs(prev []superblock.CondemnedRef, dropped []string, now time.Time, grace time.Duration) []superblock.CondemnedRef {
	out := make([]superblock.CondemnedRef, 0, len(prev)+len(dropped))
	for _, c := range prev {
		if now.Sub(time.Unix(c.CondemnedAtUnix, 0)) < grace {
			out = append(out, c)
		}
	}
	for _, name := range dropped {
		out = append(out, superblock.CondemnedRef{Name: name, CondemnedAtUnix: now.Unix()})
	}
	return out
}

// movedRootHint follows the root catalog if this change moved it.
func movedRootHint(prev *superblock.Superblock, condemn map[string]bool, moved map[[32]byte]placement) *superblock.RootHint {
	h := prev.RootCatalogHint
	if h == nil || !condemn[h.Pack] {
		return h
	}
	if p, ok := moved[prev.RootCatalog]; ok {
		return &superblock.RootHint{Pack: p.pack, Off: p.off, Length: p.length}
	}
	return nil
}

func putManifest(ctx context.Context, obj pelicanobj.Store, b *manifest.Builder) (superblock.ManifestRef, error) {
	raw := b.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := obj.Put(ctx, manifest.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.ManifestRef{}, fmt.Errorf("repack: upload manifest: %w", err)
	}
	return superblock.ManifestRef{Name: name, Hash: hash, Size: int64(len(raw)), Packs: uint32(b.Len())}, nil
}

func putIndex(ctx context.Context, obj pelicanobj.Store, moved map[[32]byte]placement) (superblock.IndexRef, error) {
	ib := mpi.NewBuilder()
	for id, p := range moved {
		ib.Add(id, p.pack)
	}
	raw := ib.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := obj.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.IndexRef{}, fmt.Errorf("repack: upload index: %w", err)
	}
	return superblock.IndexRef{
		Name: name, Hash: hash, Size: int64(len(raw)),
		Entries: uint32(ib.Len()), Packs: uint32(ib.Packs()),
	}, nil
}
