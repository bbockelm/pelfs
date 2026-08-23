package genfs

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The graft location layer: a second answer to "where are the bytes for
// this identity", resolved against a foreign Pelican prefix instead of a
// pack in this volume (internal/graft, docs/design-graft.md).
//
// # Why it is consulted BEFORE the pack index and not after
//
// The tempting order is "try packs, fall back to grafts", and it is wrong
// on cost. packIndex.locate is only entitled to say "present in no listed
// pack" once it has indexed EVERY pack (packindex.go), so a graft-backed
// read reached that way would sweep the whole generation's trailers before
// finding its answer — per chunk, on a volume where grafted content is
// the common case.
//
// Consulting the graft table first is also CORRECT rather than merely
// cheap, and that is the part worth stating: identity is the same BLAKE3
// function in both layers, so an identity both layers hold names the same
// bytes. Either location serves a correct read. There is no ordering in
// which one lies.
//
// The cost of the reordering on a volume with no grafts is one nil-map
// check per chunk read.
//
// # What it may not do
//
// It may not turn a missing graft into a pack lookup. A grafted chunkref
// resolves in no pack by construction, so falling through would report
// "present in no listed pack" — a sentence that means damage everywhere
// else in this system (fsck's missing-chunk, reach's Unresolved) for a
// volume that is merely unable to reach a third party. A graft failure
// says so, naming the graft and the source.

// graftTable resolves identities against the generation's grafts.
type graftTable struct {
	entries []graftEntry
	// verify recomputes a fetched block's identity. Always unkeyed: a
	// graft on a keyed-identity (encrypted) volume is refused outright by
	// openGrafts, so there is no mode to select here.
	verify chunkid.Hasher
	stats  graftCounters
}

type graftEntry struct {
	sb    superblock.GraftEntry
	index *graft.Index
	// store is the transport for this graft's SOURCE prefix, built by the
	// caller's GraftOpener. It is a different store from fs.inner: a graft
	// is a different prefix, and often a different federation.
	store pelicanobj.Store
}

// graftCounters is what the graft tier is doing. Grafted reads are the one
// place a pelfs read leaves the volume's own prefix, so they are counted
// separately from everything else rather than folded into the chunk
// counters — "how much of this mount's traffic went to a third party" is a
// question an operator asks, and an aggregate cannot answer it.
type graftCounters struct {
	fetches  atomic.Int64
	bytes    atomic.Int64
	failures atomic.Int64
	mismatch atomic.Int64
	resolved atomic.Int64
}

// GraftStats is a snapshot of the graft tier's counters.
type GraftStats struct {
	// Grafts is how many graft roots this generation serves.
	Grafts int
	// Blocks is how many external blocks they index.
	Blocks int
	// Resolved counts chunk reads the graft table answered, Fetches the
	// ranged requests they cost and Bytes what those moved. Fetches below
	// Resolved is the arena doing its job.
	Resolved, Fetches, Bytes int64
	// Failures counts external fetches that failed, Mismatch the subset
	// that arrived and did not hash to the identity that was asked for.
	// Mismatch is the number that matters: it is the source having changed
	// under a signed generation, and it is never zero for a benign reason.
	Failures, Mismatch int64
}

// GraftStats reports the graft tier's counters since Open.
func (fs *FS) GraftStats() GraftStats {
	if fs.grafts == nil {
		return GraftStats{}
	}
	g := fs.grafts
	var blocks int
	for i := range g.entries {
		if g.entries[i].index != nil {
			blocks += g.entries[i].index.Len()
		}
	}
	return GraftStats{
		Grafts:   len(g.entries),
		Blocks:   blocks,
		Resolved: g.stats.resolved.Load(),
		Fetches:  g.stats.fetches.Load(),
		Bytes:    g.stats.bytes.Load(),
		Failures: g.stats.failures.Load(),
		Mismatch: g.stats.mismatch.Load(),
	}
}

// Grafts reports the graft roots this generation serves, for `pelfs graft
// --list` and for a mount that wants to tell a user what its reads will
// reach out to. A reader is entitled to know this BEFORE it reads: the
// signature makes the source tamper-evident, not safe.
func (fs *FS) Grafts() []superblock.GraftEntry {
	if fs.grafts == nil {
		return nil
	}
	out := make([]superblock.GraftEntry, 0, len(fs.grafts.entries))
	for i := range fs.grafts.entries {
		out = append(out, fs.grafts.entries[i].sb)
	}
	return out
}

// openGrafts loads and verifies every graft index the generation names.
//
// Failure is FATAL to the mount, deliberately, and this is the one place
// the choice is made. A graft is not a hint: it is the only record of
// where a grafted file's bytes live, so a mount that could not load one
// would answer a read error for every file under it while looking like a
// healthy volume. That is the failure mode manifest.Packs already refuses
// to have (genfs.Open, on an empty pack set), for the same reason.
func (fs *FS) openGrafts(ctx context.Context, o Options) error {
	if len(o.SB.Grafts) == 0 {
		return nil
	}
	// ENCRYPTION IS A HARD INCOMPATIBILITY, and refusing here rather than
	// at graft time is what makes it unbypassable: whatever wrote the
	// generation, no reader of an encrypted volume serves a grafted byte.
	//
	// The reason is not squeamishness about plaintext at a third party,
	// though that is true too. It is that on an encrypted volume genfs
	// CANNOT VERIFY a grafted block at all. Identity there is keyed
	// BLAKE3 under a key genfs does not hold, so identity recomputation
	// is skipped and the AES-GCM tag authenticates every entry instead
	// (see the package comment) — and a grafted block has no tag, being
	// AlgNone with key id 0. It would be the only unauthenticated byte in
	// the system, on the volume that asked hardest for authentication.
	//
	// The confidentiality argument is the same shape and is in
	// docs/design-graft.md: an encrypted volume's promise is that the
	// federation-visible surface carries nothing content- or name-derived,
	// and a graft publishes a foreign URL naming exactly what is inside.
	if len(o.DEK) > 0 || o.SB.CatalogKeyID != 0 {
		return fmt.Errorf("genfs: this generation names %d graft(s) and the volume is encrypted; "+
			"grafted blocks carry no AEAD tag and their identity is keyed, so nothing here can "+
			"verify them (docs/design-graft.md, \"Encryption\")", len(o.SB.Grafts))
	}
	if o.GraftOpener == nil {
		return fmt.Errorf("genfs: this generation names %d graft(s) but no graft opener was "+
			"supplied, so no external source may be read", len(o.SB.Grafts))
	}
	t := &graftTable{verify: chunkid.NewHasher(nil)}
	for _, g := range o.SB.Grafts {
		ix, err := graft.Fetch(ctx, o.Inner, g)
		if err != nil {
			return fmt.Errorf("genfs: %w", err)
		}
		// The mount, not the generation, decides which sources it is
		// willing to read. This is where a reader's veto lives: the
		// opener is handed the URL the signature covers and may refuse
		// it, which is the only defence against a volume whose signer
		// chose a URL the reader's network position should not fetch.
		st, err := o.GraftOpener(ctx, g.Source)
		if err != nil {
			return fmt.Errorf("genfs: graft %s: source %s: %w", g.Path, g.Source, err)
		}
		t.entries = append(t.entries, graftEntry{sb: g, index: ix, store: st})
	}
	fs.grafts = t
	return nil
}

// closeGrafts releases graft source transports.
func (fs *FS) closeGrafts() {
	if fs.grafts == nil {
		return
	}
	for i := range fs.grafts.entries {
		if c, ok := fs.grafts.entries[i].store.(io.Closer); ok {
			c.Close() //nolint:errcheck
		}
	}
}

// graftLocate finds which graft, if any, holds an identity.
func (t *graftTable) locate(id []byte) (*graftEntry, graft.Loc, bool) {
	for i := range t.entries {
		e := &t.entries[i]
		if e.index == nil {
			continue
		}
		if l, ok := e.index.Lookup(id); ok {
			return e, l, true
		}
	}
	return nil, graft.Loc{}, false
}

// graftHolds reports whether the graft table can resolve an identity. It
// is what makes ContentOf's absence check graft-aware: an identity in no
// pack but in a graft is located, not missing.
func (fs *FS) graftHolds(id []byte) bool {
	if fs.grafts == nil {
		return false
	}
	_, _, ok := fs.grafts.locate(id)
	return ok
}

// readGraftChunk fetches and verifies one grafted block.
//
// Verification is UNCONDITIONAL here, where fs.verify makes it a policy
// for packed chunks. The two are not the same question. A packed chunk
// came from an object this volume wrote, under a prefix its own keys
// authorize, and the Merkle path to the superblock signature already
// covers it; skipping the recomputation trades a hash for latency on
// bytes that are already vouched for. A grafted block came from a party
// with no obligation to this volume and no signature over its content —
// the identity check is the ONLY thing standing between a changed source
// and a wrong read. There is no configuration in which it is skipped.
func (fs *FS) readGraftChunk(ctx context.Context, e *graftEntry, l graft.Loc, idHex string) ([]byte, error) {
	fs.grafts.stats.fetches.Add(1)
	rc, err := e.store.Get(ctx, l.Key, l.Off, l.Length)
	if err != nil {
		fs.grafts.stats.failures.Add(1)
		return nil, fmt.Errorf("genfs: graft %s: read %s/%s [%d,+%d): %w",
			e.sb.Path, e.sb.Source, l.Key, l.Off, l.Length, err)
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, l.Length))
	// Transfer-engine transports may report failure only at Close; never
	// swallow it (the packstore lesson, and readPackRange's comment).
	cerr := rc.Close()
	if rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		fs.grafts.stats.failures.Add(1)
		return nil, fmt.Errorf("genfs: graft %s: read %s/%s [%d,+%d): %w",
			e.sb.Path, e.sb.Source, l.Key, l.Off, l.Length, rerr)
	}
	if int64(len(buf)) != l.Length {
		fs.grafts.stats.failures.Add(1)
		return nil, fmt.Errorf("genfs: graft %s: read %s/%s [%d,+%d): short read (%d bytes) — "+
			"the source object has changed or been truncated; `pelfs graft --refresh %s` republishes it",
			e.sb.Path, e.sb.Source, l.Key, l.Off, l.Length, len(buf), e.sb.Path)
	}
	if id := fs.grafts.verify.Sum(buf); id.Hex() != idHex {
		fs.grafts.stats.failures.Add(1)
		fs.grafts.stats.mismatch.Add(1)
		// FAIL CLOSED, and say all four things a person needs: which
		// graft, which object inside it, that the SOURCE is what changed
		// rather than the volume, and what to run about it. Serving these
		// bytes is not an option — the whole of the graft's integrity
		// story is this comparison.
		return nil, fmt.Errorf("genfs: graft %s: %s/%s [%d,+%d) hashes to %s, the generation "+
			"says %s — the graft source has changed since it was spidered, so these bytes are "+
			"NOT what this volume published; run `pelfs graft --refresh %s` to republish it",
			e.sb.Path, e.sb.Source, l.Key, l.Off, l.Length, id.Hex(), idHex, e.sb.Path)
	}
	fs.grafts.stats.bytes.Add(int64(len(buf)))
	fs.grafts.stats.resolved.Add(1)
	return buf, nil
}

// graftChunkAt is readChunkAt's graft arm: arena first, then the source.
//
// It shares the arena with packed chunks and shares it BY IDENTITY, which
// is the choice worth defending. The arena's own comment calls it an
// amortizer of DECODE, and a grafted block has no decode to amortize — so
// on that argument alone it does not belong there. What it amortizes
// instead is a round trip to a third party, which is worth strictly more
// than a zstd frame, and the key is a real BLAKE3 hex digest so the
// arena's shard function (which reads only the first two characters) and
// its ghost filter (the first sixteen) stay as well distributed as they
// are for packed chunks. A synthetic key like "graft:<url>:<off>" would
// have collapsed every graft block into one shard.
//
// The sizing argument is the one this leaves open, and the design doc
// says so: the arena is a fixed reservation tuned against decode cost,
// and a graft-heavy mount is competing for it against a different
// currency.
func (fs *FS) graftChunkAt(ctx context.Context, e *graftEntry, l graft.Loc, idHex string, chunkOff int64, window []byte) error {
	buf, err := fs.readGraftChunk(ctx, e, l, idHex)
	if err != nil {
		return err
	}
	fs.arena.put(idHex, buf)
	if chunkOff < 0 || chunkOff+int64(len(window)) > int64(len(buf)) {
		return fmt.Errorf("genfs: graft %s: read of [%d,+%d) falls outside a %d-byte block",
			e.sb.Path, chunkOff, len(window), len(buf))
	}
	copy(window, buf[chunkOff:])
	return nil
}

// graftIdentities reports every identity the grafts hold, for the callers
// that need to know an identity is external rather than merely absent:
// publish's dedup exclusion and fsck's classification.
func (fs *FS) graftIdentities(fn func(idHex string)) {
	if fs.grafts == nil {
		return
	}
	for i := range fs.grafts.entries {
		ix := fs.grafts.entries[i].index
		if ix == nil {
			continue
		}
		for j := 0; j < ix.Len(); j++ {
			// packidx exposes At on the table; the index wraps it.
			fn(hex.EncodeToString(ix.KeyAt(j)))
		}
	}
}
