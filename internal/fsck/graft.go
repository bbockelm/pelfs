package fsck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/extsort"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Checking a generation that serves part of its namespace from somebody
// else's storage (internal/graft, docs/design-graft.md).
//
// # The line this file draws, which is the whole of its severity story
//
// A graft splits the objects behind a generation into two populations
// with different owners, and fsck's two severities fall out of exactly
// that split:
//
//	THE VOLUME'S OWN OBJECTS  ->  SeverityError.
//	  The graft index lives under this volume's prefix, is hash-named,
//	  and is covered by the superblock signature. If it is gone, corrupt,
//	  or says something the signed entry contradicts, the generation is
//	  wrong about itself, no reader will serve the files under it, and
//	  nobody but this volume's operator can fix it. That is damage, in
//	  the same sense a missing pack is damage.
//
//	THE SOURCE'S OBJECTS      ->  SeverityWarning.
//	  A graft source belongs to a third party with no obligation to this
//	  volume. Its objects moving is not a defect in the generation — it
//	  is the event a graft EXISTS to expose, the fix is `pelfs graft
//	  --refresh` rather than a restore, and an fsck that called it damage
//	  would turn every grafted volume's cron red the first time an
//	  upstream maintainer republished a file. cmd/pelfs/fsck.go's exit
//	  contract is built on that: an operator who wants a moved source to
//	  fail a job says --strict.
//
// Two consequences of the line are worth stating because they look
// inconsistent until the line is in view.
//
// A source object that has been DELETED is still a warning, even though
// the files behind it are unreadable and --refresh will not bring them
// back. Three reasons, and the third is the one that settles it: pelfs
// never held those bytes and never promised to keep them (the graft's
// bargain is O(0) storage, and its stated price is that availability
// becomes the product of two systems); the operator's action is the same
// as for any other source change; and fsck CANNOT TELL a deletion from a
// token that expired, a maintenance window, or a network partition at
// this reader's position. Classifying an outage as corruption is the
// mistake internal/genfs already refuses to make (grafterr.go keeps
// "unreachable" and "changed" apart, and has a test for it), and it is
// not one to make here for the sake of a louder word.
//
// A source that could not be REACHED at all is its own kind rather than
// silence, for the same reason: "I did not check" is a different claim
// from "I checked and it was fine", and a report that swallowed the
// difference would let an operator believe the second when only the
// first is true.
//
// # The index is always read; --grafts governs only the SOURCE
//
// GraftDepth is a dial on what fsck asks of a third party. It is not a
// dial on the graft index, which is read in full on every run — because
// it must be. A grafted chunkref resolves in no pack by construction, so
// without the index every grafted file is "chunk resolves in no listed
// pack", which is the sentence that means damage. Resolution is not
// optional, so the read that makes it possible is not either.
//
// That read is a bonus as well as a cost: streaming the object verifies
// it against the hash the superblock signs, which a MOUNT of a large
// graft cannot do (internal/graft/remote.go reads it by window and
// argues, correctly, that it does not need to). fsck is the one place
// that check happens.

// GraftDepth is how much of a graft's SOURCE a check touches. It is a
// cost dial with a factor of ten thousand between its ends, and the
// report says which end was used, because "100,000 objects checked by
// HEAD" and "10 TB re-read and verified" are different claims that would
// otherwise print the same word.
type GraftDepth int

const (
	// GraftHead stats each source object once — presence, size, and
	// mtime against the generation's own timestamp. It is the default:
	// one small request per OBJECT, independent of how many bytes or
	// blocks the object holds, so a 10 TB graft of 100,000 objects costs
	// 100,000 HEADs and moves no data.
	//
	// What it cannot do is catch a same-length edit, which is precisely
	// the failure docs/design-graft.md's spike demonstrates. See
	// checkSourceObject for what it does catch and why each check is
	// sound rather than approximate.
	GraftHead GraftDepth = iota
	// GraftNone touches no source at all. Grafted chunkrefs still
	// resolve and the index is still verified; only the third party is
	// left alone. For a check run where the sources are known to be
	// unreachable, or where reaching out is not wanted.
	GraftNone
	// GraftDeep re-reads every referenced external block and re-hashes
	// it against the identity the signed catalog names — the same
	// comparison a read performs, made over the whole graft instead of
	// over what someone happened to open. It moves every grafted byte
	// the namespace references and is the only mode that catches a
	// change that kept the length.
	GraftDeep
)

func (d GraftDepth) String() string {
	switch d {
	case GraftNone:
		return "none"
	case GraftDeep:
		return "deep"
	default:
		return "head"
	}
}

// ParseGraftDepth turns a flag value into a depth.
func ParseGraftDepth(s string) (GraftDepth, error) {
	switch s {
	case "none":
		return GraftNone, nil
	case "head", "":
		return GraftHead, nil
	case "deep":
		return GraftDeep, nil
	}
	return GraftHead, fmt.Errorf("fsck: --grafts must be none, head, or deep, not %q", s)
}

// graftMtimeSkew is how far ahead of this volume's clock a source's clock
// may be before its mtime is believed.
//
// The mtime test is one-sided and that is what makes it usable: it fires
// only when a source object is NEWER than the generation currently being
// checked, and the graft was spidered at or before that generation was
// created, so an object newer than the generation is an object that moved
// after it was spidered. There is no false negative to worry about (an
// older mtime simply proves nothing) and exactly one false-positive
// mechanism, a source clock running ahead — which this covers. Five
// minutes is far beyond any NTP-synced host's error and far below the
// hours-to-days that separate a real republish from the generation it
// invalidates.
const graftMtimeSkew = 5 * time.Minute

// graftOrd marks an identity-index record whose location is a GRAFT
// rather than a pack, in the top bit of the record's ordinal field.
//
// Putting grafted blocks into the SAME sorted table as packed chunks is
// what keeps fsck's memory story intact. The alternative — a resident set
// of grafted identities — is the 336 MB at 10.5 million blocks that
// internal/graft deleted a helper rather than ship. Here a grafted block
// costs the same 52-byte record on the same spill file the pack index
// already uses, resolution is the same binary search over pages the
// kernel can reclaim, and seenChunk's bit-per-position dedup covers both
// populations without knowing there are two.
const graftOrd uint32 = 1 << 31

// graftCheck is one graft root under examination.
type graftCheck struct {
	ent superblock.GraftEntry
	rdr *graft.Reader
	// src is the transport for this graft's SOURCE prefix, from
	// Options.GraftOpener. Nil when there is no opener, when the opener
	// refused this source, or when GraftDepth is GraftNone — in every
	// one of those cases the source is not touched.
	src pelicanobj.Store

	// objs is what the index says about each source object, folded as
	// the index streams past, and keys is the same set in the order the
	// stream first named them — an identity-index record locates its
	// object by ORDINAL, because a 52-byte record has no room for a
	// 60-character key and interning is what packNames already does for
	// packs.
	//
	// This is the one structure here that grows, and it grows with the
	// number of source OBJECTS — the bound the string table already
	// carries — never with blocks: about 10 MB at the 100,000 objects of
	// a realistic 10 TB graft, against the 505 MB index it came from.
	objs map[string]*graftObject
	keys []string

	// refs counts chunkrefs the walk resolved through this graft and
	// outside counts the subset whose namespace path is not under
	// ent.Path; sample keeps one of those for the message.
	refs, outside atomic.Int64
	sampleMu      sync.Mutex
	sample        string

	// blocks and objects are what the index actually held, for the
	// entry-versus-object comparison and the report; ok says the pass
	// finished, so that a graft whose index could not be read produces
	// ONE finding rather than that plus every comparison against the
	// nothing it yielded.
	blocks, objects int
	ok              bool
}

// graftObject is what an index says about one source object. The three
// length fields exist to answer a single question — "how big was this
// object when it was spidered" — which the index answers exactly only
// sometimes, and exactSize is where that is decided.
type graftObject struct {
	// ord is this object's position in keys, which is what an identity
	// record carries instead of the key itself.
	ord uint32
	// extent is the highest byte the index names in this object
	// (max off+length), covered the sum of its record lengths, and
	// maxLen the largest single record. records is how many there are.
	extent, covered, maxLen int64
	records                 int64
	// gone is set by the source sweep when the object is not there, so
	// that deep mode skips its blocks instead of making one failed
	// request per block for a fact already reported once.
	gone bool
}

// exactSize reports the object's size at spider time when the index
// proves it, which is not always.
//
// WHY IT IS NOT ALWAYS. The index collapses duplicate identities: two
// byte-identical blocks anywhere in the graft leave ONE record, at the
// lower location (internal/graft, Writer.Encode). So the records for an
// object are a SUBSET of its blocks, and max(off+length) is in general a
// lower bound on its size rather than its size. A file duplicated
// elsewhere in the tree can even own no records at all.
//
// Comparing a HEAD's size against a lower bound would report every
// deduplicated object as "the source grew", which on a software area —
// the case this feature exists for, full of identical files — would be
// most of them. So the bound is used for the comparison that stays sound
// under it (an object SHORTER than the highest byte the index names is
// short, whatever deduplication did), and equality is claimed only when
// the records prove the size:
//
//   - covered == extent: the surviving records tile [0, extent) with no
//     gap, so nothing below extent was collapsed away.
//   - extent is not a multiple of the block size: the top record is a
//     SHORT block, and only an object's final block is short — so extent
//     is where the object ended. Without this, a whole trailing block
//     could have deduplicated into another object and extent would be a
//     block-aligned undercount.
//
// The block size is the largest record when there are several (an object
// cut into more than one block has at least one full block, and the
// ladder cuts every object at a multiple of the policy floor); with a
// single record only the floor is known, which is enough — a lone record
// shorter than the floor can only be a final short block at offset zero.
func (o *graftObject) exactSize(floor int64) (int64, bool) {
	if o.records == 0 || o.extent <= 0 || o.covered != o.extent {
		return 0, false
	}
	b := o.maxLen
	if o.records == 1 {
		b = floor
	}
	if b <= 0 || o.extent%b == 0 {
		return 0, false
	}
	return o.extent, true
}

// openGrafts loads every graft index the generation names, streams it
// into the identity index beside the packed chunks, and reports what the
// index says against what the signed entry says.
//
// Every failure here is damage: an index is one of THIS volume's own
// objects, so an unreadable, corrupt or contradicted one is a generation
// that is wrong about itself. The sweep continues past one — a graft
// whose index is unusable leaves its chunkrefs resolving in nothing,
// which surfaces as missing-chunk per file, and that is the truth about
// a generation whose location table cannot be read.
func (c *checker) openGrafts(ctx context.Context, sorter *extsort.Sorter) error {
	if len(c.o.SB.Grafts) == 0 {
		return nil
	}
	c.rep.Grafts = len(c.o.SB.Grafts)
	c.rep.GraftDepth = c.graftDepth()
	// ENCRYPTION IS A HARD INCOMPATIBILITY and genfs refuses to mount
	// such a generation at all (genfs.openGrafts). fsck says so rather
	// than checking on: a grafted block carries no AEAD tag and its
	// identity is keyed under a key no reader holds, so there is no
	// reader anywhere that will serve these files. That is the
	// generation contradicting itself, decidable without touching any
	// source, and not fixable by a refresh — damage.
	if c.o.SB.CatalogKeyID != 0 || len(c.o.DEK) > 0 {
		c.problem(KindGraftEntry, graftPath(c.o.SB.Grafts[0]),
			"this generation names %d graft(s) and the volume is encrypted; grafted blocks carry "+
				"no AEAD tag and their identity is keyed, so no reader can verify them and none "+
				"will mount this generation (docs/design-graft.md, \"Encryption\")",
			len(c.o.SB.Grafts))
	}
	seenPath := make(map[string]bool, len(c.o.SB.Grafts))
	for _, ent := range c.o.SB.Grafts {
		if seenPath[ent.Path] {
			// Path is REPORTAGE: nothing routes by it, because a graft is
			// consulted by identity. A duplicate makes `--list` and every
			// error message ambiguous and cannot make a read wrong.
			c.problem(KindGraftMetadata, graftPath(ent),
				"two grafts are recorded at this path; `pelfs graft --list` cannot tell them apart")
		}
		seenPath[ent.Path] = true
		g := &graftCheck{ent: ent, objs: make(map[string]*graftObject)}
		c.grafts = append(c.grafts, g)
		c.streamGraftIndex(ctx, sorter, g, len(c.grafts)-1)
		c.checkGraftEntry(g)
		c.rep.GraftBlocks += g.blocks
		c.rep.GraftObjects += g.objects
	}
	return nil
}

// streamGraftIndex walks one index, adding a record per block to the
// shared identity index and folding each block into its object.
//
// Nothing per-block is retained. The callback writes a fixed-size record
// into a batch that is handed to the external sort and then reused, and
// updates four counters on the object the block lives in — so a 10 TB
// graft's 10.5 million blocks pass through a few hundred kilobytes of
// heap on their way to a spill file.
func (c *checker) streamGraftIndex(ctx context.Context, sorter *extsort.Sorter, g *graftCheck, ord int) {
	p := graftPath(g.ent)
	if g.ent.Index == ([32]byte{}) {
		c.problem(KindGraftEntry, p, "the graft entry names no index object")
		return
	}
	g.rdr = graft.OpenReader(c.o.Inner, g.ent)
	batch := make([]byte, 0, 256*locRecLen)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := sorter.Add(batch)
		batch = batch[:0]
		return err
	}
	var addErr error
	res, err := g.rdr.Enumerate(ctx, func(b graft.Block) error {
		o := g.objs[b.Loc.Key]
		if o == nil {
			o = &graftObject{ord: uint32(len(g.keys))}
			g.objs[b.Loc.Key] = o
			g.keys = append(g.keys, b.Loc.Key)
		}
		// A block length is held in 32 bits of the record below, which
		// BlockPolicy.Validate already guarantees (it refuses a ceiling
		// over 1 GiB, because "the ceiling is the minimum verified read,
		// and a read that large is a download"). An index claiming more
		// is not one this build can index, and saying so beats silently
		// truncating a length that later fails to match a chunkref.
		if b.Loc.Length < 0 || b.Loc.Length > math.MaxUint32 || b.Loc.Off < 0 {
			return fmt.Errorf("record %d names [%d,+%d), which is not a block",
				o.records, b.Loc.Off, b.Loc.Length)
		}
		o.records++
		o.covered += b.Loc.Length
		if end := b.Loc.Off + b.Loc.Length; end > o.extent {
			o.extent = end
		}
		if b.Loc.Length > o.maxLen {
			o.maxLen = b.Loc.Length
		}
		var rec [locRecLen]byte
		putGraftLoc(rec[:], b.ID, ord, o.ord, b.Loc.Off, b.Loc.Length)
		batch = append(batch, rec[:]...)
		if len(batch) >= 256*locRecLen {
			if addErr = flush(); addErr != nil {
				return addErr
			}
		}
		return nil
	})
	if addErr == nil && err == nil {
		addErr = flush()
	}
	if addErr != nil {
		// A failure of the SORT, not of the graft. Reported as the index
		// being unusable, because that is its effect, and the sweep goes
		// on rather than aborting: fsck reports every failure.
		c.problem(KindGraftIndex, p, "indexing this graft's blocks: %v", addErr)
		return
	}
	if err != nil {
		c.problem(KindGraftIndex, p, "index %x: %v", g.ent.Index, err)
		return
	}
	g.blocks, g.objects, g.ok = res.Blocks, res.Objects, true
}

// checkGraftEntry compares the SIGNED entry against the object it names.
//
// The entry is a statement about the index and the index is a hash-named
// object, so a disagreement between them is not ambiguous: one of the two
// is not what the generation was published with. Both are damage, and the
// split between this kind and KindGraftMetadata is by CONSEQUENCE — a
// field a reader resolves through against a field only a report reads.
func (c *checker) checkGraftEntry(g *graftCheck) {
	if !g.ok {
		// The index could not be read, which is already one finding.
		// Comparing the entry against the nothing that came back would
		// add two more saying the same thing in worse words.
		return
	}
	p := graftPath(g.ent)
	if g.ent.Blocks != uint64(g.blocks) {
		// Not cosmetic: remote.go sizes a windowed reader's first request
		// from this number, so a wrong one costs every mount an extra
		// round trip at best.
		c.problem(KindGraftEntry, p, "the graft entry says %d blocks, its index holds %d",
			g.ent.Blocks, g.blocks)
	}
	// Objects is omitempty, so zero means a generation published before
	// the field existed rather than a claim of no objects.
	if g.ent.Objects != 0 && g.ent.Objects != uint64(g.objects) {
		c.problem(KindGraftEntry, p, "the graft entry says %d source objects, its index names %d",
			g.ent.Objects, g.objects)
	}
	if err := c.graftPolicy(g).Validate(); err != nil {
		// A rule nobody resolves through: the index's own per-block
		// lengths say where each block is, so reads are unaffected. What
		// it breaks is `--refresh`, which must cut identically or every
		// identity moves.
		c.problem(KindGraftMetadata, p, "the recorded block policy is one no walk could have "+
			"used, so a refresh cannot reproduce this cut: %v", err)
	}
}

// graftPolicy is the block rule a graft entry records.
func (c *checker) graftPolicy(g *graftCheck) graft.BlockPolicy {
	return graft.BlockPolicy{
		Block:     g.ent.Block,
		Max:       g.ent.BlockMax,
		PerObject: int(g.ent.BlocksPerObject),
	}
}

// graftDepth is the depth this run will actually use. An opener is the
// gate and the depth is the dial: with no way to open a source there is
// no source check to run, whatever the caller asked for.
func (c *checker) graftDepth() GraftDepth {
	if c.o.GraftOpener == nil {
		return GraftNone
	}
	return c.o.GraftDepth
}

// checkGraftSources runs the HEAD sweep, which is the default mode's
// whole cost: one small request per source object, no bytes moved.
//
// It runs BEFORE the walk so that deep mode can skip the blocks of an
// object already known to be absent — one finding per object instead of
// one failed fetch per block.
func (c *checker) checkGraftSources(ctx context.Context) {
	if c.graftDepth() == GraftNone || len(c.grafts) == 0 {
		return
	}
	for _, g := range c.grafts {
		if !g.ok {
			continue // no index, so nothing to ask the source about
		}
		src, err := c.o.GraftOpener(ctx, g.ent.Source)
		if err != nil {
			// The reader's veto, or a transport that could not be built.
			// NOT damage and NOT a finding about the source: it is this
			// check declining to look.
			c.problem(KindGraftUnchecked, graftPath(g.ent),
				"the source %s was not opened, so nothing under this graft was checked against "+
					"it: %v", g.ent.Source, err)
			continue
		}
		g.src = src
		c.headSweep(ctx, g)
	}
}

// headSweep stats every source object the index names blocks in.
//
// Objects with no surviving records are skipped, and that is not a
// shortcut: an object all of whose blocks deduplicated into an earlier
// one is named by the string table and resolved through by nothing, so
// its absence breaks no read and reporting it would be a false alarm.
func (c *checker) headSweep(ctx context.Context, g *graftCheck) {
	keys := make([]string, 0, len(g.objs))
	for k, o := range g.objs {
		if o.records > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	workers := c.o.Workers
	if workers <= 0 {
		workers = 8
	}
	if workers > len(keys) {
		workers = len(keys)
	}
	if workers == 0 {
		return
	}
	var (
		wg   sync.WaitGroup
		next atomic.Int64
		done atomic.Int64
	)
	for range workers {
		wg.Go(func() {
			for {
				i := int(next.Add(1)) - 1
				if i >= len(keys) || ctx.Err() != nil {
					return
				}
				c.checkSourceObject(ctx, g, keys[i], g.objs[keys[i]])
				done.Add(1)
			}
		})
	}
	wg.Wait()
	c.mu.Lock()
	c.rep.GraftObjectsChecked += int(done.Load())
	c.mu.Unlock()
}

// checkSourceObject is the cheap check, on one object. Every comparison
// below is one-sided on purpose: it fires only where the index PROVES a
// disagreement, so that a source doing nothing wrong is silent.
func (c *checker) checkSourceObject(ctx context.Context, g *graftCheck, key string, o *graftObject) {
	p := graftObjectPath(g.ent, key)
	ki, err := g.src.StatKey(ctx, key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			o.gone = true
			c.problem(KindGraftSourceMissing, p,
				"%s/%s is not at the source; the %d block(s) the generation places in it cannot "+
					"be read. If it moved, `pelfs graft --refresh %s` republishes the tree as it "+
					"is now; if it was deleted, those bytes are gone from the source and pelfs "+
					"never held a copy",
				g.ent.Source, key, o.records, g.ent.Path)
			return
		}
		// "Could not ask" is not "asked and it was wrong". Keeping the
		// two apart is the same discipline genfs applies to a graft read
		// (grafterr.go): an unreachable source must never be classified
		// as changed data.
		c.problem(KindGraftUnchecked, p, "%s/%s could not be stat'd, so it was not checked: %v",
			g.ent.Source, key, err)
		return
	}
	// SOUND UNDER DEDUPLICATION: extent is a lower bound on the object's
	// size when it was spidered (exactSize explains why), so an object
	// shorter than it is short however the index was collapsed — and the
	// blocks past its end fail to read today, not eventually.
	if ki.Size < o.extent {
		c.problem(KindGraftSourceChanged, p,
			"%s/%s is %d bytes and the generation names bytes up to %d in it, so reads of its "+
				"last blocks fail now; run `pelfs graft --refresh %s`",
			g.ent.Source, key, ki.Size, o.extent, g.ent.Path)
		return
	}
	if size, ok := o.exactSize(c.graftPolicy(g).For(0)); ok && ki.Size != size {
		c.problem(KindGraftSourceChanged, p,
			"%s/%s is %d bytes, it was %d when this graft was published; run "+
				"`pelfs graft --refresh %s`",
			g.ent.Source, key, ki.Size, size, g.ent.Path)
		return
	}
	// THE ONLY SIGNAL THIS MODE HAS AGAINST A SAME-LENGTH EDIT, and it is
	// free: an object modified after the generation was created was
	// modified after it was spidered, because the spider ran first. See
	// graftMtimeSkew for why this cannot fire on a source that has not
	// moved.
	if gen := c.generationTime(); !ki.Mtime.IsZero() && !gen.IsZero() &&
		ki.Mtime.After(gen.Add(graftMtimeSkew)) {
		c.problem(KindGraftSourceChanged, p,
			"%s/%s was modified at %s, after generation %d was created at %s — it is the same "+
				"length, so whether its BYTES changed is a question only `--grafts=deep` answers; "+
				"`pelfs graft --refresh %s` republishes it either way",
			g.ent.Source, key, ki.Mtime.UTC().Format(time.RFC3339), c.o.SB.Generation,
			gen.UTC().Format(time.RFC3339), g.ent.Path)
	}
}

func (c *checker) generationTime() time.Time {
	if c.o.SB.CreatedUnixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, c.o.SB.CreatedUnixNano)
}

// noteGraftRef records that a chunkref resolved through a graft, for the
// two facts only the walk can supply: whether a graft is used at all, and
// whether the path it is recorded at is where its files actually are.
func (c *checker) noteGraftRef(loc packLoc, filePath string) {
	if loc.graft < 0 || loc.graft >= len(c.grafts) {
		return
	}
	g := c.grafts[loc.graft]
	g.refs.Add(1)
	root := g.ent.Path
	if root == "" || root == "/" {
		return
	}
	if filePath == root || strings.HasPrefix(filePath, strings.TrimSuffix(root, "/")+"/") {
		return
	}
	if g.outside.Add(1) == 1 {
		g.sampleMu.Lock()
		g.sample = filePath
		g.sampleMu.Unlock()
	}
}

// reportGraftUsage says what the walk found out about each graft. Both
// findings are warnings and both are about REPORTAGE: a graft nothing
// reads and a path that is no longer where its files are cost storage and
// confusion, never a byte.
func (c *checker) reportGraftUsage() {
	for _, g := range c.grafts {
		if !g.ok {
			continue
		}
		p := graftPath(g.ent)
		refs := g.refs.Load()
		if g.blocks > 0 && refs == 0 {
			c.problem(KindGraftUnreferenced, p,
				"this graft indexes %d block(s) in %s and the namespace references none of them; "+
					"the volume reads fine, but it is carrying a dependency on a third party "+
					"that nothing uses — `pelfs graft --remove %s` drops it",
				g.blocks, g.ent.Source, g.ent.Path)
			continue
		}
		if out := g.outside.Load(); out > 0 && out == refs {
			g.sampleMu.Lock()
			sample := g.sample
			g.sampleMu.Unlock()
			// Renaming a grafted directory moves its files without
			// touching a single identity, so Path goes stale while every
			// read keeps working. Ranked item 13 in docs/design-graft.md
			// is to re-derive it; until then this says so out loud.
			c.problem(KindGraftMetadata, p,
				"the graft is recorded at %s and every file it serves is somewhere else (%s); "+
					"the reads are correct — a grafted subtree was renamed, and only the "+
					"recorded path went stale",
				g.ent.Path, sample)
		}
	}
}

// verifyGraftChunk is deep mode's graft arm: fetch the block from the
// source and hash it against the identity the signed catalog names.
//
// It is the same comparison genfs.readGraftChunk makes on every read, run
// over the whole graft instead of over whatever someone opened — and it
// is a WARNING when it fails, where the identical failure on a packed
// chunk is damage. The bytes are a third party's; a hash that no longer
// matches is that party having republished, which is the event a graft
// exists to expose rather than a defect in this generation.
// Its findings are filed against j.path, the NAMESPACE path of the file
// that referenced the block, where the HEAD sweep files against the
// source object — deliberately, because that is what each one knows. A
// per-object finding cannot name a file (an object backs many) and a
// per-block one should not stop at the object when it knows exactly which
// file just became unreadable.
func (c *checker) verifyGraftChunk(ctx context.Context, j chunkJob, loc packLoc) {
	g := c.grafts[loc.graft]
	if g.src == nil {
		c.problem(KindGraftUnchecked, j.path,
			"chunk %s lives in graft %s, whose source was not opened", j.idHex, g.ent.Path)
		return
	}
	key := g.keyAt(loc.objOrd)
	if o := g.objs[key]; o != nil && o.gone {
		return // the object's absence is already one finding of its own
	}
	buf, err := readGraftRange(ctx, g.src, key, loc)
	if err != nil {
		c.problem(KindGraftUnchecked, j.path, "chunk %s: %s/%s [%d,+%d): %v",
			j.idHex, g.ent.Source, key, loc.off, loc.length, err)
		return
	}
	if int64(len(buf)) != loc.length {
		c.problem(KindGraftSourceChanged, j.path,
			"chunk %s: %s/%s [%d,+%d) came back %d bytes — the source object no longer covers "+
				"the range the generation names; run `pelfs graft --refresh %s`",
			j.idHex, g.ent.Source, key, loc.off, loc.length, len(buf), g.ent.Path)
		return
	}
	if id := c.hasher.Sum(buf); id.Hex() != j.idHex {
		c.problem(KindGraftSourceChanged, j.path,
			"chunk %s: %s/%s [%d,+%d) hashes to %s — these are NOT the bytes this volume "+
				"published, so a read of them fails closed; run `pelfs graft --refresh %s`",
			j.idHex, g.ent.Source, key, loc.off, loc.length, id.Hex(), g.ent.Path)
		return
	}
	c.mu.Lock()
	c.rep.GraftBlocksVerified++
	c.rep.GraftBytesVerified += int64(len(buf))
	c.mu.Unlock()
}

// readGraftRange reads one block from a source, never trusting the store
// to honour the limit it was given.
func readGraftRange(ctx context.Context, src pelicanobj.Store, key string, loc packLoc) ([]byte, error) {
	rc, err := src.Get(ctx, key, loc.off, loc.length)
	if err != nil {
		return nil, err
	}
	buf, rerr := readAllLimited(rc, loc.length)
	// Transfer-engine transports may report failure only at Close; never
	// swallow it (the packstore lesson).
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return buf, nil
}

// readAllLimited buffers at most n bytes, so a store that ignores the
// range it was given cannot hand back a whole object.
func readAllLimited(rc io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(rc, n))
}

// checkGraftChunkRef is what a grafted chunkref gets instead of
// missing-chunk. The chunkref resolved in the graft index, so the
// remaining question is whether the catalog and the index agree about
// the block — and where they do not, the generation contradicts itself.
func (c *checker) checkGraftChunkRef(r *catalog.ChunkRef, loc packLoc, idHex, filePath string) {
	g := c.grafts[loc.graft]
	if loc.length != r.CLen {
		c.problem(KindGraftBlock, filePath,
			"chunk %s is %d bytes in graft %s, the chunkref says clen %d",
			idHex, loc.length, g.ent.Path, r.CLen)
	}
	// A grafted block is a third party's bytes, stored exactly as they
	// are: no compression frame, no AEAD tag, nothing to decode. A
	// chunkref claiming otherwise names a transformation nothing applied,
	// so the block it points at cannot be turned into the file's bytes.
	if r.Alg != 0 || r.KeyID != 0 {
		c.problem(KindGraftBlock, filePath,
			"chunk %s is grafted from %s, which stores plain bytes, but the chunkref says "+
				"alg %d keyid %d", idHex, g.ent.Path, r.Alg, r.KeyID)
	}
	if r.LLen != r.CLen {
		c.problem(KindGraftBlock, filePath,
			"chunk %s is grafted, so its stored and logical lengths must be equal; the chunkref "+
				"says llen %d clen %d", idHex, r.LLen, r.CLen)
	}
}

// keyAt is the source object one identity record names. An ordinal from
// a record that outlived its graft (which nothing here can produce, but
// which a future caller could) names no object rather than panicking.
func (g *graftCheck) keyAt(ord uint32) string {
	if int(ord) >= len(g.keys) {
		return ""
	}
	return g.keys[ord]
}

// graftPath is where a graft's own findings are filed, in the key-space
// shape the rest of the report uses ("packs/<name>", "shards/<a>-<b>").
func graftPath(ent superblock.GraftEntry) string {
	return path.Join(graft.Dir, strings.TrimPrefix(ent.Path, "/"))
}

// graftObjectPath files a finding against one SOURCE object, under the
// graft that names it. The detail carries the source URL; this is the
// sortable name.
func graftObjectPath(ent superblock.GraftEntry, key string) string {
	return path.Join(graftPath(ent), key)
}

// closeGraftSources releases the transports the source sweep opened. A
// graft source is a different prefix and often a different federation, so
// each one is a connection pool of its own.
func (c *checker) closeGraftSources() {
	for _, g := range c.grafts {
		if cl, ok := g.src.(io.Closer); ok {
			cl.Close() //nolint:errcheck
		}
	}
}
