package importvol

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/bbockelm/pelfs/internal/extsort"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// defaultTargetPackSize cuts the packs a copy writes. It is repack's
// number rather than a seal's ramp, for repack's reason: this is a bulk
// rewrite with a known total, so there is nothing for a ramp to discover.
const defaultTargetPackSize = 64 << 20

// CopyOptions configures one pack copy.
type CopyOptions struct {
	// Src is the SOURCE volume's transport and SrcPacks its generation's
	// pack set, resolved through the manifest or the inline list by the
	// caller (manifest.Packs does both).
	Src      pelicanobj.Store
	SrcPacks []superblock.PackEntry
	// Dst is this volume's transport: where the new packs are uploaded.
	Dst pelicanobj.Store
	// SpoolDir is where packs are built before upload.
	SpoolDir string
	// Wants is the identity set to carry, from a Scan.
	Wants *extsort.Table
	// TargetPackSize cuts the packs this writes; zero takes the default.
	TargetPackSize int64
	// Checkpoint, when set, is written as packs seal and read on the way
	// in, so a killed import resumes instead of re-reading the source.
	Checkpoint *Checkpoint
	// Progress is called on a timer with Phase "copying".
	Progress func(Progress)
}

// CopyResult is what a copy placed.
type CopyResult struct {
	// Packs are the packs this volume now holds, for the generation's
	// pack list. They are uploaded and unreferenced until a superblock
	// names them — which is exactly why an interrupted import costs
	// nothing but garbage the next `pelfs gc` collects.
	Packs []packstore.SealedPack
	// Placed is the identities each pack holds, in the same order as
	// Packs, as the generation's multi-pack index needs them.
	Placed [][][32]byte
	// Copied and CopiedBytes are what this run moved; Resumed and
	// ResumedBytes what a previous run had already moved and this one
	// did not read again.
	Copied, Resumed           uint64
	CopiedBytes, ResumedBytes int64
	// SourcePacksRead is how many of the source's packs this run opened.
	SourcePacksRead int
	// Elapsed is wall time for the copy.
	Elapsed time.Duration
}

// Entries calls fn for every identity this copy placed, and the pack it
// landed in. It is the shape publish.ContentProvider.ProvidedEntries
// wants, and it is a callback rather than a map because at a hundred
// million objects the map is the memory problem, not the data.
func (r *CopyResult) Entries(fn func(identityHex, pack string)) {
	for i, p := range r.Packs {
		if i >= len(r.Placed) {
			return
		}
		for _, id := range r.Placed[i] {
			fn(hex.EncodeToString(id[:]), p.Name)
		}
	}
}

// Copy carries every wanted identity out of the source's packs and into
// packs of this volume's own.
//
// THE BYTES ARE COPIED STORED, and that is the property the whole
// operation rests on — the same one repack rests on. An entry is already
// compressed and already encrypted, and it is written out byte for byte,
// so this needs no data-encryption key, cannot mis-encode, and cannot
// silently change what a chunkref resolves to. Its identity still names
// its plaintext and every record that references it by identity carries
// across untouched.
//
// It is also why the operation is safe to interrupt at any point. Nothing
// written here is referenced by anything until a superblock names it, so
// a killed run leaves unreferenced objects that `pelfs gc` collects on
// its own schedule and a branch still on its previous generation.
func Copy(ctx context.Context, o CopyOptions) (*CopyResult, error) {
	if o.Wants == nil {
		return nil, fmt.Errorf("importvol: a copy needs the identity set a scan produced")
	}
	target := o.TargetPackSize
	if target <= 0 {
		target = defaultTargetPackSize
	}
	res := &CopyResult{}
	start := time.Now()

	// done is a bit per WANTED identity, indexed by its position in the
	// sorted table. It is what stops the same bytes being copied twice —
	// one identity can sit in several of the source's packs, and identity
	// IS the content, so the second copy is pure waste — and, read the
	// other way at the end, it is what proves nothing was missed.
	n := o.Wants.Len()
	done := newBitset(n)

	// A resume recovers its placements from the packs it already
	// uploaded, VERIFIED against the trailer hash it recorded, rather
	// than from a list it wrote down. The trailer is the truth about what
	// a pack holds; a list beside it could disagree with it, and would
	// then place an identity in a pack that does not hold it.
	skip := map[string]bool{}
	if o.Checkpoint != nil {
		if err := resume(ctx, o, res, done, skip); err != nil {
			return nil, err
		}
	}

	var totalBytes int64
	for _, pe := range o.SrcPacks {
		totalBytes += pe.Size
	}
	tick := newTicker(o.Progress, 5*time.Second)

	w := newPackCutter(o, res, target)
	defer w.abort()

	for i, pe := range o.SrcPacks {
		if err := checkCtx(ctx, "copying "+pe.Name); err != nil {
			return nil, err
		}
		if skip[pe.Name] {
			res.Resumed += 0 // counted from the recovered packs, not here
			res.ResumedBytes += pe.Size
			continue
		}
		entries, err := packstore.FetchTrailerVerified(ctx, o.Src, pe.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			return nil, fmt.Errorf("importvol: read the trailer of the source pack %s: %w", pe.Name, err)
		}
		res.SourcePacksRead++
		for _, e := range entries {
			id, err := parseIdentity(e.Key)
			if err != nil {
				// The source's own generation named this pack and vouched
				// for its trailer hash, so a key that is not an identity
				// means the pack changed under us. Stop rather than drop
				// an entry nobody can name.
				return nil, fmt.Errorf("importvol: source pack %s entry %q: %w", pe.Name, e.Key, err)
			}
			rec, idx, dups := o.Wants.Lookup(id[:])
			if rec == nil || done.get(idx) {
				// Not wanted (a catalog, a shard, a superblock backup, or
				// garbage the source has not repacked away), or already
				// carried out of another pack.
				continue
			}
			stored, err := readEntry(ctx, o.Src, pe.Name, e.Off, e.Length)
			if err != nil {
				return nil, fmt.Errorf("importvol: read entry %s of source pack %s: %w",
					e.Key, pe.Name, err)
			}
			if err := w.add(ctx, id, e.Key, e.Type, stored); err != nil {
				return nil, err
			}
			// THE WHOLE RUN, not just the first record. The wanted set
			// is one record per chunk REFERENCE, so an identity two
			// files share is two adjacent records — and marking only
			// one would leave the other looking uncarried, which the
			// completeness check at the end would report as missing
			// bytes on a volume that has them.
			done.setRun(idx, dups)
			res.Copied++
			res.CopiedBytes += int64(len(stored))
		}
		w.sourceDone(pe.Name)
		tick.tick(Progress{
			Phase: "copying", Done: res.CopiedBytes + res.ResumedBytes, Total: totalBytes,
			Packs: i + 1, PacksTotal: len(o.SrcPacks),
		}, false)
	}
	if err := w.close(ctx); err != nil {
		return nil, err
	}
	tick.tick(Progress{
		Phase: "copying", Done: res.CopiedBytes + res.ResumedBytes, Total: totalBytes,
		Packs: len(o.SrcPacks), PacksTotal: len(o.SrcPacks),
	}, true)

	// THE REFUSAL THAT KEEPS A SIGNED GENERATION HONEST. Every identity
	// the imported tree names had to be found in a pack the source's own
	// signed generation lists. One that was not means the source is
	// missing bytes it claims to have, and publishing anyway would sign a
	// generation with a chunkref no pack of ours can answer — discovered
	// by a reader, long after the import that caused it.
	if missing := done.unset(); len(missing) > 0 {
		var names []string
		for _, i := range missing {
			if len(names) == 3 {
				break
			}
			names = append(names, hex.EncodeToString(o.Wants.At(i)[:identityLen]))
		}
		return nil, fmt.Errorf("%w: %d of %d chunk identities are in no pack the source generation "+
			"lists (for example %v). `pelfs fsck` on the source names the files; nothing was written "+
			"to this volume's branch", ErrMissingBytes, len(missing), n, names)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// packCutter is the pack-writing half, kept apart from the loop above so
// that "when does a pack seal" is one decision in one place. It is
// repack's closeOut with a checkpoint hung off it.
type packCutter struct {
	o       CopyOptions
	res     *CopyResult
	target  int64
	w       *packstore.PackWriter
	pending [][32]byte
	// srcPending are source packs fully consumed into the OPEN
	// destination pack. They are only recorded as done once that pack
	// seals: a source pack whose last entry is still in a spool file is
	// not one a resume may skip.
	srcPending []string
}

func newPackCutter(o CopyOptions, res *CopyResult, target int64) *packCutter {
	return &packCutter{o: o, res: res, target: target}
}

func (c *packCutter) add(ctx context.Context, id [32]byte, key, typ string, stored []byte) error {
	if c.w != nil && c.w.Size() > 0 && c.w.Size()+int64(len(stored)) > c.target {
		if err := c.seal(ctx); err != nil {
			return err
		}
	}
	if c.w == nil {
		w, err := packstore.NewPackWriter(c.o.SpoolDir)
		if err != nil {
			return fmt.Errorf("importvol: create a pack spool: %w", err)
		}
		c.w = w
	}
	if err := c.w.Add(key, typ, stored); err != nil {
		return fmt.Errorf("importvol: write entry %s: %w", key, err)
	}
	c.pending = append(c.pending, id)
	return nil
}

func (c *packCutter) sourceDone(name string) { c.srcPending = append(c.srcPending, name) }

func (c *packCutter) seal(ctx context.Context) error {
	if c.w == nil {
		return nil
	}
	sp, err := c.w.Seal(ctx, c.o.Dst)
	c.w = nil
	if err != nil {
		return fmt.Errorf("importvol: upload a pack: %w", err)
	}
	c.res.Packs = append(c.res.Packs, sp)
	c.res.Placed = append(c.res.Placed, c.pending)
	c.pending = nil
	if c.o.Checkpoint != nil {
		// The ORDER matters and is the whole of the checkpoint's safety:
		// the pack is uploaded before it is recorded, and the source
		// packs it consumed are recorded only after it. A resume that
		// read this file therefore never skips a source pack whose
		// entries are not already in an uploaded, verifiable pack.
		if err := c.o.Checkpoint.notePack(sp); err != nil {
			return err
		}
		for _, name := range c.srcPending {
			if err := c.o.Checkpoint.noteSource(name); err != nil {
				return err
			}
		}
	}
	c.srcPending = nil
	return nil
}

func (c *packCutter) close(ctx context.Context) error { return c.seal(ctx) }

func (c *packCutter) abort() {
	if c.w != nil {
		c.w.Abort()
		c.w = nil
	}
}

// resume recovers what a previous run of this import already uploaded.
//
// It reads the checkpoint for the pack NAMES and then asks the packs
// themselves what they hold, verified against the trailer hash the
// checkpoint recorded. A pack that is gone — collected because the run
// that wrote it was longer ago than the volume's grace window, or deleted
// by hand — is not an error: its identities simply go back on the list to
// be copied again, which costs time and cannot cost correctness.
func resume(ctx context.Context, o CopyOptions, res *CopyResult, done *bitset, skip map[string]bool) error {
	packs, srcDone, err := o.Checkpoint.Read()
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, sp := range packs {
		entries, err := packstore.FetchTrailerVerified(ctx, o.Dst, sp.Name, sp.Size, sp.TrailerHash)
		if err != nil {
			// Gone or unverifiable. Say nothing to the caller and copy it
			// again; a resume that insisted on every pack would turn a
			// collected pack into a permanently unresumable import.
			continue
		}
		ids := make([][32]byte, 0, len(entries))
		for _, e := range entries {
			id, err := parseIdentity(e.Key)
			if err != nil {
				continue
			}
			rec, idx, dups := o.Wants.Lookup(id[:])
			if rec == nil {
				// This pack holds an identity this import does not want,
				// which means the checkpoint belongs to a different
				// import. The header check should have caught it; refuse
				// rather than build a pack list around it.
				return fmt.Errorf("importvol: the resumed pack %s holds identity %s, which this "+
					"import does not want; the checkpoint does not belong to this import",
					sp.Name, e.Key)
			}
			done.setRun(idx, dups)
			ids = append(ids, id)
			res.Resumed++
			res.ResumedBytes += e.Length
		}
		res.Packs = append(res.Packs, sp)
		res.Placed = append(res.Placed, ids)
		kept[sp.Name] = true
	}
	if len(kept) == len(packs) {
		// Every recorded pack is still there, so every source pack the
		// checkpoint calls done really is done.
		for _, name := range srcDone {
			skip[name] = true
		}
	}
	return nil
}

// parseIdentity is repack's, and stays a copy rather than an export: it
// is four lines, and the alternative is this package depending on repack
// for a hex decode.
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

// readEntry reads one stored entry out of a pack.
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

// bitset is one bit per wanted identity, indexed by its position in the
// sorted set. A map would be the obvious thing and is the wrong one: at a
// hundred million identities it is gigabytes, and this is 12 MB.
type bitset struct {
	w []uint64
	n int
}

func newBitset(n int) *bitset { return &bitset{w: make([]uint64, (n+63)/64), n: n} }

func (b *bitset) set(i int) {
	if i >= 0 && i < b.n {
		b.w[i/64] |= 1 << uint(i%64)
	}
}

// setRun marks n records from i. The wanted set keeps duplicates — one
// record per chunk reference, so an identity two files share appears
// twice — and one copy of the bytes settles the whole run.
func (b *bitset) setRun(i, n int) {
	for j := i; j < i+n; j++ {
		b.set(j)
	}
}

func (b *bitset) get(i int) bool {
	return i >= 0 && i < b.n && b.w[i/64]&(1<<uint(i%64)) != 0
}

// unset is every index still clear, ascending — the identities a copy did
// not find.
func (b *bitset) unset() []int {
	var out []int
	for i := range b.n {
		if !b.get(i) {
			out = append(out, i)
		}
	}
	sort.Ints(out)
	return out
}
