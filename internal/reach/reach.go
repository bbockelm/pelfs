// Package reach measures how LIVE a pack is: what fraction of the entries
// it holds some live generation still references.
//
// Several policies in docs/design-packfs.md turn on that one number and
// nothing computes it. "Retire an index whose packs are under half live",
// "repack a pack that is mostly garbage", "delete a pack nothing
// references" — all three are questions about references, and no list can
// answer them. A pack list says which packs a generation MAY read from,
// never which bytes inside them anyone still wants. Only a walk knows.
// This is git's model: packs are storage, reachability decides.
//
// It is the third of the maintenance trio. internal/fsck asks "is this
// generation intact", internal/retention asks "which whole packs may be
// deleted" by set arithmetic over pack lists, and this asks "how much of
// each pack is still worth keeping". The machinery is fsck's — an
// identity index built from verified trailers, catalogs range-read out of
// packs, decoded with the catalog DEK, spilled and opened — pointed at a
// different question, and at a SET of generations rather than one.
//
// # Conservative, and what that costs
//
// A pack wrongly reported dead is deleted and that is data loss; a pack
// wrongly reported live costs bytes until the next sweep. The two errors
// are not comparable, so the sweep is not symmetric about them: anything
// it cannot read, decode, parse or account for makes the affected packs
// count as FULLY LIVE and the whole result incomplete. There is no
// partial credit and no attempt to scope the damage — an undecodable
// catalog could reference a chunk in ANY pack of any live generation, so
// the only sound response to one is to treat the entire live pack set as
// live.
//
// That is also why the incompleteness is not a field on the report.
// Sweep returns a *Report only when the sweep was clean; when it was not,
// the report is NIL and the error is an *Incomplete carrying the
// conservative numbers. A caller who ignores the error dereferences nil
// and crashes on the spot, which is the outcome to prefer over one who
// forgets to read Report.Complete and deletes live data. The distinction
// is the API rather than a flag inside it precisely because a flag can be
// forgotten and a nil pointer cannot.
//
// # What it does not do
//
// It does not decide WHICH generations are live: the caller supplies
// head, the retain window and the tags. Retention policy lives in the ref
// layer, and a sweep that recomputed it could disagree with the GC acting
// on its answer. It does not apply the age guard on young packs either —
// that guard is what makes deletion safe against concurrent writers, and
// it belongs to whoever issues the deletes. And it reports only packs a
// live generation NAMES: a pack no live generation lists is already dead
// by list arithmetic and needs no walk to prove it.
//
// Memory is proportional to the number of entries in the live pack set,
// because the identity index is held whole — the same trade fsck makes.
// At the hundred-million-object scale the design contemplates that index
// is the thing to replace (with internal/mpi and the pack manifest), not
// the sweep around it.
package reach

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// rootInode is the volume root, as in genfs and fsck.
const rootInode int64 = 1

// defaultWorkers bounds concurrent object fetches when Options says
// nothing. Every job is a federation round trip followed by a decode, so
// the useful number is latency-bound rather than CPU-bound.
const defaultWorkers = 8

// Options configures Sweep.
type Options struct {
	// Inner is the raw transport for pack range reads.
	Inner pelicanobj.Store
	// Live is the set of generations whose references keep bytes alive:
	// the branch head, every generation still inside the retain window,
	// and every tag. The caller decides that set (see the package
	// comment); Sweep refuses an empty one, because "nothing is live"
	// is the single answer that must never be produced by accident.
	//
	// Signatures are the caller's business too, exactly as in fsck: a
	// sweep rooted in an unverified superblock proves nothing.
	Live []*superblock.Superblock
	// DEK is the unwrapped data-encryption key, needed when the
	// generations encrypt their catalogs; nil for plaintext volumes.
	DEK []byte
	// CacheDir holds catalog spill files. Empty means a temporary
	// directory removed on return. Spills are written fresh and deleted
	// after use — a cached copy is a copy the sweep has not read.
	CacheDir string
	// Workers bounds concurrent object fetches (default 8).
	Workers int
}

// Pack is one pack's liveness. Entries/Bytes describe what it holds,
// LiveEntries/LiveBytes how much of that some live generation still
// references. Bytes are STORED bytes — post-compression, post-encryption
// — because those are the bytes a repack would move and a delete would
// reclaim.
type Pack struct {
	Name string
	// Size is the whole object, trailer included: what deleting it
	// actually frees, which is always a little more than Bytes.
	Size                 int64
	Entries, LiveEntries int64
	Bytes, LiveBytes     int64
	// Indexed reports whether the pack's trailer was read and verified.
	// False means Entries and Bytes are unknown (reported as zero) and
	// the sweep is incomplete; the pack is reported fully live regardless.
	Indexed bool
}

// LiveFraction is the share of stored bytes still referenced — the number
// the repack and index-retirement thresholds are expressed in. A pack
// holding nothing counts as fully live: there is nothing to reclaim, and
// zero is the answer that gets things deleted.
func (p Pack) LiveFraction() float64 {
	if p.Bytes <= 0 {
		return 1
	}
	return float64(p.LiveBytes) / float64(p.Bytes)
}

// Report is a completed sweep. It exists only for a sweep that read
// everything it needed (see the package comment).
type Report struct {
	// Generations is how many live superblocks were swept.
	Generations int
	// Packs is every pack the live generations name, sorted by name —
	// which, pack names beginning with a creation stamp, is oldest first.
	Packs []Pack
	// Totals over Packs.
	Entries, LiveEntries int64
	Bytes, LiveBytes     int64
	// Trailers and Objects are what the sweep fetched: one trailer per
	// pack, and one object per DISTINCT catalog and inode shard across
	// every live generation. Fetched is their sum, and it is the cost of
	// the whole exercise — the number to watch when a volume grows.
	// These count logical objects, not HTTP requests: reading a trailer
	// may cost a probe and a follow-up range.
	Trailers, Objects, Fetched int
	// Unresolved counts referenced chunk identities that resolve in no
	// listed pack. It is damage — fsck's business, not this sweep's — and
	// it does not make the result unsafe: an identity present in no pack
	// contributes to no pack's liveness, so nothing here can be
	// undercounted by it.
	Unresolved int
}

// LiveFraction is the share of stored bytes across every swept pack still
// referenced by something live.
func (r *Report) LiveFraction() float64 {
	if r.Bytes <= 0 {
		return 1
	}
	return float64(r.LiveBytes) / float64(r.Bytes)
}

// Below returns the packs whose live fraction is under threshold, sorted
// by name. Below(0.5) is the design's retirement rule; Below(anything
// positive) includes the packs nothing references at all.
func (r *Report) Below(threshold float64) []Pack {
	var out []Pack
	for _, p := range r.Packs {
		if p.LiveFraction() < threshold {
			out = append(out, p)
		}
	}
	return out
}

// Failure is one thing the sweep could not read, decode or account for.
// Object names what it was about — a pack name, an object identity, a
// generation — so a report can be triaged without parsing prose.
type Failure struct {
	Object string
	Detail string
}

func (f Failure) String() string { return f.Object + ": " + f.Detail }

// Incomplete is returned INSTEAD of a report when the sweep could not
// account for everything. Its Conservative report is filled in the only
// safe direction — every pack fully live — so a caller can still show
// what the volume holds while being structurally unable to mistake it for
// a liveness measurement.
type Incomplete struct {
	// Failures lists every reason, not just the first: one unreadable
	// pack and one undecodable catalog are different repairs.
	Failures []Failure
	// Conservative reports every pack as fully live. It is a floor on
	// what must be kept, never a basis for deleting anything.
	Conservative *Report
}

func (e *Incomplete) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "reach: sweep incomplete (%d failure(s)); every pack is reported fully live", len(e.Failures))
	for i, f := range e.Failures {
		if i == 3 {
			fmt.Fprintf(&b, "; and %d more", len(e.Failures)-i)
			break
		}
		b.WriteString("; ")
		b.WriteString(f.String())
	}
	return b.String()
}

// entryLoc is one place an identity's bytes sit. An identity can sit in
// several packs at once — publish dedups against the previous generation
// but a repack or a fork can place the same bytes again — and every copy
// counts live, because any of them may be the one a reader resolves.
type entryLoc struct {
	pack        int // index into sweeper.packs
	off, length int64
	// backup marks a superblock backup entry, which is live for as long
	// as its generation is (see sweeper.readTrailers).
	backup bool
}

// keyedLoc pairs an identity with one place it sits, so a worker can
// accumulate a whole trailer's worth before taking the index lock once.
type keyedLoc struct {
	key string
	loc entryLoc
}

type sweeper struct {
	o        Options
	spillDir string

	// packs is the pack universe, sorted by name; hashes[i] is the
	// trailer hash the pack list records for packs[i].
	packs  []Pack
	hashes [][32]byte

	mu sync.Mutex
	// index maps identity -> every entry holding it, built from verified
	// trailers.
	index map[string][]entryLoc
	// reachable is the identity set the walk accumulates.
	reachable map[string]struct{}
	// promoted are the nlink>1 inodes seen in path catalogs; their content
	// records live in inode shards and are collected in a second pass.
	promoted map[int64]struct{}
	// walked guards against fetching a catalog twice: content addressing
	// means many generations name the same one, and carrying catalogs
	// forward is the common case rather than the exception.
	walked   map[string]struct{}
	failures []Failure
	objects  int
	trailers int
}

// Sweep walks every live generation and reports per-pack liveness.
//
// A non-nil report means the sweep read everything it needed and the
// numbers may be acted on. A nil report with an *Incomplete error means
// something failed; the conservative numbers inside it report every pack
// fully live. Any other error is a bad request (no store, no live
// generations, a DEK the volume needs and did not get).
func Sweep(ctx context.Context, o Options) (*Report, error) {
	if o.Inner == nil {
		return nil, errors.New("reach: Inner is required")
	}
	if len(o.Live) == 0 {
		// Fails closed exactly as the GC sweep does on finding no refs:
		// an empty live set would report every pack dead.
		return nil, errors.New("reach: no live generations were supplied")
	}
	vol := o.Live[0].VolumeID
	for _, sb := range o.Live {
		if sb == nil {
			return nil, errors.New("reach: a nil superblock is in the live set")
		}
		if sb.VolumeID != vol {
			return nil, fmt.Errorf("reach: live set mixes volumes (%x and %x)", vol, sb.VolumeID)
		}
		if sb.CatalogKeyID != 0 && len(o.DEK) == 0 {
			return nil, fmt.Errorf("reach: generation %d encrypts its catalogs but no DEK was provided", sb.Generation)
		}
		// Catalog-class entries carry no per-entry key id — the superblock
		// states the one key that encrypts them all — so a live set spanning
		// a rekey has no single answer for how to decode an object two of
		// its generations share. Refused rather than guessed: sweep the
		// generations either side of the rekey separately.
		if sb.CatalogKeyID != o.Live[0].CatalogKeyID {
			return nil, fmt.Errorf("reach: live set mixes catalog key ids (%d and %d)", o.Live[0].CatalogKeyID, sb.CatalogKeyID)
		}
	}
	spillRoot := o.CacheDir
	if spillRoot == "" {
		tmp, err := os.MkdirTemp("", "pelfs-reach-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp) //nolint:errcheck
		spillRoot = tmp
	}
	// A subdirectory of its own, for fsck's reason: a genfs spill under
	// the same cache dir is trusted on hit, and this sweep must read only
	// bytes it fetched itself.
	spillDir := filepath.Join(spillRoot, "reach")
	if err := os.MkdirAll(spillDir, 0700); err != nil {
		return nil, fmt.Errorf("reach: spill dir: %w", err)
	}
	defer os.RemoveAll(spillDir) //nolint:errcheck

	s := &sweeper{
		o:         o,
		spillDir:  spillDir,
		index:     make(map[string][]entryLoc),
		reachable: make(map[string]struct{}),
		promoted:  make(map[int64]struct{}),
		walked:    make(map[string]struct{}),
	}
	s.collectPacks(ctx)
	s.readTrailers(ctx)
	s.walkCatalogs(ctx)
	s.walkShards(ctx)
	if err := ctx.Err(); err != nil {
		s.fail("sweep", "%v", err)
	}

	rep := s.report()
	if len(s.failures) > 0 {
		sort.Slice(s.failures, func(i, j int) bool {
			a, b := s.failures[i], s.failures[j]
			if a.Object != b.Object {
				return a.Object < b.Object
			}
			return a.Detail < b.Detail
		})
		return nil, &Incomplete{Failures: s.failures, Conservative: conservative(rep)}
	}
	return rep, nil
}

func (s *sweeper) fail(object, format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, Failure{Object: object, Detail: fmt.Sprintf(format, args...)})
}

// collectPacks unions the live generations' pack lists. The same pack is
// named by every generation that inherited it — pack lists carry forward
// — so the union is much smaller than the sum, and it is the whole set
// this sweep will ever account for.
func (s *sweeper) collectPacks(ctx context.Context) {
	type listed struct {
		pack Pack
		hash [32]byte
	}
	var all []listed
	seen := make(map[string]int)
	for _, sb := range s.o.Live {
		// Inline list or manifest segments, whichever the generation uses
		// (manifest.Packs). A generation whose manifest will not read is a
		// FAILURE rather than a generation with no packs: the sweep would
		// otherwise report the packs only that generation references as
		// unreferenced, which is the one error this package is built not to
		// make. Recorded and carried on, so the report names every
		// generation that could not be read rather than the first.
		packs, err := manifest.Packs(ctx, s.o.Inner, sb)
		if err != nil {
			s.fail(fmt.Sprintf("generation %d", sb.Generation), "pack set unreadable: %v", err)
			continue
		}
		for _, pe := range packs {
			i, dup := seen[pe.Name]
			if !dup {
				seen[pe.Name] = len(all)
				all = append(all, listed{pack: Pack{Name: pe.Name, Size: pe.Size}, hash: pe.TrailerHash})
				continue
			}
			// Two generations describing one immutable pack differently is
			// a contradiction the sweep cannot resolve, and resolving it
			// either way would index bytes at offsets one of them denies.
			if all[i].hash != pe.TrailerHash || all[i].pack.Size != pe.Size {
				s.fail(pe.Name, "generation %d describes it as %d bytes / trailer %x, another as %d / %x",
					sb.Generation, pe.Size, pe.TrailerHash, all[i].pack.Size, all[i].hash)
			}
		}
	}
	// Sorted by name is sorted by age: a pack name begins with a
	// zero-padded creation stamp, and age is the order retention thinks in.
	sort.Slice(all, func(i, j int) bool { return all[i].pack.Name < all[j].pack.Name })
	s.packs = make([]Pack, len(all))
	s.hashes = make([][32]byte, len(all))
	for i, l := range all {
		s.packs[i], s.hashes[i] = l.pack, l.hash
	}
}

// readTrailers builds the identity index and the per-pack totals from
// every pack's verified trailer, concurrently. A pack whose trailer does
// not read is a failure and stays unindexed: everything that lived in it
// then fails to resolve, which is the same conservative direction.
func (s *sweeper) readTrailers(ctx context.Context) {
	each(ctx, s.o.Workers, len(s.packs), func(i int) {
		p := &s.packs[i]
		entries, err := packstore.FetchTrailerVerified(ctx, s.o.Inner, p.Name, p.Size, s.hashes[i])
		if err != nil {
			s.fail(p.Name, "%v", err)
			return
		}
		var ents, bytes, liveEnts, liveBytes int64
		locs := make([]keyedLoc, 0, len(entries))
		for _, e := range entries {
			ents++
			bytes += e.Length
			backup := e.Type == packstore.EntrySuperblock
			if backup {
				// A generation's own superblock backup is live while the
				// generation is, and nothing references it by identity —
				// it is the disaster-recovery copy, reachable only by
				// scavenging. Counting every backup in the live pack set
				// keeps a retired generation's backup alive slightly
				// longer than it needs to be, which is one entry per
				// publish and the safe direction.
				liveEnts++
				liveBytes += e.Length
			}
			locs = append(locs, keyedLoc{e.Key, entryLoc{pack: i, off: e.Off, length: e.Length, backup: backup}})
		}
		s.mu.Lock()
		p.Indexed = true
		p.Entries, p.Bytes = ents, bytes
		p.LiveEntries, p.LiveBytes = liveEnts, liveBytes
		for _, kl := range locs {
			s.index[kl.key] = append(s.index[kl.key], kl.loc)
		}
		s.trailers++
		s.mu.Unlock()
	})
}

// locate picks where to read an identity from. Any copy will do — they
// are the same bytes by construction — so the first indexed one is taken.
func (s *sweeper) locate(id string) (entryLoc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	locs := s.index[id]
	if len(locs) == 0 {
		return entryLoc{}, false
	}
	return locs[0], true
}

// fetchObject reads and decodes one catalog-class pack entry. Their
// encoding is fixed by rule — always zstd, under the one key the
// superblock names — and never sniffed (docs/design-packfs.md, "Codec
// marking").
func (s *sweeper) fetchObject(ctx context.Context, id string) ([]byte, error) {
	loc, ok := s.locate(id)
	if !ok {
		return nil, errors.New("resolves in no listed pack")
	}
	stored, err := s.readRange(ctx, loc)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.objects++
	s.mu.Unlock()
	return entrycodec.Decode(stored, entrycodec.AlgZstd, s.catalogDEK())
}

// catalogDEK is nil on a plaintext volume. Generations are checked to
// agree on the key id in Sweep, so one answer serves the whole sweep.
func (s *sweeper) catalogDEK() []byte {
	if s.o.Live[0].CatalogKeyID != 0 {
		return s.o.DEK
	}
	return nil
}

func (s *sweeper) readRange(ctx context.Context, loc entryLoc) ([]byte, error) {
	key := packstore.PackDirKey + "/" + s.packs[loc.pack].Name
	rc, err := s.o.Inner.Get(ctx, key, loc.off, loc.length)
	if err != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, loc.off, loc.length, err)
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, loc.length))
	// Transfer-engine transports may report failure only at Close; never
	// swallow it (the packstore lesson).
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, loc.off, loc.length, cerr)
	}
	if int64(len(buf)) != loc.length {
		return nil, fmt.Errorf("read %s [%d,+%d): short read (%d bytes)", key, loc.off, loc.length, len(buf))
	}
	return buf, nil
}

// spill materializes decoded catalog bytes so catalog.OpenReader can read
// them. Named by identity, which is unique per job, so concurrent jobs
// never collide.
func (s *sweeper) spill(id string, plain []byte) (string, error) {
	fp := filepath.Join(s.spillDir, id+".db")
	if err := os.WriteFile(fp, plain, 0600); err != nil {
		return "", err
	}
	return fp, nil
}

// report totals the per-pack numbers after marking every reachable
// identity live. Marking happens here rather than during the walk because
// an identity is reachable once but may sit in several packs.
func (s *sweeper) report() *Report {
	rep := &Report{Generations: len(s.o.Live), Trailers: s.trailers, Objects: s.objects}
	rep.Fetched = rep.Trailers + rep.Objects
	for id := range s.reachable {
		locs := s.index[id]
		if len(locs) == 0 {
			rep.Unresolved++
			continue
		}
		for _, loc := range locs {
			if loc.backup {
				continue // already counted at trailer time
			}
			p := &s.packs[loc.pack]
			p.LiveEntries++
			p.LiveBytes += loc.length
		}
	}
	rep.Packs = s.packs
	for _, p := range rep.Packs {
		rep.Entries += p.Entries
		rep.LiveEntries += p.LiveEntries
		rep.Bytes += p.Bytes
		rep.LiveBytes += p.LiveBytes
	}
	return rep
}

// conservative rewrites a report as "every pack fully live", which is what
// an incomplete sweep is entitled to claim and nothing more.
func conservative(rep *Report) *Report {
	out := *rep
	out.Packs = make([]Pack, len(rep.Packs))
	copy(out.Packs, rep.Packs)
	out.LiveEntries, out.LiveBytes = 0, 0
	for i := range out.Packs {
		p := &out.Packs[i]
		p.LiveEntries, p.LiveBytes = p.Entries, p.Bytes
		out.LiveEntries += p.LiveEntries
		out.LiveBytes += p.LiveBytes
	}
	return &out
}

// each runs fn over n jobs on a bounded worker pool — the shape
// mpi.FetchAll uses, and for the same reason: a generation with ten
// thousand catalogs must cost `workers` goroutines and one round trip's
// latency each, not ten thousand goroutines and not ten thousand serial
// round trips.
func each(ctx context.Context, workers, n int, fn func(i int)) {
	if n == 0 {
		return
	}
	if workers <= 0 {
		workers = defaultWorkers
	}
	workers = min(workers, n)
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				if ctx.Err() != nil {
					return
				}
				fn(i)
			}
		})
	}
	for i := range n {
		select {
		case next <- i:
		case <-ctx.Done():
			close(next)
			wg.Wait()
			return
		}
	}
	close(next)
	wg.Wait()
}

func idHex(id [32]byte) string { return hex.EncodeToString(id[:]) }
