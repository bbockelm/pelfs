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
// # Memory
//
// The sweep is a MERGE JOIN over two sorted streams — every (identity,
// pack) placement the trailers describe, and every identity the walk
// reaches — rather than a walk against a resident index.
//
// It used to be the latter, and that bounded this package to volumes
// whose identity index fit in memory: a hundred million entries keyed by
// hex string is tens of gigabytes before the reference set is counted at
// all. Both sides are keyed by identity, so the question was never a
// lookup; it only looked like one because a map was the easiest thing to
// reach for. Sorting instead (sorter.go) makes the pass sequential, the
// records fixed-width, the keys raw rather than hex, and the memory a
// buffer the caller sizes (Options.SortBytes).
//
// What remains resident is proportional to the number of PACKS, the
// number of CATALOGS and the number of hardlinked inodes — thousands
// each, not hundreds of millions:
//
//   - per-pack liveness counters, which are the answer being computed;
//   - the locations of catalog-class entries, which are the only entries
//     this sweep ever reads back (sweeper.objLoc);
//   - the set of catalogs already walked, and the promoted inodes whose
//     content the shard pass still has to find.
//
// Persisting reachability instead of recomputing it — git's bitmap model,
// which fits this format unusually well — is a larger change and is
// written up in docs/design-reachability.md rather than built here.
package reach

import (
	"bytes"
	"context"
	"encoding/binary"
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
	// CacheDir holds catalog spill files and the sort runs the join
	// streams over. Empty means a temporary directory removed on return.
	// Spills are written fresh and deleted after use — a cached copy is a
	// copy the sweep has not read.
	//
	// It must have room for the sweep's identity records: about 45 bytes
	// per pack entry plus 32 per reference, so a hundred-million-object
	// volume spills a few gigabytes there and a small one spills nothing
	// at all.
	CacheDir string
	// Workers bounds concurrent object fetches (default 8).
	Workers int
	// SortBytes is how much either side of the join buffers before
	// spilling a run (default 64 MiB). It is the sweep's memory bound in
	// all but name: everything else it holds is proportional to the number
	// of packs, catalogs and hardlinked inodes rather than to the number
	// of objects.
	SortBytes int
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
}

// The two record layouts the join streams over. Both are keyed by the raw
// 32-byte identity — raw rather than the hex the sweep used to key its
// maps by, which halves every byte moved and every byte compared.
const (
	idLen = 32
	// placeLen: identity, pack index, stored length, flags. The OFFSET is
	// deliberately absent. Only catalog-class entries are ever read back,
	// and those are held resident (sweeper.objLoc); a chunk's placement is
	// needed to attribute bytes and never to fetch them, so spilling eight
	// bytes per entry that nothing reads would be the largest single line
	// item in the sort for no purpose.
	placeLen = idLen + 4 + 8 + 1
	// flagBackup marks a superblock backup, already counted live at
	// trailer time and skipped by the join so it cannot count twice.
	flagBackup = 1
)

// objEntry is one catalog-class entry a worker found, held locally until
// the whole trailer is read and merged into objLoc under one lock.
type objEntry struct {
	id  [32]byte
	loc entryLoc
}

func putPlace(dst []byte, id [32]byte, pack int, length int64, flags byte) {
	copy(dst[0:idLen], id[:])
	binary.LittleEndian.PutUint32(dst[idLen:], uint32(pack))
	binary.LittleEndian.PutUint64(dst[idLen+4:], uint64(length))
	dst[idLen+12] = flags
}

type sweeper struct {
	o        Options
	spillDir string

	// packs is the pack universe, sorted by name; hashes[i] is the
	// trailer hash the pack list records for packs[i].
	packs  []Pack
	hashes [][32]byte

	// places is every (identity, pack) placement the trailers describe and
	// refs is every identity the walk reaches. They are the two sides of
	// the join, streamed rather than held (sorter.go).
	places *sorter
	refs   *sorter

	mu sync.Mutex
	// objLoc locates the catalog-class entries — catalogs, inode shards,
	// superblock backups — which are the only ones this sweep ever READS.
	// It is resident because the walk needs random access to it while it
	// is still discovering what to look up, and it is affordable because a
	// volume has thousands of catalogs and hundreds of millions of chunks.
	//
	// The consequence is that a catalog stored as an untyped entry cannot
	// be found. That is a format violation — typed entries are what let
	// rescue inventory a namespace from packs alone — and it lands in the
	// safe direction: the catalog fails to resolve, which is a failure,
	// which makes the whole sweep incomplete and every pack fully live.
	objLoc map[[32]byte]entryLoc
	// promoted are the nlink>1 inodes seen in path catalogs; their content
	// records live in inode shards and are collected in a second pass.
	promoted map[int64]struct{}
	// walked guards against fetching a catalog twice: content addressing
	// means many generations name the same one, and carrying catalogs
	// forward is the common case rather than the exception.
	walked   map[[32]byte]struct{}
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
		o:        o,
		spillDir: spillDir,
		places:   newSorter(spillDir, "places", idLen, placeLen, o.SortBytes),
		refs:     newSorter(spillDir, "refs", idLen, idLen, o.SortBytes),
		objLoc:   make(map[[32]byte]entryLoc),
		promoted: make(map[int64]struct{}),
		walked:   make(map[[32]byte]struct{}),
	}
	defer s.places.Close() //nolint:errcheck
	defer s.refs.Close()   //nolint:errcheck
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

// readTrailers records every placement and the per-pack totals from every
// pack's verified trailer, concurrently. A pack whose trailer does not
// read is a failure and stays unindexed: everything that lived in it then
// fails to resolve, which is the same conservative direction.
//
// A whole trailer's placements are built into one buffer and handed to
// the sorter in a single call, so the cost paid per identity is a memcpy
// into a slice rather than a lock, a map probe and an allocation.
func (s *sweeper) readTrailers(ctx context.Context) {
	each(ctx, s.o.Workers, len(s.packs), func(i int) {
		p := &s.packs[i]
		entries, err := packstore.FetchTrailerVerified(ctx, s.o.Inner, p.Name, p.Size, s.hashes[i])
		if err != nil {
			s.fail(p.Name, "%v", err)
			return
		}
		var ents, stored, liveEnts, liveBytes int64
		batch := make([]byte, 0, len(entries)*placeLen)
		var objs []objEntry
		for _, e := range entries {
			id, err := parseIdentity(e.Key)
			if err != nil {
				// A trailer key that is not an identity indexes nothing this
				// sweep can join against, and one that a reader WOULD resolve
				// would then look unreferenced. Refusing is the safe reading.
				s.fail(p.Name, "entry key %q: %v", e.Key, err)
				return
			}
			ents++
			stored += e.Length
			var flags byte
			if e.Type == packstore.EntrySuperblock {
				// A generation's own superblock backup is live while the
				// generation is, and nothing references it by identity —
				// it is the disaster-recovery copy, reachable only by
				// scavenging. Counting every backup in the live pack set
				// keeps a retired generation's backup alive slightly
				// longer than it needs to be, which is one entry per
				// publish and the safe direction.
				liveEnts++
				liveBytes += e.Length
				flags |= flagBackup
			}
			if e.Type != packstore.EntryData {
				objs = append(objs, objEntry{id, entryLoc{pack: i, off: e.Off, length: e.Length}})
			}
			var rec [placeLen]byte
			putPlace(rec[:], id, i, e.Length, flags)
			batch = append(batch, rec[:]...)
		}
		if err := s.places.Add(batch); err != nil {
			s.fail(p.Name, "recording placements: %v", err)
			return
		}
		s.mu.Lock()
		p.Indexed = true
		p.Entries, p.Bytes = ents, stored
		p.LiveEntries, p.LiveBytes = liveEnts, liveBytes
		for _, o := range objs {
			// First writer wins: any copy will do, since they are the same
			// bytes by construction.
			if _, dup := s.objLoc[o.id]; !dup {
				s.objLoc[o.id] = o.loc
			}
		}
		s.trailers++
		s.mu.Unlock()
	})
}

// parseIdentity reads a trailer key as the 32-byte identity everything
// here is keyed by.
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

// locate picks where to read a catalog-class identity from.
func (s *sweeper) locate(id [32]byte) (entryLoc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	loc, ok := s.objLoc[id]
	return loc, ok
}

// fetchObject reads and decodes one catalog-class pack entry. Their
// encoding is fixed by rule — always zstd, under the one key the
// superblock names — and never sniffed (docs/design-packfs.md, "Codec
// marking").
func (s *sweeper) fetchObject(ctx context.Context, id [32]byte) ([]byte, error) {
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
//
// It is a MERGE JOIN over two sorted streams — every placement the
// trailers described, and every identity the walk reached — rather than
// the map lookup it used to be. Both sides arrive sorted by identity, so
// the whole attribution is one pass with a constant amount of state, and
// the sweep's memory stops depending on how many objects the volume
// holds. A stream that fails to read is recorded as a failure: a
// truncated join would under-count liveness, which is the direction that
// deletes data.
func (s *sweeper) report() *Report {
	rep := &Report{Generations: len(s.o.Live), Trailers: s.trailers, Objects: s.objects}
	rep.Fetched = rep.Trailers + rep.Objects
	s.join(rep)
	rep.Packs = s.packs
	for _, p := range rep.Packs {
		rep.Entries += p.Entries
		rep.LiveEntries += p.LiveEntries
		rep.Bytes += p.Bytes
		rep.LiveBytes += p.LiveBytes
	}
	return rep
}

// join walks the two sorted streams together and credits each pack for
// the entries something still references.
//
// The reference side may hold an identity many times over — a chunk
// shared by a thousand files is reached a thousand times, and nothing
// upstream deduplicates it, because deduplicating is exactly what a
// sorted stream does for free. It is counted once. The placement side may
// also hold an identity many times, and each of THOSE is counted: the
// same bytes in two packs keep both alive, since either may be the copy a
// reader resolves.
func (s *sweeper) join(rep *Report) {
	places, err := s.places.Sorted()
	if err != nil {
		s.fail("sweep", "reading placements: %v", err)
		return
	}
	defer places.Close() //nolint:errcheck
	refs, err := s.refs.Sorted()
	if err != nil {
		s.fail("sweep", "reading references: %v", err)
		return
	}
	defer refs.Close() //nolint:errcheck

	place, more := places.Next()
	var prev [idLen]byte
	first := true
	for {
		id, ok := refs.Next()
		if !ok {
			break
		}
		if !first && bytes.Equal(id, prev[:]) {
			continue
		}
		copy(prev[:], id)
		first = false

		for more && bytes.Compare(place[:idLen], id) < 0 {
			place, more = places.Next()
		}
		found := false
		for more && bytes.Equal(place[:idLen], id) {
			found = true
			if place[idLen+12]&flagBackup == 0 {
				p := &s.packs[binary.LittleEndian.Uint32(place[idLen:])]
				p.LiveEntries++
				p.LiveBytes += int64(binary.LittleEndian.Uint64(place[idLen+4:]))
			}
			place, more = places.Next()
		}
		if !found {
			rep.Unresolved++
		}
	}
	if err := refs.Err(); err != nil {
		s.fail("sweep", "reading references: %v", err)
	}
	if err := places.Err(); err != nil {
		s.fail("sweep", "reading placements: %v", err)
	}
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
