package memtable

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// ContentRow is one inode's content as the overlay's database would hold
// it: a length and a list of extent references. It names handles, never
// places, which is the point — a flush moves bytes without touching one
// of these.
type ContentRow struct {
	Inode uint64
	Size  int64
	Refs  []ExtentRef
}

// Durable is the state a crash is expected to leave behind: the content
// rows and the location map, both of which live in the overlay's
// database in a real mount. The buffer files are the volatile half.
//
// The location map has to be here, and the design does not say so. A
// handle that has already flushed resolves through Handles, and nothing
// else in the format can reconstruct that binding: pack trailers know
// chunk identities, but nothing on the federation has ever heard of a
// handle. So a flush must durably record one row per surviving extent,
// which is a database write per extent per flush that the design's
// "flushing does not touch a catalog row" framing quietly omits.
type Durable struct {
	Rows    []ContentRow
	Handles map[Handle][]ChunkSlice
	Chunks  map[string]PackLoc
	Packs   []packstore.SealedPack
	// Adopted is handle -> the base inode it was adopted from, as the
	// OPERATION LOG has it. It is the authority on which adopted handles
	// this journal ever created; AdoptedRefs is the authority on what each
	// one holds.
	Adopted map[Handle]uint64
	// AdoptedRefs is the records each adopted handle was taken with. It
	// exists because the base generation a later mount serves is not the
	// one the handle was taken from, and cannot answer for an inode nobody
	// has looked up (AdoptedExtent says the rest). A journal written before
	// these were recorded has none, which recovery reports rather than
	// guesses at.
	AdoptedRefs map[Handle]AdoptedExtent
}

// Durable returns the state that would have been committed to the
// overlay's database. Callers persist it; Recover consumes it.
func (s *Store) Durable() Durable {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := Durable{
		Handles:     make(map[Handle][]ChunkSlice, len(s.handleLoc)),
		Chunks:      make(map[string]PackLoc, len(s.chunkLoc)),
		Packs:       append([]packstore.SealedPack(nil), s.packs...),
		Adopted:     make(map[Handle]uint64, len(s.baseRefs)),
		AdoptedRefs: make(map[Handle]AdoptedExtent, len(s.baseRefs)),
	}
	for h, be := range s.baseRefs {
		d.Adopted[h] = be.ino
		d.AdoptedRefs[h] = AdoptedExtent{
			Inode:  be.ino,
			Length: be.length,
			Refs:   append([]catalog.ChunkRef(nil), be.refs...),
		}
	}
	inodes := make([]uint64, 0, len(s.content))
	for ino := range s.content {
		inodes = append(inodes, ino)
	}
	sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })
	for _, ino := range inodes {
		c := s.content[ino]
		d.Rows = append(d.Rows, ContentRow{
			Inode: ino,
			Size:  c.size,
			Refs:  append([]ExtentRef(nil), c.refs...),
		})
	}
	for h, sl := range s.handleLoc {
		d.Handles[h] = append([]ChunkSlice(nil), sl...)
	}
	for k, v := range s.chunkLoc {
		d.Chunks[k] = v
	}
	return d
}

// LostRange is one span of one inode that recovery could not find.
type LostRange struct {
	Inode   uint64
	FileOff int64
	Length  int
	Handle  Handle
}

// BufferReport is what one buffer file yielded.
type BufferReport struct {
	Path    string
	Seq     uint64
	Records int
	Bytes   int64
	// Torn means bytes were found past the last valid record. Truncated
	// means the file is shorter than a table. Neither is proof of loss on
	// its own — only the content rows can say that — but both belong in
	// the report a user reads after a crash.
	Torn      bool
	Truncated bool
	// Missing is how many bytes short of a full table the file is.
	Missing int64
	// Ignored means the file was found but not read. There is one ring, so
	// a second buffer file is a stray from an older layout or a crashed
	// rotation, and its absolute positions are meaningless against the
	// ring that was adopted. It is reported because its records are gone
	// and the content rows naming them will say so.
	Ignored bool
}

// Report is recovery's account of itself. It must be shown to the user
// whenever Lost is true: losing data to a crash is expected on a mount
// tied to a job, but losing it silently is not.
type Report struct {
	Buffers   []BufferReport
	Lost      []LostRange
	LostBytes int64
	// LostInodes is the distinct inodes with at least one lost range.
	LostInodes []uint64
}

// Loss reports whether anything was lost.
func (r *Report) Loss() bool { return len(r.Lost) > 0 }

func (r *Report) String() string {
	var b strings.Builder
	recs, bytes := 0, int64(0)
	for _, br := range r.Buffers {
		recs += br.Records
		bytes += br.Bytes
		// A file can be both short AND torn — a truncation usually cuts
		// through a record — so these are separate lines, not a switch.
		if br.Ignored {
			fmt.Fprintf(&b, "memtable: %s is a stray buffer file and was not read\n", br.Path)
		}
		if br.Truncated {
			fmt.Fprintf(&b, "memtable: %s is short by %d bytes; %d records recovered\n", br.Path, br.Missing, br.Records)
		}
		if br.Torn {
			fmt.Fprintf(&b, "memtable: %s has a torn tail; %d records recovered before it\n", br.Path, br.Records)
		}
	}
	fmt.Fprintf(&b, "memtable: recovered %d extents (%d bytes) from %d buffer files\n", recs, bytes, len(r.Buffers))
	if !r.Loss() {
		return b.String()
	}
	fmt.Fprintf(&b, "memtable: DATA LOST: %d extents, %d bytes, across %d files:\n", len(r.Lost), r.LostBytes, len(r.LostInodes))
	for _, l := range r.Lost {
		fmt.Fprintf(&b, "  inode %d: bytes [%d,%d) are gone\n", l.Inode, l.FileOff, l.FileOff+int64(l.Length))
	}
	return b.String()
}

// Recover reopens a state directory against the durable state a crash
// left behind. Every buffer file is scanned and validated; the scan of
// each stops at its first bad record. Content references that resolve to
// neither a recovered extent nor the location map are dropped from the
// rebuilt content and reported.
//
// It asks the base generation for NOTHING, which is the property that
// matters on a remount: see readopt.
//
// The recovered tables are not merged into the active table. They are
// full or nearly so, they are already frozen by virtue of the crash, and
// re-appending their bytes would double the local I/O of a recovery for
// no gain — so they are flushed as they are, by Flush, before the active
// table rotates.
func Recover(opts Options, d Durable) (*Store, *Report, error) {
	s, err := newStore(opts)
	if err != nil {
		return nil, nil, err
	}
	rep := &Report{}

	seqs, err := bufferSeqs(opts.Dir)
	if err != nil {
		return nil, nil, err
	}
	// A ring recovers IN PLACE: the surviving run stays exactly where it
	// is and the store adopts the file rather than copying its records
	// into a fresh one. Positions are absolute and the reader resolves
	// them modulo this ring's size, so copying would invalidate every one
	// of them — which is also why an older stray file is reported and
	// never read: its positions mean nothing in these coordinates.
	found := make(map[Handle]struct{})
	for i, seq := range seqs {
		path := filepath.Join(opts.Dir, bufferName(seq))
		if seq >= s.nextSeq {
			s.nextSeq = seq + 1
		}
		if i != len(seqs)-1 {
			rep.Buffers = append(rep.Buffers, BufferReport{Path: path, Seq: seq, Ignored: true})
			continue
		}
		r, recs, err := OpenRing(path)
		if err != nil {
			return nil, nil, err
		}
		br := BufferReport{
			Path: path, Seq: seq, Records: len(recs),
			Torn: r.Torn, Truncated: r.Truncated, Missing: r.Missing,
		}
		s.ring = r
		for _, rec := range recs {
			s.index[rec.Handle] = rec
			s.order = append(s.order, rec.Handle)
			br.Bytes += int64(rec.Length)
			found[rec.Handle] = struct{}{}
			if rec.Handle >= s.nextHandle {
				s.nextHandle = rec.Handle + 1
			}
		}
		rep.Buffers = append(rep.Buffers, br)
	}

	s.handleLoc = make(map[Handle][]ChunkSlice, len(d.Handles))
	// Replaced, not added to, so its reference counts are replaced too:
	// they are rebuilt below from the rows this recovery could restore.
	s.locRefs = make(map[Handle]int, len(d.Handles))
	for h, sl := range d.Handles {
		s.handleLoc[h] = sl
		if h >= s.nextHandle {
			s.nextHandle = h + 1
		}
	}
	s.chunkLoc = make(map[string]PackLoc, len(d.Chunks))
	for k, v := range d.Chunks {
		s.chunkLoc[k] = v
	}
	s.packs = append([]packstore.SealedPack(nil), d.Packs...)

	if err := s.readopt(d, found); err != nil {
		return nil, nil, err
	}

	lostInodes := make(map[uint64]struct{})
	for _, row := range d.Rows {
		c := &content{size: row.Size}
		for _, r := range row.Refs {
			if _, ok := found[r.Handle]; ok {
				c.refs = append(c.refs, r)
				// Two counts, because an extent is either a ring record or
				// an adopted one and never both. Putting an adopted handle
				// in the ring's live set would make it uncollectable: only
				// the count on the baseRefs entry decides when that entry
				// goes.
				if be, adopted := s.baseRefs[r.Handle]; adopted {
					be.nrefs++
					s.baseRefs[r.Handle] = be
				} else {
					s.live[r.Handle]++
				}
				continue
			}
			if _, ok := s.handleLoc[r.Handle]; ok {
				c.refs = append(c.refs, r)
				// Published, and this row is a reference to it. The count
				// is rebuilt here for the same reason the ring's and the
				// base's are above: a recovered store has to be able to
				// collect what a live one would have collected.
				s.locRefs[r.Handle]++
				continue
			}
			rep.Lost = append(rep.Lost, LostRange{Inode: row.Inode, FileOff: r.FileOff, Length: r.Length, Handle: r.Handle})
			rep.LostBytes += int64(r.Length)
			lostInodes[row.Inode] = struct{}{}
			s.stats.LostHandles++
		}
		sort.Slice(c.refs, func(i, j int) bool { return c.refs[i].FileOff < c.refs[j].FileOff })
		s.content[row.Inode] = c
	}
	// An adopted handle no surviving content row names is dead on arrival.
	// readopt never establishes one now — deciding that BEFORE resolving it
	// is what stopped a mount refusing over a handle it was about to throw
	// away — so this is the standing check rather than the working path, and
	// it stays because the count above is what the store collects by.
	for h, be := range s.baseRefs {
		if be.nrefs == 0 {
			delete(s.baseRefs, h)
		}
	}
	for ino := range lostInodes {
		rep.LostInodes = append(rep.LostInodes, ino)
	}
	sort.Slice(rep.LostInodes, func(i, j int) bool { return rep.LostInodes[i] < rep.LostInodes[j] })
	sort.Slice(rep.Lost, func(i, j int) bool {
		if rep.Lost[i].Inode != rep.Lost[j].Inode {
			return rep.Lost[i].Inode < rep.Lost[j].Inode
		}
		return rep.Lost[i].FileOff < rep.Lost[j].FileOff
	})

	// Only when there was nothing to adopt: a recovered ring IS the active
	// one, and creating a second would leave every recovered position
	// pointing into a file nobody reads.
	if s.ring == nil {
		if err := s.openActive(); err != nil {
			return nil, nil, err
		}
	}
	return s, rep, nil
}

// UnresolvedAdoption is one adopted handle recovery could neither rebuild
// from what was written down nor obtain from the base generation.
type UnresolvedAdoption struct {
	Handle Handle
	// Inode is the base inode the handle was adopted from. The bytes are
	// not gone — an immutable generation still holds that file — but this
	// store cannot say which chunks of it the handle stands for.
	Inode uint64
	// Bytes is how much of the recovered file the handle accounts for.
	Bytes int64
	// Err is why the base could not answer either.
	Err error
}

// UnresolvedAdoptionsError is recovery refusing, and it is deliberate.
//
// The store's other unrecoverable case — a ring extent whose bytes are
// gone — is REPORTED and dropped, and the mount comes up with a hole where
// it was (Report, LostRange). That is honest there because the bytes exist
// nowhere: nothing better than zeros is available, and a user watching a
// crashed job is told exactly which ranges went.
//
// An adopted handle is the opposite case. Its bytes are published, signed
// and immutable in a generation that is still on the federation; only this
// store's note of WHICH chunks they are is missing. Dropping the extent
// would put zeros over live data and the next seal would publish them, so
// the two degradations available here are "quietly destroy something that
// still exists" and "refuse to start". Refusing is the safer of those, so
// recovery refuses — but it refuses ONCE, naming every handle rather than
// the first, so the report is the whole problem and not a sample.
//
// This is reachable only for a journal written by a build that recorded no
// adoption records (AdoptedExtent), because a build that records them
// resolves adoptions without the base at all. The escape is stated by the
// caller, which is the layer that knows where the state directory is.
type UnresolvedAdoptionsError struct {
	Adoptions []UnresolvedAdoption
}

func (e *UnresolvedAdoptionsError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "memtable: %d adopted extent(s) in this state directory cannot be resolved", len(e.Adoptions))
	for _, a := range e.Adoptions {
		fmt.Fprintf(&b, "\n  inode %d: %d bytes were taken from a published generation by reference, "+
			"and the records naming them are not in the journal: %v", a.Inode, a.Bytes, a.Err)
	}
	return b.String()
}

func (e *UnresolvedAdoptionsError) Unwrap() error {
	if len(e.Adoptions) == 0 {
		return nil
	}
	return e.Adoptions[0].Err
}

// readopt rebuilds the store's adopted extents. Every handle the operation
// log adopted is accounted for here, in one of three ways:
//
//   - NOBODY NAMES IT: no surviving content row references the handle, so
//     re-establishing it would buy a record of a borrowing nothing does.
//     Those are skipped, and skipping them is most of this fix: the
//     four-op sequence that made a state directory unopenable ended in a
//     checkpoint whose rebase Forgot the inode, so the handle recovery
//     refused over was one it would have deleted three lines later.
//
//   - ITS RECORDS ARE ON DISK: the ordinary path, and the only one that
//     works on a mount that has just started. Nothing is asked of the base.
//
//   - NEITHER: the base is asked, as recovery always used to, which
//     succeeds only while the inode is still resident from a descent this
//     process made. When it fails the handle is collected into one refusal
//     (UnresolvedAdoptionsError) rather than aborting on the first.
//
// found is recovery's set of resolvable handles, which the row scan reads.
func (s *Store) readopt(d Durable, found map[Handle]struct{}) error {
	// nextHandle moves past every handle the log ever adopted, resolved or
	// not. A skipped handle that could be handed out again would collide
	// with the location rows an earlier life of that number left behind.
	handles := make([]Handle, 0, len(d.Adopted))
	for h := range d.Adopted {
		handles = append(handles, h)
		if h >= s.nextHandle {
			s.nextHandle = h + 1
		}
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })

	named := make(map[Handle]int64, len(d.Adopted))
	for _, row := range d.Rows {
		for _, r := range row.Refs {
			if _, adopted := d.Adopted[r.Handle]; adopted {
				named[r.Handle] += int64(r.Length)
			}
		}
	}

	var unresolved []UnresolvedAdoption
	for _, h := range handles {
		ino := d.Adopted[h]
		span, isNamed := named[h]
		if !isNamed {
			s.stats.DroppedAdoptions++
			continue
		}
		a, ok := d.AdoptedRefs[h]
		if ok && a.Inode != ino {
			// The log and the records disagree about which file this is.
			// Trusting either would be a guess, so it is neither.
			ok = false
		}
		if !ok {
			err := error(ErrNoBase)
			var c genfs.Content
			if s.base != nil {
				c, err = s.base.ContentOf(context.Background(), ino)
			}
			if err != nil {
				unresolved = append(unresolved, UnresolvedAdoption{
					Handle: h, Inode: ino, Bytes: span, Err: err,
				})
				continue
			}
			a = AdoptedExtent{Inode: ino, Length: c.Length, Refs: c.Refs}
		}
		s.baseRefs[h] = baseExtent{ino: ino, refs: a.Refs, length: a.Length}
		found[h] = struct{}{}
	}
	if len(unresolved) > 0 {
		return &UnresolvedAdoptionsError{Adoptions: unresolved}
	}
	return nil
}

// bufferSeqs lists the buffer files in a state directory, oldest first.
func bufferSeqs(dir string) ([]uint64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var seqs []uint64
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "mem-") || !strings.HasSuffix(name, ".buf") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "mem-"), ".buf"), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}
