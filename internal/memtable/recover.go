package memtable

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
}

// Durable returns the state that would have been committed to the
// overlay's database. Callers persist it; Recover consumes it.
func (s *Store) Durable() Durable {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := Durable{
		Handles: make(map[Handle][]ChunkSlice, len(s.handleLoc)),
		Chunks:  make(map[string]PackLoc, len(s.chunkLoc)),
		Packs:   append([]packstore.SealedPack(nil), s.packs...),
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
		switch {
		case br.Torn:
			fmt.Fprintf(&b, "memtable: %s has a torn tail; %d records recovered before it\n", br.Path, br.Records)
		case br.Truncated:
			fmt.Fprintf(&b, "memtable: %s is short by %d bytes; %d records recovered\n", br.Path, br.Missing, br.Records)
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
	found := make(map[Handle]*table)
	for _, seq := range seqs {
		path := filepath.Join(opts.Dir, bufferName(seq))
		buf, recs, err := OpenBuffer(path, seq)
		if err != nil {
			return nil, nil, err
		}
		t := &table{
			seq:    seq,
			buf:    buf,
			index:  make(map[Handle]Record, len(recs)),
			live:   make(map[Handle]int),
			inodes: make(map[uint64]struct{}),
		}
		br := BufferReport{Path: path, Seq: seq, Records: len(recs), Torn: buf.Torn()}
		if short := int64(s.tableSize - buf.Cap()); short > 0 {
			br.Truncated, br.Missing = true, short
		}
		for _, rec := range recs {
			t.index[rec.Handle] = rec
			t.inodes[rec.Inode] = struct{}{}
			br.Bytes += int64(rec.Length)
			found[rec.Handle] = t
			if rec.Handle >= s.nextHandle {
				s.nextHandle = rec.Handle + 1
			}
		}
		rep.Buffers = append(rep.Buffers, br)
		if seq >= s.nextSeq {
			s.nextSeq = seq + 1
		}
		s.recovered = append(s.recovered, t)
	}

	s.handleLoc = make(map[Handle][]ChunkSlice, len(d.Handles))
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

	lostInodes := make(map[uint64]struct{})
	for _, row := range d.Rows {
		c := &content{size: row.Size}
		for _, r := range row.Refs {
			if t, ok := found[r.Handle]; ok {
				c.refs = append(c.refs, r)
				t.acquire(r.Handle)
				continue
			}
			if _, ok := s.handleLoc[r.Handle]; ok {
				c.refs = append(c.refs, r)
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

	if err := s.openActive(); err != nil {
		return nil, nil, err
	}
	return s, rep, nil
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
