package reach

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// catJob is one catalog to open and scan: its identity, and the directory
// inode it is rooted at.
type catJob struct {
	id  [32]byte
	ino int64
}

// found is what scanning one catalog discovered. It is accumulated
// locally and handed over once, rather than taking a lock per chunkref: a
// catalog holds thousands of them and the hand-over is the only part any
// other worker cares about.
//
// chunks is the raw concatenation of 32-byte identities rather than a
// slice of them, because that is already the sorter's record layout — so
// a catalog's references reach the spool as one append, with no per-chunk
// allocation, no hex, and no second copy to build.
type found struct {
	chunks   []byte
	nested   []catJob
	promoted []int64
}

// walkCatalogs reads every catalog the live generations name and collects
// the identities inside them.
//
// The frontier comes from the SUPERBLOCKS — RootCatalog plus the Catalogs
// list — rather than from descending the namespace, which is the whole
// economy of this sweep against fsck's: the generation already names its
// catalogs, so nothing has to be discovered by reading a parent first,
// and every fetch can go out at once. Nested locators are still checked
// against that list while scanning, and one naming a catalog the
// superblock does not is queued anyway: the Catalogs field is optional in
// the format, so a generation published by a writer that does not
// maintain it must still sweep correctly rather than silently report the
// subtrees below it dead.
func (s *sweeper) walkCatalogs(ctx context.Context) {
	pending := s.seedCatalogs()
	for len(pending) > 0 {
		var next []catJob
		each(ctx, s.o.Workers, len(pending), func(i int) {
			s.scanCatalog(ctx, pending[i], &next)
		})
		s.mu.Lock()
		pending = nil
		var batch []byte
		for _, j := range next {
			if _, dup := s.walked[j.id]; dup {
				continue
			}
			s.walked[j.id] = struct{}{}
			batch = append(batch, j.id[:]...)
			pending = append(pending, j)
		}
		s.mu.Unlock()
		if err := s.refs.Add(batch); err != nil {
			s.fail("sweep", "recording catalog references: %v", err)
			return
		}
	}
}

// seedCatalogs is the catalog frontier: every catalog and shard identity
// the live generations name. All of them are reachable by definition —
// the superblock is signed and names them — so they are marked live here,
// before anything is fetched, and stay live even if the fetch then fails.
func (s *sweeper) seedCatalogs() []catJob {
	var jobs []catJob
	var batch []byte
	queue := func(id [32]byte, ino int64) {
		if _, dup := s.walked[id]; dup {
			return
		}
		s.walked[id] = struct{}{}
		batch = append(batch, id[:]...)
		jobs = append(jobs, catJob{id: id, ino: ino})
	}
	for _, sb := range s.o.Live {
		queue(sb.RootCatalog, rootInode)
		for _, ce := range sb.Catalogs {
			queue(ce.Identity, int64(ce.Inode))
		}
		for _, sh := range sb.Shards {
			// Shard bytes are reachable; their CONTENT is collected in the
			// second pass, once every promoted inode is known.
			batch = append(batch, sh.Identity[:]...)
		}
	}
	if err := s.refs.Add(batch); err != nil {
		s.fail("sweep", "recording the catalog frontier: %v", err)
		return nil
	}
	return jobs
}

// scanCatalog fetches, decodes, opens and scans one catalog. Every
// failure is terminal for the sweep as a whole (see the package comment),
// so it is recorded and the catalog abandoned rather than half-read.
func (s *sweeper) scanCatalog(ctx context.Context, j catJob, next *[]catJob) {
	cat, release, err := s.openObject(ctx, j.id)
	if err != nil {
		s.fail("catalog "+idHex(j.id), "%v", err)
		return
	}
	defer release()

	var f found
	if err := s.scanDir(cat, j.ino, &f, make(map[int64]bool)); err != nil {
		s.fail("catalog "+idHex(j.id), "%v", err)
		return
	}
	if err := s.refs.Add(f.chunks); err != nil {
		s.fail("catalog "+idHex(j.id), "recording references: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ino := range f.promoted {
		s.promoted[ino] = struct{}{}
	}
	*next = append(*next, f.nested...)
}

// openObject fetches one catalog-class object and opens it over a spill
// file. The returned closure closes the reader and drops the spill: a
// catalog is read exactly once, so nothing is kept.
func (s *sweeper) openObject(ctx context.Context, id [32]byte) (catalog.Reader, func(), error) {
	plain, err := s.fetchObject(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	fp, err := s.spill(idHex(id), plain)
	if err != nil {
		return nil, nil, err
	}
	cat, err := catalog.OpenReader(fp)
	if err != nil {
		os.Remove(fp) //nolint:errcheck
		return nil, nil, err
	}
	return cat, func() {
		cat.Close()                                             //nolint:errcheck
		os.Remove(filepath.Join(s.spillDir, filepath.Base(fp))) //nolint:errcheck
	}, nil
}

// scanDir collects the identities under one directory of one catalog,
// recursing into the subdirectories that live in the SAME catalog and
// queueing the ones that do not.
//
// seen stops a corrupt catalog whose edges cycle back on themselves from
// hanging the sweep; fsck reports that as damage, and here it only needs
// to terminate.
func (s *sweeper) scanDir(cat catalog.Reader, ino int64, f *found, seen map[int64]bool) error {
	if seen[ino] {
		return nil
	}
	seen[ino] = true
	dirents, nesteds, err := cat.Readdir(ino)
	if err != nil {
		return fmt.Errorf("readdir inode %d: %w", ino, err)
	}
	nestedByName := make(map[string][]byte, len(nesteds))
	for _, n := range nesteds {
		nestedByName[string(n.Name)] = n.CatalogIdentity
	}
	for _, d := range dirents {
		n, err := cat.Stat(d.Inode)
		if err != nil {
			// A dirent with no node row is damage, and it is damage this
			// sweep cannot see past: the missing row is what would have
			// said whether the name is a file holding chunks.
			if errors.Is(err, catalog.ErrNotExist) {
				return fmt.Errorf("dirent %q names inode %d, which has no node row", d.Name, d.Inode)
			}
			return fmt.Errorf("stat inode %d: %w", d.Inode, err)
		}
		switch n.Type {
		case catalog.TypeDir:
			if id, ok := nestedByName[string(d.Name)]; ok {
				if len(id) != 32 {
					return fmt.Errorf("nested locator under inode %d is %d bytes, want 32", ino, len(id))
				}
				var nested [32]byte
				copy(nested[:], id)
				f.nested = append(f.nested, catJob{id: nested, ino: d.Inode})
				continue
			}
			if err := s.scanDir(cat, d.Inode, f, seen); err != nil {
				return err
			}
		case catalog.TypeFile:
			if n.Nlink > 1 {
				// Promoted: the content records are in an inode shard, and
				// the shard pass collects them. The chunk lookup below
				// still runs — it costs nothing and finds nothing, and if
				// a writer ever left content records behind in the path
				// catalog they would be counted rather than lost.
				f.promoted = append(f.promoted, d.Inode)
			}
			if err := collectChunks(cat, d.Inode, f); err != nil {
				return err
			}
		default:
			// Symlinks, holes-only files and special files hold no chunks;
			// inline content rides inside the catalog entry itself, which
			// is already accounted for as the catalog's own bytes.
		}
	}
	return nil
}

// collectChunks appends one file's chunk identities. catalog.Chunks
// already refuses a list whose logical lengths do not account for the
// node length, and that refusal is exactly a reference this sweep cannot
// trust, so it propagates.
func collectChunks(cat catalog.Reader, ino int64, f *found) error {
	refs, err := cat.Chunks(ino)
	if err != nil {
		return fmt.Errorf("chunks of inode %d: %w", ino, err)
	}
	for i := range refs {
		id := refs[i].Identity
		if id == nil {
			continue // a hole: LLen zeros, no object
		}
		if len(id) != 32 {
			return fmt.Errorf("chunkref %d of inode %d has a %d-byte identity", i, ino, len(id))
		}
		f.chunks = append(f.chunks, id...)
	}
	return nil
}

// shardJob is one inode shard and the inode ranges the live generations
// route through it. One identity may be routed by several generations;
// its bytes are the same, so it is fetched once and the ranges union.
type shardJob struct {
	id     [32]byte
	ranges [][2]uint64
}

// walkShards is the second pass: the content records of promoted
// (nlink > 1) inodes live in shards rather than in the path catalog that
// holds their node row, so they can only be collected once the whole
// catalog pass has said which inodes are promoted.
//
// Routing is unioned across generations rather than evaluated per
// generation. That over-approximates — an inode promoted in one
// generation is looked up in every shard whose range covers it — and
// over-approximation is the safe direction here. Doing it per generation
// would mean re-walking every shared catalog once per generation to learn
// which of its inodes that generation promoted, which is the cost this
// sweep exists to avoid.
func (s *sweeper) walkShards(ctx context.Context) {
	jobs := s.shardJobs()
	promoted := make([]int64, 0, len(s.promoted))
	for ino := range s.promoted {
		promoted = append(promoted, ino)
	}
	sort.Slice(promoted, func(i, j int) bool { return promoted[i] < promoted[j] })

	covered := make(map[int64]bool, len(promoted))
	each(ctx, s.o.Workers, len(jobs), func(i int) {
		j := jobs[i]
		cat, release, err := s.openObject(ctx, j.id)
		if err != nil {
			s.fail("shard "+idHex(j.id), "%v", err)
			return
		}
		defer release()
		var f found
		var got []int64
		for _, r := range j.ranges {
			for _, ino := range inRange(promoted, r) {
				if _, err := cat.Stat(ino); err != nil {
					if errors.Is(err, catalog.ErrNotExist) {
						continue // another generation's shard holds it
					}
					s.fail("shard "+idHex(j.id), "stat inode %d: %v", ino, err)
					return
				}
				got = append(got, ino)
				if err := collectChunks(cat, ino, &f); err != nil {
					s.fail("shard "+idHex(j.id), "%v", err)
					return
				}
			}
		}
		if err := s.refs.Add(f.chunks); err != nil {
			s.fail("shard "+idHex(j.id), "recording references: %v", err)
			return
		}
		s.mu.Lock()
		for _, ino := range got {
			covered[ino] = true
		}
		s.mu.Unlock()
	})

	for _, ino := range promoted {
		if !covered[ino] {
			// A promoted inode no shard holds is content this sweep cannot
			// account for at all: its chunks would silently look dead.
			s.fail(fmt.Sprintf("inode %d", ino), "promoted (nlink > 1) but no live shard holds its content records")
		}
	}
}

func (s *sweeper) shardJobs() []shardJob {
	var jobs []shardJob
	at := make(map[string]int)
	for _, sb := range s.o.Live {
		for _, sh := range sb.Shards {
			if sh.FirstInode > sh.LastInode {
				s.fail("shard "+idHex(sh.Identity), "inverted inode range %d-%d", sh.FirstInode, sh.LastInode)
				continue
			}
			r := [2]uint64{sh.FirstInode, sh.LastInode}
			i, dup := at[idHex(sh.Identity)]
			if !dup {
				at[idHex(sh.Identity)] = len(jobs)
				jobs = append(jobs, shardJob{id: sh.Identity, ranges: [][2]uint64{r}})
				continue
			}
			if !slicesHasRange(jobs[i].ranges, r) {
				jobs[i].ranges = append(jobs[i].ranges, r)
			}
		}
	}
	return jobs
}

func slicesHasRange(rs [][2]uint64, r [2]uint64) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// inRange returns the sorted inodes inside an inclusive shard range.
func inRange(sorted []int64, r [2]uint64) []int64 {
	lo := sort.Search(len(sorted), func(i int) bool { return uint64(sorted[i]) >= r[0] })
	hi := sort.Search(len(sorted), func(i int) bool { return uint64(sorted[i]) > r[1] })
	return sorted[lo:hi]
}
