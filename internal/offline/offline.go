// Package offline implements maintenance operations that run against a
// volume without mounting it: garbage collection of leaked block objects
// (uploaded by sessions that crashed before committing metadata) and a
// consistency check that every block referenced by metadata exists in the
// federation. Both mirror the essentials of `juicefs gc` / `juicefs fsck`.
package offline

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
)

// Options configures GC and Fsck.
type Options struct {
	MetaPath string               // local sqlite metadata database
	Blob     object.ObjectStorage // prefix-rooted store (encryption-wrapped when the volume is encrypted)
	Delete   bool                 // GC only: actually delete leaked objects
	MinAge   time.Duration        // GC only: never touch objects newer than this (default 1h)
}

// GCReport summarizes a garbage-collection scan.
type GCReport struct {
	UsedSlices  int
	Scanned     int
	Valid       int
	Skipped     int // too new to judge safely
	Leaked      int
	LeakedBytes int64
	Deleted     int
}

// FsckReport summarizes a consistency check.
type FsckReport struct {
	Slices      int
	Blocks      int
	Missing     int
	MissingKeys []string // capped sample
}

func openMeta(metaPath string) (meta.Meta, *meta.Format, error) {
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format, err := m.Load(true)
	if err != nil {
		return nil, nil, fmt.Errorf("load volume metadata: %w", err)
	}
	if err := m.NewSession(false); err != nil {
		return nil, nil, fmt.Errorf("metadata session: %w", err)
	}
	return m, format, nil
}

// usedSlices returns every slice ID referenced by the metadata engine,
// including pending-delete ones (their blocks are not leaked; the engine
// still owns them).
func usedSlices(ctx context.Context, m meta.Meta) (map[uint64]uint32, error) {
	used := make(map[uint64]uint32)
	c := meta.WrapContext(ctx)
	if st := m.ScanSlices(c, &meta.ScanSlicesOption{ScanPending: true}, func(_ meta.Ino, s meta.Slice) error {
		if s.Id > 0 {
			used[s.Id] = s.Size
		}
		return nil
	}); st != 0 {
		return nil, fmt.Errorf("scan slices: %s", st)
	}
	return used, nil
}

// GC scans <prefix>/chunks/ for block objects whose slice ID is not
// referenced by the metadata, reporting (and with Delete, removing) them.
func GC(ctx context.Context, o Options) (*GCReport, error) {
	if o.MinAge <= 0 {
		o.MinAge = time.Hour
	}
	m, _, err := openMeta(o.MetaPath)
	if err != nil {
		return nil, err
	}
	defer m.CloseSession() //nolint:errcheck

	used, err := usedSlices(ctx, m)
	if err != nil {
		return nil, err
	}
	rep := &GCReport{UsedSlices: len(used)}

	blocks := object.WithPrefix(o.Blob, "chunks/")
	objs, err := object.ListAll(ctx, blocks, "", "", true, false)
	if err != nil {
		return nil, fmt.Errorf("list blocks: %w", err)
	}
	cutoff := time.Now().Add(-o.MinAge)
	for obj := range objs {
		if obj == nil {
			return rep, fmt.Errorf("listing blocks failed partway through")
		}
		if obj.IsDir() {
			continue
		}
		rep.Scanned++
		id, ok := parseBlockKey(obj.Key())
		if !ok {
			rep.Skipped++
			continue
		}
		if _, ok := used[id]; ok {
			rep.Valid++
			continue
		}
		if obj.Mtime().After(cutoff) {
			// Could belong to an in-flight write from a live session.
			rep.Skipped++
			continue
		}
		rep.Leaked++
		rep.LeakedBytes += obj.Size()
		if o.Delete {
			if err := blocks.Delete(ctx, obj.Key()); err != nil {
				fmt.Printf("pelfs gc: delete %s: %v\n", obj.Key(), err)
			} else {
				rep.Deleted++
			}
		}
	}
	return rep, nil
}

// parseBlockKey extracts the slice ID from a block key of the form
// <dir>/<dir>/<id>_<indx>_<size> (relative to chunks/).
func parseBlockKey(key string) (uint64, bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		return 0, false
	}
	fields := strings.Split(parts[2], "_")
	if len(fields) != 3 {
		return 0, false
	}
	id, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

// Fsck verifies that every block referenced by the metadata exists in the
// federation.
func Fsck(ctx context.Context, o Options) (*FsckReport, error) {
	m, format, err := openMeta(o.MetaPath)
	if err != nil {
		return nil, err
	}
	defer m.CloseSession() //nolint:errcheck

	used, err := usedSlices(ctx, m)
	if err != nil {
		return nil, err
	}
	blockSize := format.BlockSize * 1024
	rep := &FsckReport{Slices: len(used)}

	type block struct{ key string }
	work := make(chan block, 256)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range work {
				if _, err := o.Blob.Head(ctx, b.key); err != nil {
					mu.Lock()
					rep.Missing++
					if len(rep.MissingKeys) < 20 {
						rep.MissingKeys = append(rep.MissingKeys, b.key)
					}
					mu.Unlock()
				}
			}
		}()
	}
	for id, size := range used {
		if size == 0 {
			continue
		}
		n := int(size-1)/blockSize + 1
		for indx := 0; indx < n; indx++ {
			bsize := blockSize
			if indx == n-1 {
				bsize = int(size) - indx*blockSize
			}
			rep.Blocks++
			work <- block{key: blockKey(format.HashPrefix, id, indx, bsize)}
		}
	}
	close(work)
	wg.Wait()
	return rep, nil
}

// blockKey mirrors JuiceFS's chunk object naming (pkg/chunk rSlice.key).
func blockKey(hashPrefix bool, id uint64, indx, bsize int) string {
	if hashPrefix {
		return fmt.Sprintf("chunks/%02X/%v/%v_%v_%v", id%256, id/1000/1000, id, indx, bsize)
	}
	return fmt.Sprintf("chunks/%v/%v/%v_%v_%v", id/1000/1000, id/1000, id, indx, bsize)
}
