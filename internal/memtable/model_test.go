package memtable

import (
	"bytes"
	"context"
	"math/rand/v2"
	"sync"
	"testing"
)

// model is what the filesystem is supposed to contain: a plain byte
// slice per inode, with holes as zeros. The ref map that replaces it in
// the store is the part with the arithmetic, and the only cheap way to
// trust that arithmetic is to run it against something with none.
type model map[uint64][]byte

func (m model) write(ino uint64, off int64, p []byte) {
	b := m[ino]
	if end := off + int64(len(p)); int64(len(b)) < end {
		b = append(b, make([]byte, end-int64(len(b)))...)
	}
	copy(b[off:], p)
	m[ino] = b
}

func (m model) truncate(ino uint64, size int64) {
	b := m[ino]
	if int64(len(b)) > size {
		b = b[:size]
	} else {
		b = append(b, make([]byte, size-int64(len(b)))...)
	}
	m[ino] = b
}

// Random writes, partial overwrites, truncates and flushes, checked
// against the model after every step. This is the test that found the
// reference-count sign error, which nothing hand-written had caught.
func TestRandomWritesMatchAModel(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 96<<10, Hooks{})
	m := model{}
	r := rand.New(rand.NewPCG(0xfeed, 0xbeef))

	const inodes = 6
	for step := range 600 {
		ino := uint64(1 + r.IntN(inodes))
		switch n := r.IntN(100); {
		case n < 70:
			off := int64(r.IntN(9000))
			p := fill(1+r.IntN(4000), uint64(step))
			if err := s.Write(ctx, ino, off, p); err != nil {
				t.Fatalf("step %d write: %v", step, err)
			}
			m.write(ino, off, p)
		case n < 85:
			size := int64(r.IntN(9000))
			s.Truncate(ino, size)
			m.truncate(ino, size)
		default:
			if err := s.Flush(ctx); err != nil {
				t.Fatalf("step %d flush: %v", step, err)
			}
		}
		for i := uint64(1); i <= inodes; i++ {
			if got, want := readAll(t, s, i), m[i]; !bytes.Equal(got, want) {
				t.Fatalf("step %d: inode %d diverged: %d bytes vs %d", step, i, len(got), len(want))
			}
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= inodes; i++ {
		if got, want := readAll(t, s, i), m[i]; !bytes.Equal(got, want) {
			t.Fatalf("inode %d diverged after the final flush", i)
		}
	}
}

// Readers running across a flush are the reason a source pins its table.
// Under the race detector a missed pin is an unmapped read, which is a
// crash rather than a wrong answer — so this test's job is to keep
// readers busy while tables are recycled underneath them.
func TestConcurrentReadsAcrossFlushes(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 128<<10, Hooks{})
	want := make(map[uint64][]byte)
	for ino := uint64(1); ino <= 8; ino++ {
		want[ino] = fill(20000, ino)
		if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
			t.Fatal(err)
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, 20000)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for ino := uint64(1); ino <= 8; ino++ {
					n, err := s.Read(ctx, ino, 0, buf)
					if err != nil {
						t.Errorf("read inode %d: %v", ino, err)
						return
					}
					if !bytes.Equal(buf[:n], want[ino]) {
						t.Errorf("inode %d read back wrong under concurrent flushes", ino)
						return
					}
				}
			}
		})
	}
	for range 6 {
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		// Give the readers something new to chase on the next round.
		if err := s.Write(ctx, 9, 0, fill(60000, 9)); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}
