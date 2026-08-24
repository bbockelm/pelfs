package graft

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// The concurrency measurement behind the default in SpiderOptions.
//
// It is skipped unless PELFS_GRAFT_BENCH=1 so that `go test ./...` stays
// fast; the table it prints is what docs/design-graft.md quotes, and it
// is reproducible with one env var rather than being a number someone
// remembered.
//
// It runs against cmd/fakeorigin's handler over loopback, at two
// latencies, and the second one is the point: with no latency term a
// loopback origin answers before a second request can be issued, so the
// table would measure BLAKE3 and nothing else. A real graft source is
// tens of milliseconds away, and how many workers saturate it is a
// function of that.
func TestSpiderThroughputTable(t *testing.T) {
	if os.Getenv("PELFS_GRAFT_BENCH") != "1" {
		t.Skip("set PELFS_GRAFT_BENCH=1 to run the concurrency measurement")
	}
	root := t.TempDir()
	// A tree shaped like the case this is for: a few large objects and
	// many medium ones, so both dimensions of parallelism are exercised.
	const (
		bigCount   = 4
		bigSize    = 64 << 20
		smallCount = 200
		smallSize  = 1 << 20
	)
	var total int64
	write := func(name string, n int) {
		p := filepath.Join(root, "ext", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*31 + len(name))
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		total += int64(n)
	}
	for i := 0; i < bigCount; i++ {
		write(fmt.Sprintf("big/%02d.bin", i), bigSize)
	}
	for i := 0; i < smallCount; i++ {
		write(fmt.Sprintf("many/%03d.bin", i), smallSize)
	}
	t.Logf("source tree: %d objects, %d MB", bigCount+smallCount, total>>20)

	for _, rtt := range []time.Duration{0, 5 * time.Millisecond, 20 * time.Millisecond} {
		srv := httptest.NewServer(fakeorigin.HandlerWithDelay(root, rtt))
		src, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/ext"})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("--- simulated RTT %s ---", rtt)
		t.Logf("%-12s %-12s %-12s", "workers", "seconds", "MB/s")
		for _, workers := range []int{1, 2, 4, 8, 16, 32, 64} {
			dir := t.TempDir()
			w, err := NewWriter(dir, DefaultBlock)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			res, err := Spider(context.Background(), SpiderOptions{
				Src: src, Index: w, Policy: DefaultPolicy(), Concurrency: workers,
			})
			el := time.Since(start)
			w.Close() //nolint:errcheck
			os.RemoveAll(dir)
			if err != nil {
				t.Fatalf("workers=%d: %v", workers, err)
			}
			t.Logf("%-12d %-12.2f %-12.1f", workers, el.Seconds(),
				float64(res.BytesHashed)/el.Seconds()/(1<<20))
		}
		srv.Close()
	}
}

// BenchmarkBlockDigest is the floor the table above cannot beat: what one
// core costs to hash a block. It is what tells you whether a measured
// ceiling is the network or the CPU.
func BenchmarkBlockDigest(b *testing.B) {
	buf := make([]byte, DefaultBlock)
	for i := range buf {
		buf[i] = byte(i)
	}
	h := chunkid.NewHasher(nil)
	b.SetBytes(DefaultBlock)
	for i := 0; i < b.N; i++ {
		_ = h.Sum(buf)
	}
}
