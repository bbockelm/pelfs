// Chunk-boundary fingerprint.
//
// Chunk boundaries are a volume's IDENTITY DOMAIN. If they move, every
// existing volume stops deduping against new writes: the same bytes
// produce different chunks, so nothing already stored is recognised, and
// the next seal re-uploads a tree it already holds. Nothing else in the
// suite would notice — every test still passes, every file still reads
// back — which is what makes a pinned digest the only guard available.
//
// The synthetic half is pinned and runs everywhere. The corpus half needs
// files this repository does not carry, so it is measured and logged
// rather than asserted.
package dedupbench

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// TestBoundaryFingerprint digests every chunk boundary the chunker
// produces over a spread of inputs: empty, sub-min, exactly-min, random,
// low-entropy (forces max cuts), highly repetitive, and every file in the
// corpus above MinSize.
// syntheticFingerprint is the digest of every boundary the chunker cuts
// over the synthetic inputs below. It is a CONSTANT of the format, not a
// property of this test: changing it silently strands every volume that
// was written before the change.
//
// If a change to internal/chunkid moves it, that change needs a migration
// story or a version bump on the identity domain — not a new constant
// here.
const syntheticFingerprint = "a3b7481557605c3288bdb16451d29db2bab5d8b3049f075c740992ce19c25260"

func TestBoundaryFingerprint(t *testing.T) {
	h := blake3.New(32, nil)
	var chunks, total int64

	run := func(label string, data []byte) {
		ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
		h.Write([]byte(label)) //nolint:errcheck
		for {
			c, err := ck.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			var rec [16]byte
			binary.LittleEndian.PutUint64(rec[:8], uint64(c.Offset))
			binary.LittleEndian.PutUint64(rec[8:], uint64(len(c.Data)))
			h.Write(rec[:]) //nolint:errcheck
			id := blake3.Sum256(c.Data)
			h.Write(id[:]) //nolint:errcheck
			chunks++
			total += int64(len(c.Data))
		}
	}

	// Synthetic edge cases.
	for _, n := range []int{0, 1, 4095, 4096, 1 << 20, (1 << 20) + 1, 4 << 20, (16 << 20) - 1, 16 << 20, (16 << 20) + 1, 40 << 20} {
		run(fmt.Sprintf("rand%d", n), randomBytes(n, int64(n)+1))
	}
	// Low-entropy inputs: the cut mask rarely fires, so forced max cuts
	// dominate — the path most sensitive to how much lookahead the window
	// holds.
	zeros := make([]byte, 40<<20)
	run("zeros", zeros)
	rep := make([]byte, 40<<20)
	for i := range rep {
		rep[i] = byte(i % 7)
	}
	run("repeat7", rep)
	// Streams whose length straddles the window boundary exactly.
	for _, n := range []int{(16 << 20) - 1, 16 << 20, (16 << 20) + 1, (32 << 20) - 1, 32 << 20} {
		run(fmt.Sprintf("straddle%d", n), randomBytes(n, 999))
	}

	if got := fmt.Sprintf("%x", h.Sum(nil)); got != syntheticFingerprint {
		t.Fatalf("chunk boundaries moved:\n  now    %s\n  pinned %s\n"+
			"Every volume written before this change stops deduping against new writes.",
			got, syntheticFingerprint)
	}
	t.Logf("synthetic fingerprint %s (%d chunks, %s)", syntheticFingerprint, chunks, mib(total))

	// Every corpus file that can produce more than one chunk. Measured
	// rather than pinned: this repository does not carry a corpus, so the
	// digest is not reproducible for everyone who runs the suite.
	corpus := blake3.New(32, nil)
	h = corpus
	chunks, total = 0, 0
	if root := os.Getenv("PELFS_CORPUS_A"); root != "" {
		for _, f := range walkCorpus(t, root) {
			if f.size <= chunkid.DefaultMinSize {
				continue
			}
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			run(f.path[len(root):], data)
		}
	}
	// A big concatenated stream, so cuts land at many alignments.
	if p := os.Getenv("PELFS_BIGFILE"); p != "" {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512<<20)
		if _, err := io.ReadFull(f, buf); err != nil {
			t.Fatal(err)
		}
		f.Close() //nolint:errcheck
		run("bigfile", buf)
		run("bigfile-shift1", buf[1:])
		run("bigfile-shift4095", buf[4095:])
	}

	if chunks > 0 {
		t.Logf("corpus fingerprint %x (%d chunks, %s)", corpus.Sum(nil), chunks, mib(total))
	}
}
