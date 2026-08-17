package chunkid_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// wantIdentityFingerprint pins the chunker's IDENTITY DOMAIN: the exact
// boundaries it cuts, over a spread of inputs, digested into one hash.
//
// Chunk boundaries are content identity in this format. Move them and the
// same bytes hash to different identities, which silently forks every
// volume ever written: cross-generation content reuse stops matching, the
// dedup index stops hitting, and a seal re-uploads a tree it already
// holds. None of that fails loudly — it just gets slower and larger
// forever, which is why it is pinned rather than left to be noticed.
//
// A deliberate change to the chunking parameters is allowed to change this
// value, but only as an explicit decision with a format-compatibility
// story. An INCIDENTAL change — a refactor of the rolling window, a
// buffering tweak — must not.
const wantIdentityFingerprint = "1cc58071e2db6a9427f43dde0cc55dd167f8bdeb702b6138d1bd64e3b27c0e25"

func TestChunkIdentityDomainIsStable(t *testing.T) {
	h := blake3.New(32, nil)

	run := func(label string, data []byte) {
		ck := chunkid.NewChunker(bytes.NewReader(data), chunkid.Options{})
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
		}
	}

	// Sizes straddling every threshold the cut loop cares about: empty,
	// sub-minimum, exactly minimum, and either side of the maximum.
	for _, n := range []int{0, 1, 4095, 4096, 1 << 20, (1 << 20) + 1, 4 << 20, (16 << 20) - 1, 16 << 20, (16 << 20) + 1, 40 << 20} {
		run(fmt.Sprintf("rand%d", n), seededBytes(n, int64(n)+1))
	}
	// Low-entropy input: the cut mask rarely fires, so forced maximum cuts
	// dominate. That is the path most sensitive to how much lookahead the
	// rolling window retains, and the one a buffering change would move.
	run("zeros", make([]byte, 40<<20))
	rep := make([]byte, 40<<20)
	for i := range rep {
		rep[i] = byte(i % 251)
	}
	run("repeating", rep)

	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != wantIdentityFingerprint {
		t.Fatalf("chunk boundaries moved: fingerprint %s, want %s\n"+
			"Every existing volume's content identities were computed with the old boundaries, "+
			"so this silently breaks cross-generation reuse and dedup. If the change was deliberate, "+
			"update the constant and say why in the commit message.", got, wantIdentityFingerprint)
	}
}

func seededBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(seed))
	_, _ = r.Read(b)
	return b
}
