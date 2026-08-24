package graft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"

	"lukechampine.com/blake3"
)

func hdr() CheckpointHeader {
	return CheckpointHeader{Source: "pelican://osg-htc.org/sw", Mount: "/sw",
		Block: 1 << 20, BlockMax: 8 << 20, PerObject: 32, Hasher: "blake3-256"}
}

func rec(key string, size int64, n int) *CheckObject {
	o := &CheckObject{Key: key, Size: size, MtimeNS: 1700000000, Block: 1 << 20}
	for i := 0; i < n; i++ {
		o.IDs = append(o.IDs, chunkid.Identity(blake3.Sum256([]byte(key+string(rune(i))))))
	}
	return o
}

// TestACheckpointSurvivesTheProcessDying is the guarantee the whole
// design rests on: what was written before the crash is there afterwards,
// and it is there without an fsync per object.
func TestACheckpointSurvivesTheProcessDying(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ckpt.log")
	c, discarded, err := OpenCheckpoint(path, hdr())
	if err != nil {
		t.Fatal(err)
	}
	if discarded != "" {
		t.Fatalf("a fresh log reported %q", discarded)
	}
	for i := 0; i < 20; i++ {
		if err := c.Record(rec("obj"+string(rune('a'+i))+".bin", 1<<20, 1)); err != nil {
			t.Fatal(err)
		}
	}
	// No Close: this is the process dying, not exiting.
	c2, discarded, err := OpenCheckpoint(path, hdr())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close() //nolint:errcheck
	if discarded != "" {
		t.Fatalf("reopening the same walk discarded it: %s", discarded)
	}
	if got := c2.Resumed(); got != 20<<20 {
		t.Fatalf("resumed %d bytes, want %d: records were lost with the process", got, 20<<20)
	}
	if _, ok := c2.Done("obja.bin"); !ok {
		t.Fatal("the first record did not survive")
	}
}

// TestATornTailIsDroppedAndTheRestIsKept: a machine that died mid-write
// must cost the record it was writing and nothing else.
func TestATornTailIsDroppedAndTheRestIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ckpt.log")
	c, _, err := OpenCheckpoint(path, hdr())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := c.Record(rec("obj"+string(rune('a'+i))+".bin", 1<<20, 4)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cut the file in the middle of the last record.
	if err := os.Truncate(path, fi.Size()-30); err != nil {
		t.Fatal(err)
	}
	c2, discarded, err := OpenCheckpoint(path, hdr())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close() //nolint:errcheck
	if discarded == "" {
		t.Fatal("a torn tail was accepted silently")
	}
	t.Logf("reported: %s", discarded)
	if got := c2.Resumed(); got != 4<<20 {
		t.Fatalf("resumed %d bytes, want %d: the torn tail took good records with it", got, 4<<20)
	}
	// And the log is appendable again from the good end.
	if err := c2.Record(rec("obje.bin", 1<<20, 4)); err != nil {
		t.Fatal(err)
	}
}

// TestALogForADifferentWalkIsDiscardedAndSaidSo. A checkpoint is only a
// resume if it is a resume of THIS walk; a different block rule moves
// every identity, so half-using one would publish an index that is a
// mixture of two rules.
func TestALogForADifferentWalkIsDiscardedAndSaidSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ckpt.log")
	c, _, err := OpenCheckpoint(path, hdr())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Record(rec("a.bin", 1<<20, 1)); err != nil {
		t.Fatal(err)
	}
	c.Close() //nolint:errcheck

	for name, change := range map[string]func(CheckpointHeader) CheckpointHeader{
		"a different source":     func(h CheckpointHeader) CheckpointHeader { h.Source = "pelican://other/sw"; return h },
		"a different mount":      func(h CheckpointHeader) CheckpointHeader { h.Mount = "/elsewhere"; return h },
		"a different block size": func(h CheckpointHeader) CheckpointHeader { h.Block = 2 << 20; return h },
		"a different ceiling":    func(h CheckpointHeader) CheckpointHeader { h.BlockMax = 16 << 20; return h },
		"a different ladder":     func(h CheckpointHeader) CheckpointHeader { h.PerObject = 64; return h },
		"a keyed hasher":         func(h CheckpointHeader) CheckpointHeader { h.Hasher = "blake3-256-keyed"; return h },
	} {
		// A fresh copy each time, because opening rewrites the header.
		dir := t.TempDir()
		p2 := filepath.Join(dir, "ckpt.log")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p2, raw, 0600); err != nil {
			t.Fatal(err)
		}
		c2, discarded, err := OpenCheckpoint(p2, change(hdr()))
		if err != nil {
			t.Fatal(err)
		}
		if discarded == "" {
			t.Fatalf("%s: the log was resumed as if it were the same walk", name)
		}
		if c2.Resumed() != 0 {
			t.Fatalf("%s: %d bytes were resumed from another walk's log", name, c2.Resumed())
		}
		c2.Close() //nolint:errcheck
	}
}

// TestCheckpointPathIsDerivedFromTheWalk so that a re-run finds its own
// log without the user naming it, and two grafts in one volume do not
// share one.
func TestCheckpointPathIsDerivedFromTheWalk(t *testing.T) {
	a := CheckpointPath("/state", "/sw", "pelican://osg-htc.org/sw")
	b := CheckpointPath("/state", "/sw", "pelican://other/sw")
	c := CheckpointPath("/state", "/data", "pelican://osg-htc.org/sw")
	if a == b || a == c || b == c {
		t.Fatal("two different grafts share a checkpoint path")
	}
	if a != CheckpointPath("/state", "/sw", "pelican://osg-htc.org/sw") {
		t.Fatal("the same graft does not find its own checkpoint")
	}
}
