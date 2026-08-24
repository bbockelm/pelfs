package genfs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/graft"
)

// A graft-integrity failure is its own error CLASS.
//
// Before it was one, the two ways a grafted read fails arrived at a caller
// identically: "the third party was unreachable", which is worth retrying,
// and "the third party republished the file", where every retry from now
// until someone runs `pelfs graft --refresh` returns the same wrong bytes.
// A job that retries on I/O errors spins forever on the second.

// TestAChangedSourceIsAGraftIntegrityError, and carries the evidence
// rather than only a sentence.
func TestAChangedSourceIsAGraftIntegrityError(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	p := filepath.Join(f.srcDir, "data", "multi.bin")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[20000] ^= 0xff
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	_, err = fs.Read(ctx, ino, 19000, make([]byte, 2000))
	if err == nil {
		t.Fatal("a read of a mutated source succeeded")
	}
	if !errors.Is(err, genfs.ErrGraftIntegrity) {
		t.Fatalf("a changed source is not classified as a graft-integrity failure: %v", err)
	}
	var gi *genfs.GraftIntegrityError
	if !errors.As(err, &gi) {
		t.Fatalf("the error does not carry the details: %v", err)
	}
	if gi.Kind != genfs.GraftHashMismatch {
		t.Fatalf("kind is %v, want a hash mismatch", gi.Kind)
	}
	if gi.Graft != "/ext" || gi.Source == "" || gi.Key == "" {
		t.Fatalf("the error does not name the graft, source and object: %+v", gi)
	}
	if gi.Want == "" || gi.Got == "" || gi.Want == gi.Got {
		t.Fatalf("the error does not carry both hashes: %+v", gi)
	}
	if gi.Length == 0 {
		t.Fatalf("the error does not carry the range: %+v", gi)
	}
	// The wording is unchanged: this was a classification change, and the
	// message already named the graft, the object, both hashes and the fix.
	for _, want := range []string{"graft /ext", "the graft source has changed", "--refresh"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message lost %q: %v", want, err)
		}
	}
}

// TestATruncatedSourceIsAlsoAnIntegrityError. It is the same class — the
// source no longer holds what was published — with different evidence.
//
// The truncation is INSIDE the block being read, deliberately. A source
// truncated below the block's START comes back as a transport error (HTTP
// 416) and is classified as one: distinguishing "the object shrank" from
// any other range refusal would mean parsing the transport's status here,
// or spending a HEAD on every failure, and the read fails closed either
// way. That limit is stated in docs/design-graft.md rather than papered
// over.
func TestATruncatedSourceIsAlsoAnIntegrityError(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	p := filepath.Join(f.srcDir, "data", "multi.bin")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw[:20000], 0o644); err != nil {
		t.Fatal(err)
	}
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	_, err = fs.Read(ctx, ino, 19000, make([]byte, 2000))
	if err == nil {
		t.Fatal("a read past the end of a truncated source succeeded")
	}
	if !errors.Is(err, genfs.ErrGraftIntegrity) {
		t.Fatalf("a truncated source is not an integrity failure: %v", err)
	}
	var gi *genfs.GraftIntegrityError
	if !errors.As(err, &gi) {
		t.Fatalf("no details: %v", err)
	}
	if gi.Kind != genfs.GraftShortObject {
		t.Fatalf("kind is %v, want a short object", gi.Kind)
	}
	if gi.Have >= gi.Length {
		t.Fatalf("a short object reported %d of %d bytes", gi.Have, gi.Length)
	}
	if st := fs.GraftStats(); st.Mismatch == 0 {
		t.Fatal("a truncated source did not move the mismatch counter, so an operator " +
			"watching that number would call it a network problem")
	}
}

// TestAnUnREACHABLESourceIsNotAnIntegrityError. This is the half that
// makes the class worth having: the same read failing for a reason that IS
// worth retrying must not be classified as "the data changed".
func TestAnUnreachableSourceIsNotAnIntegrityError(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	f.offline()
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	_, err := fs.Read(ctx, ino, 0, make([]byte, 2000))
	if err == nil {
		t.Fatal("a read with the source offline succeeded without a prefetch")
	}
	if errors.Is(err, genfs.ErrGraftIntegrity) {
		t.Fatalf("an unreachable source was reported as changed data: %v", err)
	}
	st := fs.GraftStats()
	if st.Failures == 0 {
		t.Fatal("an unreachable source did not count as a failure")
	}
	if st.Mismatch != 0 {
		t.Fatalf("an unreachable source moved the mismatch counter to %d", st.Mismatch)
	}
}
