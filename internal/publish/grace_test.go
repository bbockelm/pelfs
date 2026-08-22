package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// T_grace as a PER-VOLUME PARAMETER, which it was documented to be for
// three releases and was not: publish stated a build-time constant on every
// generation it wrote, so `Params.TGraceSeconds` was a field that could
// only ever hold one value.
//
// The three properties below are what makes the knob real rather than
// decorative. Generation 0 records what its creator asked for; every seal
// after it carries the RECORDED value rather than re-stating a default;
// and a window under the floor is refused before a volume exists.

// newGraceKey mints a volume identity for the refusal cases, which create
// their volumes directly rather than through testvol.
func newGraceKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// INVARIANT: the window a volume is created with is the window it records.
func TestAVolumeRecordsTheGraceWindowItWasCreatedWith(t *testing.T) {
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{Grace: 12 * time.Hour})
	if got := v.Superblock().Params.Grace(); got != 12*time.Hour {
		t.Fatalf("generation 0 records a %v grace window, want 12h; the volume's own sweep, its repack "+
			"planner and its three ledgers all read this field, so a window that is not recorded is a "+
			"window nothing applies", got)
	}
}

// INVARIANT: a seal carries the recorded window forward, and this is the
// half that makes the parameter survive.
//
// A seal that re-stated the build-time default would move the window on
// every checkpoint: a volume created at 12h would be back at 72h one seal
// later, its ledgers would age against a window its own gc did not use, and
// the parameter would exist only on generation 0. Which is exactly what the
// code did before this change, and exactly what the docs said it did not.
func TestSealsCarryTheRecordedGraceWindowForward(t *testing.T) {
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{Grace: 12 * time.Hour})
	v.WriteFile(testvol.RootInode, "a.txt", []byte("first"))
	first := v.Publish(publish.Options{})
	if got := first.Superblock.Params.Grace(); got != 12*time.Hour {
		t.Fatalf("the first seal records a %v window, want the 12h generation 0 recorded", got)
	}
	// Twice, because carrying forward once could be an accident of the
	// parent being generation 0.
	v.WriteFile(testvol.RootInode, "b.txt", []byte("second"))
	second := v.Publish(publish.Options{})
	if got := second.Superblock.Params.Grace(); got != 12*time.Hour {
		t.Fatalf("generation %d records a %v window, want the 12h the volume was created with; the window "+
			"has to be a property of the VOLUME, not of the binary that happened to seal it",
			second.Superblock.Generation, got)
	}
	if second.Superblock.Params.Grace() == publish.DefaultGrace {
		t.Fatal("fixture: the test window equals the default, so carrying forward and re-stating the " +
			"default are indistinguishable and this proves nothing")
	}
}

// INVARIANT: a window under the floor is refused, and refused BEFORE
// anything is written.
//
// The window is what makes a sweep safe beside a live writer with no
// coordination: a pack younger than it may be one a concurrent seal is
// about to reference. At zero, `pelfs gc --delete` races that seal into
// data loss — so this is the one place in the knob where clamping silently
// would be worse than refusing.
func TestAGraceWindowUnderTheFloorIsRefused(t *testing.T) {
	inner := newInner(t)
	_, err := publish.InitVolume(context.Background(), publish.Options{
		Inner:      inner,
		SpoolDir:   t.TempDir(),
		Branch:     "main",
		SigningKey: newGraceKey(t),
		VolumeID:   [16]byte{0x67, 0x72, 0x01},
		Grace:      time.Minute,
	})
	if err == nil {
		t.Fatal("a one-minute grace window was accepted; the age guard is the only thing protecting a " +
			"pack a concurrent writer has cut and not yet named, so this volume's next sweep can delete " +
			"live data")
	}
	// And the floor itself is accepted, so the refusal is a floor rather
	// than a ban on saying anything.
	if _, err := publish.InitVolume(context.Background(), publish.Options{
		Inner:      inner,
		SpoolDir:   t.TempDir(),
		Branch:     "floor",
		SigningKey: newGraceKey(t),
		VolumeID:   [16]byte{0x67, 0x72, 0x02},
		Grace:      publish.MinGrace,
	}); err != nil {
		t.Fatalf("the floor value itself was refused: %v", err)
	}
}
