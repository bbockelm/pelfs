package idmap

import (
	"os"
	"testing"
)

// The volume's own identity is translated and nothing else is. Both
// halves matter: without the first a volume made elsewhere is unwritable,
// and without the second chown becomes invisible and `tar -p`, `cp -a`
// and every installer appear to succeed while doing nothing.
func TestOnlyTheVolumeIdentityIsTranslated(t *testing.T) {
	// A volume created on a laptop as 501:20, mounted on a cluster as
	// 20114:5000.
	m := Map{FromUID: 501, FromGID: 20, ToUID: 20114, ToGID: 5000}
	for _, tc := range []struct {
		name             string
		uid, gid         uint32
		wantUID, wantGID uint32
	}{
		{"the volume's own files", 501, 20, 20114, 5000},
		{"a file chowned to someone else", 4242, 4343, 4242, 4343},
		{"root-owned content", 0, 0, 0, 0},
		{"the mounting user's own id, stored", 20114, 5000, 20114, 5000},
		{"owner matches, group does not", 501, 4343, 20114, 4343},
		{"group matches, owner does not", 4242, 20, 4242, 5000},
	} {
		uid, gid := m.Apply(tc.uid, tc.gid)
		if uid != tc.wantUID || gid != tc.wantGID {
			t.Errorf("%s: %d:%d -> %d:%d, want %d:%d",
				tc.name, tc.uid, tc.gid, uid, gid, tc.wantUID, tc.wantGID)
		}
	}
}

// Preserve has to be exact: a caller that asks for stored ownership is
// asking because the numbers matter.
func TestPreserveTranslatesNothing(t *testing.T) {
	m := Map{FromUID: 501, FromGID: 20, ToUID: 20114, ToGID: 5000, Preserve: true}
	for _, stored := range [][2]uint32{{0, 0}, {501, 20}, {4242, 4343}} {
		uid, gid := m.Apply(stored[0], stored[1])
		if uid != stored[0] || gid != stored[1] {
			t.Errorf("stored %v reported as %d:%d", stored, uid, gid)
		}
	}
}

// A volume rooted at uid 0 — the shape publish.InitVolume used to
// produce, and what a zero Map means — must become writable, because that
// is the case that is otherwise unrecoverable without root.
func TestARootOwnedVolumeBecomesTheMountersOwn(t *testing.T) {
	m := Owner(0, 0)
	uid, gid := m.Apply(0, 0)
	if uid != uint32(os.Getuid()) || gid != uint32(os.Getgid()) {
		t.Fatalf("root-owned content reported as %d:%d, want %d:%d",
			uid, gid, os.Getuid(), os.Getgid())
	}
}

// Mounting a volume on the machine that made it must change nothing at
// all, which is both the common case and the one where a surprise would
// be least welcome.
func TestOwnerIsIdentityOnItsOwnMachine(t *testing.T) {
	m := Owner(uint32(os.Getuid()), uint32(os.Getgid()))
	if !m.Identity() {
		t.Fatalf("a volume mounted where it was made is remapped: %+v", m)
	}
	for _, stored := range [][2]uint32{{0, 0}, {4242, 4343}, {uint32(os.Getuid()), uint32(os.Getgid())}} {
		uid, gid := m.Apply(stored[0], stored[1])
		if uid != stored[0] || gid != stored[1] {
			t.Errorf("stored %v reported as %d:%d on its own machine", stored, uid, gid)
		}
	}
}
