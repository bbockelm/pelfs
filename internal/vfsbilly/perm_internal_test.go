package vfsbilly

import (
	"os"
	"path/filepath"
	"testing"
)

// The capability set is read from /proc/self/status, and getting it wrong
// is not a small error: reading uid alone would say the hostile container's
// root may write a 0444 file, when the container drops CAP_DAC_OVERRIDE and
// every local filesystem in it refuses. The masks below are the real ones.
func TestCapabilitiesComeFromCapEff(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want Caps
	}{
		{
			name: "an unconfined root process holds all four",
			line: "CapEff:\t000001ffffffffff\n",
			want: CapChown | CapDACOverride | CapDACReadSearch | CapFOwner,
		},
		{
			// scripts/hostile-docker.sh: --cap-drop ALL --cap-add
			// SYS_ADMIN,CHOWN,FOWNER. Bits 0 (CHOWN), 3 (FOWNER) and 21
			// (SYS_ADMIN). DAC_OVERRIDE is bit 1 and is NOT here, which is
			// why the reference tmpfs in that container refuses a write to
			// a 0444 file and why this mount must too.
			name: "the hostile container: CHOWN and FOWNER, no DAC_OVERRIDE",
			line: "CapEff:\t0000000000200009\n",
			want: CapChown | CapFOwner,
		},
		{
			// The same launcher with --drop-chown: SYS_ADMIN alone.
			name: "--drop-chown leaves nothing that changes a permission answer",
			line: "CapEff:\t0000000000200000\n",
			want: 0,
		},
		{
			name: "an ordinary user holds none",
			line: "CapEff:\t0000000000000000\n",
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "status")
			body := "Name:\tpelfs\nUid:\t0\t0\t0\t0\n" + tc.line + "CapBnd:\t000001ffffffffff\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, ok := capsFromProcStatus(path)
			if !ok {
				t.Fatal("CapEff line not found in a file that has one")
			}
			if got != tc.want {
				t.Errorf("caps = %04b, want %04b", got, tc.want)
			}
		})
	}

	// A status file without the line, and a path that is not there at all,
	// both report "unknown" rather than "no capabilities" -- the caller
	// falls back to the uid rule, and cannot do that if it is told zero.
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte("Name:\tpelfs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := capsFromProcStatus(path); ok {
		t.Error("a status file with no CapEff line reported a capability set")
	}
	if _, ok := capsFromProcStatus(filepath.Join(t.TempDir(), "absent")); ok {
		t.Error("a missing status file reported a capability set")
	}
}

// The class rules, at the model itself: one class decides, first match
// wins, and the two DAC capabilities are the only fallback.
func TestClassSelectionIsFirstMatchWins(t *testing.T) {
	me := Cred{UID: 10, GID: 20, Groups: []uint32{30}}
	for _, tc := range []struct {
		name     string
		uid, gid uint32
		mode     uint32
		want     perm
		wantOK   bool
	}{
		{"owner class grants", 10, 99, 0o600, permRead | permWrite, true},
		{"owner class denies without falling through", 10, 99, 0o066, permWrite, false},
		{"primary group counts", 99, 20, 0o060, permWrite, true},
		{"a supplementary group counts", 99, 30, 0o060, permWrite, true},
		{"group denies without falling through to other", 99, 30, 0o006, permWrite, false},
		{"other class is the last resort", 99, 99, 0o006, permWrite, true},
	} {
		if got := me.allowed(tc.uid, tc.gid, tc.mode, false, tc.want); got != tc.wantOK {
			t.Errorf("%s: allowed(%d:%d %04o, %s) = %v, want %v",
				tc.name, tc.uid, tc.gid, tc.mode, tc.want, got, tc.wantOK)
		}
	}

	// DAC_OVERRIDE is total on a directory and on read/write, but it does
	// not conjure an execute bit onto a file that has none for anybody --
	// the one exception the kernel makes.
	root := Cred{UID: 0, Caps: CapDACOverride}
	if !root.allowed(10, 20, 0o000, true, permRead|permWrite|permExec) {
		t.Error("CAP_DAC_OVERRIDE did not open a 0000 directory")
	}
	if !root.allowed(10, 20, 0o000, false, permRead|permWrite) {
		t.Error("CAP_DAC_OVERRIDE did not open a 0000 file for read and write")
	}
	if root.allowed(10, 20, 0o666, false, permExec) {
		t.Error("CAP_DAC_OVERRIDE invented an execute bit on a file that has none")
	}
	if !root.allowed(10, 20, 0o111, false, permExec) {
		t.Error("CAP_DAC_OVERRIDE refused a file that does have an execute bit")
	}
}
