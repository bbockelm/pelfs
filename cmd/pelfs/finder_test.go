package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVolumeName(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, override, want string
	}{
		{"last component of the prefix", "pelican://osg-htc.org/pelfs/survey", "", "survey"},
		{"trailing slash", "pelican://osg-htc.org/pelfs/survey/", "", "survey"},
		{"one component", "pelican://osg-htc.org/data", "", "data"},
		// A bare federation URL has no last component to speak of: the
		// trailing empty segment is not a name, and the scheme's own
		// slashes must not become one.
		{"no path at all", "pelican://osg-htc.org/", "", "osg-htc.org"},
		{"override wins", "pelican://osg-htc.org/pelfs/survey", "Field Notes", "Field Notes"},
		// A colon is legal in a POSIX file name and the Finder shows it as
		// a slash, so a volume called "a:b" would read as "a/b".
		{"colon in the name", "pelican://fed/a:b", "", "a-b"},
		{"slash in an override", "pelican://fed/x", "a/b", "a-b"},
		// A leading dot would hide the mount point from the Finder and the
		// shell both, which is the one thing --finder exists to avoid.
		{"leading dot", "pelican://fed/.hidden", "", "hidden"},
		{"nothing usable", "pelican://fed/...", "", "pelfs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := volumeName(tc.prefix, tc.override)
			if err != nil {
				t.Fatalf("volumeName: %v", err)
			}
			if got != tc.want {
				t.Errorf("volumeName(%q, %q) = %q, want %q", tc.prefix, tc.override, got, tc.want)
			}
		})
	}
	// An override with nothing left after sanitizing is an error rather
	// than a silent fallback: the user typed a name, and being given a
	// different one without being told is worse than being asked again.
	if _, err := volumeName("pelican://fed/x", ". ."); err == nil {
		t.Error("an unusable --volume-name was accepted")
	}
}

func TestSanitizeVolumeName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// Spaces stay: "Survey Data" is an ordinary name for a volume.
		{"Survey Data", "Survey Data"},
		{"a/b:c", "a-b-c"},
		{"tab\there", "tabhere"},
		{"trailing. ", "trailing"},
		{" . leading", "leading"},
		{"..", ""},
		{"Ünicode ✓", "Ünicode ✓"},
	} {
		if got := sanitizeVolumeName(tc.in); got != tc.want {
			t.Errorf("sanitizeVolumeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A name longer than a file name can be is cut, and cut on a rune
	// boundary: a truncated multi-byte sequence would be a name no
	// filesystem accepts.
	long := sanitizeVolumeName(strings.Repeat("é", 400))
	if len(long) > 255 {
		t.Errorf("a long name was not cut: %d bytes", len(long))
	}
	if !isValidUTF8(long) {
		t.Error("cutting a long name split a rune")
	}
	// A sanitized name must be usable as a directory name, which is the
	// whole point of sanitizing it: the mount point is <dir>/<name>.
	dir := t.TempDir()
	for _, in := range []string{"Survey Data", "a/b:c", "Ünicode ✓", "trailing. "} {
		name := sanitizeVolumeName(in)
		if err := os.Mkdir(filepath.Join(dir, name), 0755); err != nil {
			t.Errorf("a sanitized name is not a usable directory name (%q -> %q): %v", in, name, err)
		}
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// Where a Finder volume lands. /Volumes is mode 755 root:wheel, so the
// only way a mount gets there is a directory the user made and gave to
// themselves; every other case falls back, and says why.
func TestChooseMountPoint(t *testing.T) {
	fallback := t.TempDir()

	t.Run("volumes directory has a usable mountpoint", func(t *testing.T) {
		volumes := t.TempDir()
		if err := os.Mkdir(filepath.Join(volumes, "Data"), 0755); err != nil {
			t.Fatal(err)
		}
		got, note := chooseMountPoint("Data", volumes, fallback)
		if want := filepath.Join(volumes, "Data"); got != want {
			t.Errorf("mountpoint = %q, want %q", got, want)
		}
		if !strings.Contains(note, "Data") {
			t.Errorf("note does not name the volume: %q", note)
		}
	})

	t.Run("nothing there falls back and says how to fix it", func(t *testing.T) {
		volumes := t.TempDir()
		got, note := chooseMountPoint("Data", volumes, fallback)
		if want := filepath.Join(fallback, "Data"); got != want {
			t.Errorf("mountpoint = %q, want %q", got, want)
		}
		// The note is the feature: it is the one place a user learns the
		// two commands that move the volume into /Volumes.
		for _, want := range []string{"sudo mkdir", "sudo chown", filepath.Join(volumes, "Data")} {
			if !strings.Contains(note, want) {
				t.Errorf("note is missing %q: %q", want, note)
			}
		}
	})

	t.Run("a non-empty directory is refused", func(t *testing.T) {
		volumes := t.TempDir()
		dir := filepath.Join(volumes, "Data")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "somebody-elses.txt"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		got, note := chooseMountPoint("Data", volumes, fallback)
		if want := filepath.Join(fallback, "Data"); got != want {
			t.Errorf("mountpoint = %q, want the fallback %q", got, want)
		}
		if !strings.Contains(note, "not empty") {
			t.Errorf("note does not say why: %q", note)
		}
	})

	t.Run("a file in the way is refused", func(t *testing.T) {
		volumes := t.TempDir()
		if err := os.WriteFile(filepath.Join(volumes, "Data"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		got, note := chooseMountPoint("Data", volumes, fallback)
		if want := filepath.Join(fallback, "Data"); got != want {
			t.Errorf("mountpoint = %q, want the fallback %q", got, want)
		}
		if !strings.Contains(note, "not a directory") {
			t.Errorf("note does not say why: %q", note)
		}
	})

	// A name with a space, because the volume names this flag exists for
	// have them, and because a note that quotes an unquoted path would
	// hand the user two commands that do not work.
	t.Run("a name with a space is joined and quoted usefully", func(t *testing.T) {
		volumes := t.TempDir()
		got, note := chooseMountPoint("Survey Data", volumes, fallback)
		if want := filepath.Join(fallback, "Survey Data"); got != want {
			t.Errorf("mountpoint = %q, want %q", got, want)
		}
		if !strings.Contains(note, filepath.Join(volumes, "Survey Data")) {
			t.Errorf("note does not carry the candidate path: %q", note)
		}
	})
}

// The ownership test is the one that catches a half-done recipe: `sudo
// mkdir /Volumes/Data` without the chown leaves a root-owned directory,
// and an unprivileged mount(2) on it is refused by the kernel. Checking it
// first turns that into a sentence instead of a mount error.
func TestOwnedByUs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no uid to compare, and no --finder to compare it for")
	}
	dir := t.TempDir()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByUs(fi) {
		t.Error("a directory this test just created is not ours")
	}
	if got := ownerOf(fi); got != os.Getuid() {
		t.Errorf("ownerOf = %d, want %d", got, os.Getuid())
	}
}

// A directory owned by somebody else is refused, and the refusal SAYS so
// rather than reporting "not empty" or falling through to a mount error.
// Root's own directories are the ones a user actually hits (`sudo mkdir`
// with no chown), and every machine has one to point at.
func TestUsableMountPointRefusesADirectoryWeDoNotOwn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no uid to compare")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root, which owns everything this could point at")
	}
	// /var/empty is a root-owned empty directory on macOS, and /boot or
	// /root serve on Linux; whichever exists, the assertion is the same.
	for _, candidate := range []string{"/var/empty", "/private/var/empty", "/boot", "/root"} {
		fi, err := os.Stat(candidate)
		if err != nil || !fi.IsDir() || ownedByUs(fi) {
			continue
		}
		err = usableMountPoint(candidate)
		if err == nil {
			t.Fatalf("%s is owned by uid %d, not %d, and was accepted anyway",
				candidate, ownerOf(fi), os.Getuid())
		}
		if !strings.Contains(err.Error(), "owned by uid") {
			t.Errorf("usableMountPoint(%s) = %v, want a refusal naming the owner", candidate, err)
		}
		return
	}
	t.Skip("no root-owned directory found to point at")
}

// --finder must fail loudly where it cannot work, because the user's
// evidence for whether it worked is a Finder window, and a flag that
// quietly did nothing would send them looking at the wrong thing.
func TestCheckFinder(t *testing.T) {
	err := checkFinder("nfs")
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Errorf("checkFinder(nfs) on macOS = %v, want nil", err)
		}
		if err := checkFinder("fuse"); err == nil || !strings.Contains(err.Error(), "--backend nfs") {
			t.Errorf("checkFinder(fuse) = %v, want a refusal naming --backend nfs", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "macOS-only") {
		t.Errorf("checkFinder on %s = %v, want a refusal naming the platform", runtime.GOOS, err)
	}
}

// An unspecified backend becomes the loopback-NFS one, because that is the
// only backend whose mount options this flag can change. An explicit
// choice is left alone so that --finder --backend fuse stays the error it
// should be.
func TestFinderBackend(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "nfs"},
		{"auto", "nfs"},
		{"nfs", "nfs"},
		{"fuse", "fuse"},
	} {
		o := &cmdOpts{backend: tc.in}
		finderBackend(o)
		if o.backend != tc.want {
			t.Errorf("finderBackend(%q) left %q, want %q", tc.in, o.backend, tc.want)
		}
	}
}

// A mountpoint the user named is used as given, and the volume takes ITS
// name: a window titled something other than the directory it is mounted
// on would be a worse surprise than a name that is not the prefix's.
func TestFinderMountHonorsAnExplicitMountpoint(t *testing.T) {
	v, err := finderMount("pelican://fed/survey", "", "/Users/x/Volumes/Field Notes")
	if err != nil {
		t.Fatalf("finderMount: %v", err)
	}
	if v.MountPoint != "/Users/x/Volumes/Field Notes" {
		t.Errorf("MountPoint = %q", v.MountPoint)
	}
	if v.Name != "Field Notes" {
		t.Errorf("Name = %q, want the mountpoint's last component", v.Name)
	}
	if v.Note != "" {
		t.Errorf("Note = %q, want empty when the caller chose the path", v.Note)
	}
}
