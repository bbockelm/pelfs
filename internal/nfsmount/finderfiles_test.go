package nfsmount

import (
	"errors"
	"os"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
)

// filtered is a filesystem that hides the Finder's bookkeeping, and plain
// is the same one that does not. Every assertion below is made against
// both, because the point is not only that a browsable mount refuses these
// names -- it is that an ordinary mount still does not, which is what
// every existing user and gate depends on.
func filtered() billy.Filesystem { return diagnose(memfs.New(), finderDropping) }
func plain() billy.Filesystem    { return diagnose(memfs.New(), nil) }

func TestFinderDroppingsAreRefused(t *testing.T) {
	fs := filtered()

	// The one that matters: the Finder writes this in every directory a
	// user opens, and on a --rw mount it would be sealed and published.
	if _, err := fs.Create("/.DS_Store"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Create(.DS_Store) = %v, want a permission error", err)
	}
	if _, err := fs.Create("/deep/tree/.DS_Store"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Create at depth = %v, want a permission error", err)
	}
	// An open that would create is refused; an open that only reads is
	// told the file does not exist, the same as the lookup before it.
	if _, err := fs.OpenFile("/.DS_Store", os.O_CREATE|os.O_WRONLY, 0644); !errors.Is(err, os.ErrPermission) {
		t.Errorf("OpenFile(O_CREATE) = %v, want a permission error", err)
	}
	if _, err := fs.OpenFile("/.DS_Store", os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OpenFile(O_RDONLY) = %v, want not-exist", err)
	}
	if _, err := fs.Open("/.DS_Store"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open = %v, want not-exist", err)
	}
	for _, name := range []string{"/.DS_Store", "/deep/.DS_Store"} {
		if _, err := fs.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Stat(%s) = %v, want not-exist", name, err)
		}
		if _, err := fs.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Lstat(%s) = %v, want not-exist", name, err)
		}
		if err := fs.Remove(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Remove(%s) = %v, want not-exist", name, err)
		}
	}
	// The metadata daemons' directories, and the two ways one could be
	// smuggled in past Create.
	if err := fs.MkdirAll("/.Spotlight-V100", 0755); !errors.Is(err, os.ErrPermission) {
		t.Errorf("MkdirAll(.Spotlight-V100) = %v, want a permission error", err)
	}
	if err := fs.Symlink("/etc/passwd", "/.fseventsd"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Symlink(.fseventsd) = %v, want a permission error", err)
	}
	if _, err := fs.Create("/ok.txt"); err != nil {
		t.Fatalf("Create(ok.txt): %v", err)
	}
	if err := fs.Rename("/ok.txt", "/.DS_Store"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Rename to a hidden name = %v, want a permission error", err)
	}
}

// Two families stay allowed on purpose, and both would be regressions if
// somebody "completed" the list: refusing them breaks an operation the
// user asked for rather than housekeeping they did not.
func TestAppleDoubleAndTrashAreNotFiltered(t *testing.T) {
	fs := filtered()
	for _, name := range []string{"/._report.pdf", "/.Trashes", "/.TemporaryItems", "/.hidden", "/DS_Store"} {
		f, err := fs.Create(name)
		if err != nil {
			t.Errorf("Create(%s) = %v, want success", name, err)
			continue
		}
		f.Close() //nolint:errcheck
		if _, err := fs.Stat(name); err != nil {
			t.Errorf("Stat(%s) = %v, want success", name, err)
		}
	}
}

// An ordinary mount is unchanged. A .DS_Store written through the default
// server is created, found and listed, exactly as before this filter
// existed.
func TestUnfilteredMountKeepsFinderFiles(t *testing.T) {
	fs := plain()
	f, err := fs.Create("/.DS_Store")
	if err != nil {
		t.Fatalf("Create(.DS_Store) on an unfiltered mount = %v, want success", err)
	}
	f.Close() //nolint:errcheck
	if _, err := fs.Stat("/.DS_Store"); err != nil {
		t.Errorf("Stat = %v, want success", err)
	}
	names := listing(t, fs, "/")
	if !names[".DS_Store"] {
		t.Errorf("an unfiltered listing dropped .DS_Store: %v", names)
	}
}

// A hidden name that is already in the volume -- sealed by a Linux client,
// or by a pelfs from before this filter -- stops being listed too. Every
// other method says it does not exist, so the listing has to agree.
func TestReadDirHidesFinderFilesThatExist(t *testing.T) {
	inner := memfs.New()
	for _, name := range []string{"/.DS_Store", "/data.csv", "/._data.csv", "/.fseventsd"} {
		f, err := inner.Create(name)
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		f.Close() //nolint:errcheck
	}
	fs := diagnose(inner, finderDropping)
	names := listing(t, fs, "/")
	if names[".DS_Store"] || names[".fseventsd"] {
		t.Errorf("listing still shows Finder bookkeeping: %v", names)
	}
	if !names["data.csv"] || !names["._data.csv"] {
		t.Errorf("listing dropped a user's file: %v", names)
	}
}

func listing(t *testing.T, fs billy.Filesystem, dir string) map[string]bool {
	t.Helper()
	entries, err := fs.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	out := map[string]bool{}
	for _, fi := range entries {
		out[fi.Name()] = true
	}
	return out
}
