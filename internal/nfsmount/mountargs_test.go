package nfsmount

import (
	"strings"
	"testing"
)

// The argument list is the one thing about this backend that cannot be
// exercised without mounting something, and it is where a Finder volume is
// won or lost: nobrowse is what keeps a mount out of the macOS GUI, so a
// flag that failed to drop it would leave --finder doing nothing at all,
// silently, on the one platform where anybody would notice.

// opts returns the -o list mountCommand built, split into options.
func opts(t *testing.T, args []string) []string {
	t.Helper()
	for i, a := range args {
		if a == "-o" && i+1 < len(args) {
			return strings.Split(args[i+1], ",")
		}
	}
	t.Fatalf("no -o in %q", args)
	return nil
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestMountCommandDarwinHidesTheVolumeByDefault(t *testing.T) {
	name, args := mountCommand("darwin", 54321, "/Users/x/mnt", MountOptions{})
	if name != "mount_nfs" {
		t.Errorf("command = %q, want mount_nfs", name)
	}
	o := opts(t, args)
	if !has(o, "nobrowse") {
		t.Errorf("the default mount lost nobrowse, so it would appear in the Finder: %q", o)
	}
	for _, want := range []string{"vers=3", "tcp", "nolocks", "soft", "noresvport", "port=54321", "mountport=54321"} {
		if !has(o, want) {
			t.Errorf("missing %q in %q", want, o)
		}
	}
	// The export path and the mountpoint, in that order, are what
	// mount_nfs expects; the export is bare "/" when no name was asked
	// for, which is what every existing mount has used.
	if got := args[len(args)-2:]; got[0] != "127.0.0.1:/" || got[1] != "/Users/x/mnt" {
		t.Errorf("operands = %q, want [127.0.0.1:/ /Users/x/mnt]", got)
	}
}

func TestMountCommandBrowsableCarriesTheVolumeName(t *testing.T) {
	// A name with a space in it, because "Survey Data" is an ordinary name
	// for a volume and the code path that would break on it -- joining the
	// option list, building the export -- is the same one being tested.
	_, args := mountCommand("darwin", 2049, "/Users/x/Volumes/Survey Data",
		MountOptions{VolumeName: "Survey Data", Browsable: true})
	o := opts(t, args)
	if has(o, "nobrowse") {
		t.Errorf("a browsable mount still passed nobrowse: %q", o)
	}
	// Both places a name can come from carry it: the export path (in case
	// the client names the volume after what it mounted) and the last
	// component of the mountpoint (in case it names it after where).
	if got := args[len(args)-2]; got != "127.0.0.1:/Survey Data" {
		t.Errorf("export = %q, want 127.0.0.1:/Survey Data", got)
	}
	if got := args[len(args)-1]; got != "/Users/x/Volumes/Survey Data" {
		t.Errorf("mountpoint = %q", got)
	}
}

// Linux mounts through mount(8) and has no GUI to hide from, so it must
// never be handed a macOS-only option -- nobrowse included, which mount(8)
// on Linux does not know.
func TestMountCommandLinuxTakesNoMacOptions(t *testing.T) {
	name, args := mountCommand("linux", 2049, "/mnt/pelfs", MountOptions{VolumeName: "Data", Browsable: true})
	if name != "mount" {
		t.Errorf("command = %q, want mount", name)
	}
	if args[0] != "-t" || args[1] != "nfs" {
		t.Errorf("args do not start with -t nfs: %q", args)
	}
	o := opts(t, args)
	for _, unwanted := range []string{"nobrowse", "nolocks"} {
		if has(o, unwanted) {
			t.Errorf("linux options contain the macOS spelling %q: %q", unwanted, o)
		}
	}
	if !has(o, "nolock") {
		t.Errorf("linux options lost nolock: %q", o)
	}
	if got := args[len(args)-2]; got != "127.0.0.1:/Data" {
		t.Errorf("export = %q, want 127.0.0.1:/Data", got)
	}
}
