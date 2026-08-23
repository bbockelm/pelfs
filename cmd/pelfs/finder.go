package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/bbockelm/pelfs/internal/nfsmount"
	"github.com/bbockelm/pelfs/internal/ui"
)

// --finder: a pelfs mount that behaves like a Mac volume.
//
// WHAT MAKES A VOLUME VISIBLE. Not its location. The flag that decides is
// MNT_DONTBROWSE, which mount(8) spells `nobrowse` and describes as "the
// mount point should not be visible via the GUI"; pelfs has always passed
// it (internal/nfsmount), and dropping it is what puts the volume in the
// Finder sidebar under Locations, with an eject button. /Volumes is a
// CONVENTION on top of that, and one an unprivileged process cannot join:
// it is mode 755 root:wheel with no ACL, so nothing pelfs does can create
// a directory there.
//
// WHY NOT NetFS. macOS does have a route that puts a user's mount in
// /Volumes -- the machinery behind the Finder's "Connect to Server" and
// `open nfs://...` -- and it can carry everything this backend needs. The
// NFS URL-mount plugin (/System/Library/Filesystems/NetFSPlugins/nfs.bundle)
// takes the query parameter `options=` and turns it into mount_nfs's -o
// list with ':' rewritten to '=', so a URL of the form
//
//	nfs://127.0.0.1/name?options=vers:3,tcp,port:54321,mountport:54321,nolocks,soft
//
// reaches mount_nfs as the exact option list below. That was confirmed
// against the plugin, and then against the system: /usr/libexec/mount_url,
// the supported command-line front end to the same API, was pointed at a
// dead port and reported "can't mount /PelfsProbe from 127.0.0.1", proving
// the port and the export path had been carried through.
//
// It is not used, for three reasons found in the same investigation.
// (1) It creates no mount point. mount_url sets MountAtMountDir and still
// mounted onto the directory it was given, not a subdirectory of it, so
// the /Volumes problem is exactly where it was: somebody has to make the
// directory. (2) The only caller that gets a mount point CHOSEN for it is
// one that passes no path at all -- Finder, or AppleScript's `mount
// volume` -- which means giving up naming the volume, giving up knowing
// where it landed until the mount table is read back, and depending on a
// GUI login session from a background daemon. (3) It needs cgo or
// AppleScript to reach, and pelfs builds CGO_ENABLED=0 by design.
//
// So the mount stays ours, and /Volumes is available by consent instead:
// a mount point the user creates there once, with sudo, is used when it is
// there. docs/finder.md has both recipes.

// finderVolume is where a --finder mount goes and what it is called.
type finderVolume struct {
	// Name is what the volume should be called. It is used twice, because
	// which of the two macOS shows for an NFS volume is not a thing a mount
	// option can settle (nfsmount.MountOptions.VolumeName): as the last
	// component of the mount point, and as the exported path.
	Name string
	// MountPoint is the directory the filesystem attaches to.
	MountPoint string
	// Note explains how MountPoint was chosen, for the line the session
	// prints. Empty when the caller named the mount point itself.
	Note string
}

// homeVolumes is where a --finder mount goes when /Volumes is not
// available: a directory named for the convention it stands in for, in the
// user's own home, where an unprivileged process can create what it needs.
// The volume's NAME does not depend on this choice -- that comes from the
// last path component either way -- so the only thing lost by landing here
// is the path shown in Get Info.
func homeVolumes() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory to put a volume in: %w", err)
	}
	return filepath.Join(home, "Volumes"), nil
}

// systemVolumes is the directory macOS mounts volumes in. Named rather
// than inlined because the tests substitute for it.
const systemVolumes = "/Volumes"

// checkFinder refuses a --finder mount that cannot work, before anything
// has been started. Each refusal names the thing to do instead: a flag
// that silently did nothing on the platform or backend where it does not
// apply would be worse than an error, because the user's evidence for
// "did it work" is a Finder window.
func checkFinder(backend string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("--finder is macOS-only: it turns off the `nobrowse` mount option, "+
			"which is what keeps a volume out of the macOS GUI, and %s has no GUI to appear in",
			runtime.GOOS)
	}
	if backend != "nfs" {
		return fmt.Errorf("--finder needs --backend nfs (this mount resolved to %q): "+
			"the Finder-visible volume is a property of the loopback-NFS mount's options, "+
			"and a macFUSE mount is macFUSE's own business", backend)
	}
	return nil
}

// finderBackend picks the loopback-NFS backend for a --finder mount that
// did not ask for one.
//
// Without this, --finder on a Mac WITH macFUSE installed would resolve to
// the FUSE backend (resolveBackend prefers it) and then be refused by
// checkFinder — telling a user who asked for a Finder volume to add a
// second flag naming a backend they have no reason to know about. An
// explicit --backend is left alone, so `--finder --backend fuse` is still
// the error it should be rather than a flag quietly overruled.
func finderBackend(o *cmdOpts) {
	if o.backend == "" || o.backend == "auto" {
		o.backend = "nfs"
	}
}

// finderMount decides the name and the mount point for a --finder session.
// mountPoint is what the user asked for, or "" to let this choose.
func finderMount(prefix, name, mountPoint string) (finderVolume, error) {
	n, err := volumeName(prefix, name)
	if err != nil {
		return finderVolume{}, err
	}
	if mountPoint != "" {
		// The user named the path, so the name follows it: a volume whose
		// window title disagreed with the directory it is mounted on would
		// be a worse surprise than a name that is not the one derived from
		// the prefix.
		v := finderVolume{Name: filepath.Base(mountPoint), MountPoint: mountPoint}
		return v, occupied(v.MountPoint)
	}
	home, err := homeVolumes()
	if err != nil {
		return finderVolume{}, err
	}
	path, note := chooseMountPoint(n, systemVolumes, home)
	return finderVolume{Name: n, MountPoint: path, Note: note}, occupied(path)
}

// occupied refuses to mount on top of an existing mount.
//
// The case it is for is two volumes whose prefixes end in the same word --
// .../survey/data and .../trial/data both derive the name "data" -- which
// would otherwise both land on ~/Volumes/data, the second stacking on the
// first and hiding it. Stacked mounts are legal and nearly impossible to
// reason about from the Finder, where both would show the same name.
func occupied(path string) error {
	mounted, err := nfsmount.Mounted(path)
	if err != nil || !mounted {
		return nil
	}
	return fmt.Errorf("%s already has something mounted on it "+
		"(another pelfs volume whose name comes out the same?): "+
		"pass --volume-name to give this one a different name, or a mountpoint of your own",
		path)
}

// chooseMountPoint prefers <volumes>/<name> when the user has already made
// that directory ours, and falls back to <fallback>/<name> otherwise. The
// note it returns is the whole reason this is a function and not a
// constant: a user who wanted /Volumes and got their home directory is
// entitled to be told which test failed and what to type.
func chooseMountPoint(name, volumes, fallback string) (string, string) {
	candidate := filepath.Join(volumes, name)
	if err := usableMountPoint(candidate); err == nil {
		return candidate, "using " + candidate + ", which is already yours"
	} else if !os.IsNotExist(err) {
		// A candidate that exists and is unsuitable is worth a sentence:
		// it is almost always a leftover from an earlier mount, or a
		// directory somebody made without chown-ing it.
		return filepath.Join(fallback, name), fmt.Sprintf(
			"%s cannot be used (%v), so mounting on %s instead",
			candidate, err, filepath.Join(fallback, name))
	}
	return filepath.Join(fallback, name), fmt.Sprintf(
		"mounting on %s; to have the volume live in %s instead, create it once with "+
			"`sudo mkdir -p %s && sudo chown %d %s` and mount again",
		filepath.Join(fallback, name), volumes, candidate, os.Getuid(), candidate)
}

// usableMountPoint reports whether path is a directory this process may
// mount on: it exists, it is a directory, we own it (the kernel refuses an
// unprivileged mount on a directory owned by anybody else -- which is what
// a bare `sudo mkdir` leaves behind), it is empty, and nothing is mounted
// on it already.
//
// A NotExist error is distinguished by the caller, so it is returned
// unwrapped.
func usableMountPoint(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	if !ownedByUs(fi) {
		return fmt.Errorf("owned by uid %d, not %d, so an unprivileged mount(2) on it "+
			"would be refused", ownerOf(fi), os.Getuid())
	}
	if mounted, err := nfsmount.Mounted(path); err == nil && mounted {
		return fmt.Errorf("something is already mounted there")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("not empty (%d entries), and mounting would hide them", len(entries))
	}
	return nil
}

// volumeName is the name the volume will answer to: the override if there
// is one, else the last meaningful component of the prefix.
func volumeName(prefix, override string) (string, error) {
	if override != "" {
		clean := sanitizeVolumeName(override)
		if clean == "" {
			return "", fmt.Errorf("--volume-name %q has nothing usable in it: a volume name "+
				"cannot contain '/' or ':' and cannot be only dots", override)
		}
		return clean, nil
	}
	// Everything after the last slash of the prefix, ignoring trailing
	// slashes: for pelican://fed/group/dataset that is "dataset", which is
	// what a user calls this volume when they talk about it.
	trimmed := strings.TrimRight(prefix, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	if clean := sanitizeVolumeName(trimmed); clean != "" {
		return clean, nil
	}
	// A prefix with no usable last component -- a bare federation URL, or
	// one made entirely of characters a name cannot hold. "pelfs" is a
	// worse name than the volume's own, and a better one than none.
	return "pelfs", nil
}

// sanitizeVolumeName makes a string safe to be both a file name and a
// volume name in the Finder.
//
// Two characters have to go. '/' is the path separator, and the name
// becomes a directory name. ':' is legal in a POSIX name and the Finder
// DISPLAYS it as '/', a historical exchange that makes any name containing
// one read as a different name than it is. Control characters go too, for
// the same reason a terminal-facing tool never prints them. Everything
// else stays, including spaces: "Survey Data" is a perfectly good name for
// a volume and a poor reason to force an underscore on somebody.
func sanitizeVolumeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '/' || r == ':':
			b.WriteRune('-')
		case r < 0x20 || r == 0x7f:
			// Dropped rather than replaced: a name with a stray tab in it
			// is a name with a stray tab in it, not a name with a dash.
		default:
			b.WriteRune(r)
		}
	}
	// A leading dot hides the mount point from the shell and from the
	// Finder both, which is the one thing this flag exists to avoid.
	// Trailing dots and spaces are trimmed because the Finder trims them
	// when displaying, so keeping them means the name shown and the name
	// on disk disagree.
	out := strings.TrimLeft(b.String(), ". ")
	out = strings.TrimRight(out, ". ")
	// 255 bytes is the file-name limit on every filesystem a mount point
	// can live on, and a name near it is a name nobody chose deliberately.
	// Cut on a rune boundary, not a byte.
	for len(out) > 255 {
		_, size := utf8.DecodeLastRuneInString(out)
		if size == 0 {
			break
		}
		out = out[:len(out)-size]
	}
	return out
}

// reportFinderVolume says what a user should now be able to see, because
// none of it is visible from the terminal the mount was started in.
func reportFinderVolume(v finderVolume, rw bool) {
	if v.Note != "" {
		ui.Info("{note}", "note", v.Note)
	}
	ui.Info("{name} should now be in the Finder sidebar under Locations "+
		"(and on the Desktop, if Finder Settings has \"Connected servers\" checked). "+
		"Eject there seals and ends the session, exactly as `pelfs umount` does",
		"name", v.Name)
	if rw {
		ui.Info("Finder bookkeeping files (.DS_Store and friends) are refused on this mount " +
			"rather than published; see docs/finder.md")
	}
}
