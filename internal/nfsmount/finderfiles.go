package nfsmount

// Finder bookkeeping files, and why a volume the Finder can see must
// refuse them.
//
// The moment a pelfs volume becomes visible in the Finder (MountOptions
// .Browsable), the Finder starts writing to it. Every directory a user
// opens gets a .DS_Store holding that window's icon positions and view
// settings; the metadata daemons drop .Spotlight-V100, .fseventsd and
// .DocumentRevisions-V100 at the volume root. None of it is user data,
// none of it is portable, and all of it changes constantly.
//
// On a --rw pelfs mount those writes are not scratch. They land in the
// overlay, get chunked, packed, encrypted, uploaded and SEALED into the
// next generation, and then they are in the volume's history forever --
// published to every other client of the federation, and re-published by
// every checkpoint that follows, because a .DS_Store is rewritten every
// time a window moves. A single afternoon of browsing would publish more
// generations of Finder state than of the user's own work.
//
// So a browsable mount answers as though those names did not exist:
// ENOENT to every lookup, EACCES to every attempt to create one. The
// Finder is built for this -- a read-only network volume answers exactly
// the same way, which is why browsing an SMB share you cannot write to
// produces no complaint and no .DS_Store -- and the same is true of a
// pelfs mount without --rw, where the whole filesystem refuses writes.
//
// WHAT IS DELIBERATELY NOT HERE. Two families of Finder-adjacent names
// stay allowed, because refusing them breaks operations a user asked for
// rather than housekeeping they did not:
//
//   - `._name`, the AppleDouble sidecar. The Finder writes one when
//     copying a file whose extended attributes or resource fork the
//     destination cannot hold. Refusing it fails the COPY, not the
//     bookkeeping: the user loses the file's metadata and gets a dialog
//     about it. It is also, unlike the names below, sometimes the only
//     copy of information the user has.
//   - `.Trashes`, where a network volume's "Move to Trash" puts things.
//     Refusing it turns an undoable delete into an error.
//
// Both are therefore sealed and published like any other file, and that
// is the honest trade: they exist because the user moved data, so the
// volume records that they moved data.

// finderDroppings are the names a browsable mount pretends not to have.
// Matched on the last path component, which makes the rule the same at
// every depth -- and safe under Chroot, where the path a caller passes is
// relative to a root this filter never sees.
var finderDroppings = map[string]bool{
	// Per-directory Finder window state. The one that matters: it is
	// written in every directory a user so much as looks at.
	".DS_Store": true,
	// Volume-root metadata stores, created by the Spotlight, FSEvents and
	// versions daemons. Spotlight does not index a network volume by
	// default, so on most Macs these never appear at all -- but "most" is
	// not a guarantee worth publishing a generation over, and nothing
	// reads them but the daemon that wrote them.
	".Spotlight-V100":         true,
	".fseventsd":              true,
	".DocumentRevisions-V100": true,
	// Written by the Finder to hold a volume's custom icon and by Disk
	// Utility to hold its autodiskmount settings. Both are properties of
	// THIS Mac's view of the volume, not of the volume.
	".VolumeIcon.icns": true,
	".apdisk":          true,
}

// finderDropping reports whether name is Finder bookkeeping that a
// browsable mount should refuse. It takes a single path component.
func finderDropping(name string) bool {
	return finderDroppings[name]
}
