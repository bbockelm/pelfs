package main

import "os"

// ownerOf has no answer on Windows, and -1 is how this file says so.
//
// There is no uid: a Windows file's owner is a SID, os.Getuid() returns -1
// for the process to compare it against, and the question the caller is
// really asking — "would an unprivileged mount(2) on this directory be
// refused" — has no Windows spelling at all.
//
// Nothing reaches it. --finder is refused on any platform but darwin
// (checkFinder), which is checked before a mount point is chosen, and the
// NFS backend that a Finder volume is made of refuses to mount here too
// (nfsmount.Mount). The file exists so that the Windows build has the
// symbol the shared code names, and returning -1 keeps ownedByUs on its
// "not ours" branch rather than inventing an ownership claim.
func ownerOf(os.FileInfo) int { return -1 }
