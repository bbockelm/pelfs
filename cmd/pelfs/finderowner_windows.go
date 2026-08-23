package main

import "os"

// Windows has no uid to compare and no /Volumes to compare it for: this
// file exists so the tree builds for GOOS=windows, which CI does, and not
// because --finder could ever run there (checkFinder refuses every
// platform but darwin, by name).
//
// -1 rather than a guess, and the same -1 the unix version returns when
// FileInfo.Sys carries something it does not recognise: ownedByUs is then
// false, so usableMountPoint refuses every candidate rather than accepting
// one it could not check.
func ownerOf(os.FileInfo) int { return -1 }

func ownedByUs(os.FileInfo) bool { return false }
