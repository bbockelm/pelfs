package genfs

// Hooks the external tests (package genfs_test) need and the package does
// not otherwise expose. They live here rather than as options because
// nothing outside a test has any business setting them: a cap that a
// caller could shrink is a cap a caller could shrink to something that
// makes every read a re-derivation.

// HotPackLocationCap is the shipped cap, for a measurement that states
// what it comes to rather than repeating the constant.
func HotPackLocationCap() int { return hotCapEntries }

// SetHotPackLocationCap shrinks the location cache so a test can drive
// eviction without a fixture the size of the real cap, and restores it.
func SetHotPackLocationCap(n int) func() {
	prev := hotCapEntries
	hotCapEntries = n
	return func() { hotCapEntries = prev }
}

// HeldPackLocations is how many locations the mount is holding right now —
// the number the cap bounds, and the one a test asserts against.
func (fs *FS) HeldPackLocations() int {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	x := fs.packIndex
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.byKey)
}

// IndexedPacks is how many packs' trailers are folded into the location
// cache — the unit eviction works in.
func (fs *FS) IndexedPacks() int {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	x := fs.packIndex
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.keysOf)
}

// DropDecodedChunks empties the decoded-chunk arena, so the next read of
// anything has to go back to a pack and decode it again.
//
// It replaces "delete gencache/chunks/" as the way a test asks for a cold
// decode path. The tier is one mmap'd file with an in-memory index now
// (chunkarena.go), so there are no per-chunk files for a test to unlink —
// and unlinking the arena file under the mapping would be a bug, not a
// fixture.
func (fs *FS) DropDecodedChunks() {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	fs.arena.clear()
}

// DecodedChunksResident is how many chunks the arena is holding. It is the
// number the old tests counted files in gencache/chunks/ to get.
func (fs *FS) DecodedChunksResident() int {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	if fs.arena == nil {
		return 0
	}
	fs.arena.mu.Lock()
	defer fs.arena.mu.Unlock()
	return len(fs.arena.q) - fs.arena.head
}
