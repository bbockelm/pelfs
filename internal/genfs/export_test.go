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
	return fs.arena.residency().Slots
}

// ArenaOverlaps counts pairs of LIVE arena slots whose bytes overlap, the
// resident bytes, the mapping's size, and how many identities the index is
// publishing.
//
// It is the arena's central invariant, stated so a test can check it: two
// live slots naming the same bytes means a reader can be handed another
// chunk's content under its own identity, and resident bytes over the
// mapping's size means slots the cursor overwrote without declaring dead.
// Indexed above resident means the same thing seen from the index.
func (fs *FS) ArenaOverlaps() (overlaps, indexed int, resident, size int64) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	a := fs.arena
	if a == nil {
		return 0, 0, 0, 0
	}
	a.mu.Lock()
	var live []*arenaSlot
	for _, r := range a.regions() {
		for i := r.head; i < len(r.q); i++ {
			s := r.q[i]
			if !s.dead.Load() {
				live = append(live, s)
				resident += s.length
			}
		}
	}
	size = a.size
	a.mu.Unlock()
	for i := range live {
		for j := i + 1; j < len(live); j++ {
			x, y := live[i], live[j]
			if x.off < y.off+y.length && y.off < x.off+x.length {
				overlaps++
			}
		}
	}
	for i := range a.idx {
		a.idx[i].mu.RLock()
		indexed += len(a.idx[i].byID)
		a.idx[i].mu.RUnlock()
	}
	return overlaps, indexed, resident, size
}

// ArenaBytesFor is the arena a mount would get for this request, so a
// measurement can name the size it actually ran at rather than the one it
// asked for.
func ArenaBytesFor(want int64) int64 { return chunkArenaBytes(want, DefaultCacheBytes) }

// ArenaResidency is what the mapping is holding right now, and how much of
// it has answered a read since it was filled — the number that says whether
// an admission policy is keeping chunks anybody wants.
type ArenaResidency struct {
	Slots, Served, Reused           int
	Bytes, ServedBytes, ReusedBytes int64
	// Fills, Evicted and Promoted are the tier's lifetime totals: what the
	// gate let in, what the cursor took back, and how often the ghost table
	// let a chunk back into the protected region.
	Fills, Evicted, Promoted int64
}

// ArenaResidency reports the decoded-chunk arena's occupancy and the
// admission gate's lifetime tally.
func (fs *FS) ArenaResidency() ArenaResidency {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	r := fs.arena.residency()
	fills, evicted, _, promoted := fs.arena.stats()
	return ArenaResidency{
		Slots: r.Slots, Served: r.Served, Reused: r.Reused,
		Bytes: r.Bytes, ServedBytes: r.ServedBytes, ReusedBytes: r.ReusedBytes,
		Fills: fills, Evicted: evicted, Promoted: promoted,
	}
}
