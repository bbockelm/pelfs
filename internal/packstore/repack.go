package packstore

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Repack policy defaults: a sealed pack is condemned when less than half of
// its bytes are live, once total garbage passes the floor, and never while
// it is younger than the age floor (the hot tail is still receiving
// tombstones; repacking it early wastes work).
const (
	defaultRepackLiveness   = 0.5
	defaultRepackMinGarbage = 256 << 20
	defaultRepackAgeFloor   = 10 * time.Minute
	// repackMoveBudget bounds live bytes moved per Repack call, which
	// bounds the latency added to the caller (the pre-snapshot hook).
	// Heavily churned packs have few live bytes, so one budget cleans many
	// of them — the adversarial case is the cheap case.
	repackMoveBudget = 64 << 20
)

// Garbage reports total dead bytes across sealed packs (stored entry bytes
// no longer referenced by the live index).
func (s *Store) Garbage() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.garbageLocked()
}

func (s *Store) garbageLocked() int64 {
	live := make(map[string]int64, len(s.packBytes))
	for _, e := range s.index {
		live[e.pack] += e.length
	}
	var garbage int64
	for pack, stored := range s.packBytes {
		if g := stored - live[pack]; g > 0 {
			garbage += g
		}
	}
	return garbage
}

// Repack bounds federation space amplification from overwrite churn: packs
// whose liveness has dropped below the threshold have their live entries
// rewritten into the current spool (sealed by the Flush below) and are then
// deleted whole. No tombstones are needed — the moved entries reappear in a
// newer pack, and name-ordered shadowing already makes the newer copy
// authoritative — and a crash at any point is safe: duplicates resolve
// newest-wins and a leftover old pack is re-condemned (with zero live
// bytes, so re-condemning is nearly free).
//
// With liveness threshold L and garbage floor G, steady-state federation
// usage is bounded by live/L + G plus the unsealed spool, regardless of how
// long a client loops overwrites.
func (s *Store) Repack(ctx context.Context) error {
	if !s.cfg.WriteEnabled {
		return nil // read-only sessions accumulate no obligation to clean
	}
	return s.repack(ctx, s.cfg.repackMinGarbage(), s.cfg.repackAgeFloor())
}

// RepackAll drains garbage regardless of the floor and age policy — the
// offline `pelfs repack` path, run under the volume lease so no other
// writer can be producing tombstones concurrently. Loops until a pass
// stops making progress.
func (s *Store) RepackAll(ctx context.Context) error {
	for {
		before := s.Garbage()
		if before == 0 {
			return nil
		}
		if err := s.repack(ctx, 1, 0); err != nil {
			return err
		}
		if s.Garbage() >= before {
			return nil
		}
	}
}

func (s *Store) repack(ctx context.Context, minGarbage int64, ageFloor time.Duration) error {
	if !s.cfg.WriteEnabled {
		return fmt.Errorf("repack requires a write-enabled pack store")
	}
	// Single repacker at a time; skip rather than queue (the next
	// pre-snapshot hook will try again).
	if !s.repackMu.TryLock() {
		return nil
	}
	defer s.repackMu.Unlock()

	type candidate struct {
		name    string
		live    int64
		stored  int64
		entries []string // keys of live entries in this pack
	}

	s.mu.Lock()
	if s.garbageLocked() < minGarbage {
		s.mu.Unlock()
		return nil
	}
	liveBy := make(map[string]*candidate, len(s.packBytes))
	for name, stored := range s.packBytes {
		liveBy[name] = &candidate{name: name, stored: stored}
	}
	for k, e := range s.index {
		if c, ok := liveBy[e.pack]; ok {
			c.live += e.length
			c.entries = append(c.entries, k)
		}
	}
	cutoff := time.Now().Add(-ageFloor)
	var cands []*candidate
	for _, c := range liveBy {
		if packCreated(c.name).After(cutoff) {
			continue // hot tail: still receiving tombstones
		}
		if float64(c.live) < s.cfg.repackLiveness()*float64(c.stored) {
			cands = append(cands, c)
		}
	}
	s.mu.Unlock()
	if len(cands) == 0 {
		return nil
	}
	// Worst (least live) first: cheapest space per byte moved.
	sort.Slice(cands, func(i, j int) bool { return cands[i].live < cands[j].live })

	var moved int64
	var condemned []string
	for _, c := range cands {
		if moved > 0 && moved+c.live > repackMoveBudget {
			break
		}
		ok := true
		for _, key := range c.entries {
			// Re-check under the lock: the entry may have been deleted or
			// already moved since candidate selection.
			s.mu.Lock()
			e, still := s.index[key]
			s.mu.Unlock()
			if !still || e.pack != c.name {
				continue
			}
			data, err := s.readRange(ctx, s.packKey(c.name), e.off, e.length)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: repack: read %s from %s: %v\n", key, c.name, err)
				ok = false
				break
			}
			if err := s.appendPending(key, data, e.created); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: repack: respool %s: %v\n", key, err)
				ok = false
				break
			}
			moved += e.length
		}
		if !ok {
			break
		}
		condemned = append(condemned, c.name)
	}
	if len(condemned) == 0 {
		return nil
	}
	// Seal the moved entries into a durable pack, then delete the old
	// packs whole. Order matters: delete only after the replacement pack
	// is durable.
	if err := s.Flush(ctx); err != nil {
		return fmt.Errorf("repack seal: %w", err)
	}
	for _, name := range condemned {
		if err := s.inner.Delete(ctx, s.packKey(name)); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: repack: delete %s: %v (will retry next repack)\n", name, err)
			continue
		}
		s.mu.Lock()
		delete(s.packBytes, name)
		s.mu.Unlock()
	}
	return nil
}

// appendPending spools bytes for key without triggering a cut (the caller
// seals explicitly); used by Repack to move live entries between packs.
func (s *Store) appendPending(key string, data []byte, created int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.spool.WriteAt(data, s.spoolSz); err != nil {
		return err
	}
	s.pending[key] = entry{off: s.spoolSz, length: int64(len(data)), created: created}
	s.spoolSz += int64(len(data))
	return nil
}

// packCreated parses the creation time embedded in a pack name
// (p-<unixnano hex>-<rand>); zero time when unparsable.
func packCreated(name string) time.Time {
	parts := strings.SplitN(name, "-", 3)
	if len(parts) < 2 {
		return time.Time{}
	}
	ns, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, int64(ns))
}

func (c Config) repackLiveness() float64 {
	if c.RepackLiveness > 0 {
		return c.RepackLiveness
	}
	return defaultRepackLiveness
}

func (c Config) repackMinGarbage() int64 {
	if c.RepackMinGarbage > 0 {
		return c.RepackMinGarbage
	}
	return defaultRepackMinGarbage
}

func (c Config) repackAgeFloor() time.Duration {
	if c.RepackAgeFloor > 0 {
		return c.RepackAgeFloor
	}
	return defaultRepackAgeFloor
}
