// Package retention implements the v2 sweep (docs/design-packfs.md,
// "Retention and GC"): pure set arithmetic over verified superblocks.
//
// Retained packs are the union, over every branch head and every tag, of
// the generation's pack list plus its condemned-ledger entries still
// inside the grace window. A pack is deleted only when it is (a) absent
// from that union AND (b) older than the grace window by the timestamp in
// its own name. Guard (b) is what makes the sweep safe to run against
// live writers with no coordination: a writer's new packs are always
// young, and a mid-sweep fork's closure is already retained.
//
// The sweep fails closed: if any ref or tag cannot be fetched and
// verified, nothing is deleted — an unreadable superblock means the
// retained set is unknown, and guessing destroys data.
package retention

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// DefaultGrace is the T_grace fallback when no superblock states one.
const DefaultGrace = 72 * time.Hour

// Options configures GC.
type Options struct {
	Inner pelicanobj.Store // raw transport (listings, deletes)
	Refs  *refs.Store      // verified superblock access
	// Grace overrides the grace window; zero derives it from the largest
	// Params.TGraceSeconds across verified superblocks (DefaultGrace floor
	// — the window may only ever widen, never narrow, from options).
	Grace  time.Duration
	Delete bool      // false = report only
	Now    time.Time // injectable clock (zero = time.Now())
}

// Report summarizes one sweep.
type Report struct {
	Branches       int
	Tags           int
	RetainedPacks  int
	ScannedPacks   int
	SkippedYoung   int
	Candidates     int
	CandidateBytes int64
	Deleted        int
	CandidateNames []string // capped sample
}

// GC computes (and with o.Delete, removes) unreferenced packs.
func GC(ctx context.Context, o Options) (*Report, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	rep := &Report{}
	retained, grace, err := retainedSet(ctx, o, rep)
	if err != nil {
		return nil, err
	}
	if o.Grace > grace {
		grace = o.Grace
	}
	rep.RetainedPacks = len(retained)

	packs, err := o.Inner.ListDir(ctx, packstore.PackDirKey)
	if err != nil {
		return rep, fmt.Errorf("list packs: %w", err)
	}
	cutoff := o.Now.Add(-grace)
	var candidates []string
	sizes := make(map[string]int64)
	for _, p := range packs {
		if p.IsDir || !strings.HasPrefix(p.Name, "p-") {
			continue
		}
		rep.ScannedPacks++
		if _, ok := retained[p.Name]; ok {
			continue
		}
		created, ok := packstore.PackNameTime(p.Name)
		if !ok || created.After(cutoff) {
			// Unparseable names are treated as young forever: a pack we
			// cannot age is a pack we do not delete.
			rep.SkippedYoung++
			continue
		}
		candidates = append(candidates, p.Name)
		sizes[p.Name] = p.Size
	}

	// Narrow the race window: a fork or publish that landed while we were
	// scanning could have retained a candidate. Recompute against fresh
	// heads immediately before acting. (Not needed for correctness — the
	// age guard already covers coordination-free safety for young packs,
	// and fork sources are ref-reachable — but it is cheap.)
	if len(candidates) > 0 {
		fresh, _, err := retainedSet(ctx, o, &Report{})
		if err != nil {
			return rep, fmt.Errorf("re-list before delete: %w", err)
		}
		kept := candidates[:0]
		for _, name := range candidates {
			if _, ok := fresh[name]; !ok {
				kept = append(kept, name)
			}
		}
		candidates = kept
	}

	rep.Candidates = len(candidates)
	for _, name := range candidates {
		rep.CandidateBytes += sizes[name]
	}
	for _, name := range candidates {
		if len(rep.CandidateNames) < 20 {
			rep.CandidateNames = append(rep.CandidateNames, name)
		}
		if o.Delete {
			if err := o.Inner.Delete(ctx, packstore.PackDirKey+"/"+name); err != nil {
				return rep, fmt.Errorf("delete pack %s: %w", name, err)
			}
			rep.Deleted++
		}
	}
	return rep, nil
}

// retainedSet unions pack lists and grace-young condemned entries across
// every verified branch head and tag, returning the set and the largest
// stated grace window. Any unverifiable superblock is a hard error.
func retainedSet(ctx context.Context, o Options, rep *Report) (map[string]struct{}, time.Duration, error) {
	retained := make(map[string]struct{})
	grace := DefaultGrace

	absorb := func(sb *superblock.Superblock) {
		for _, pe := range sb.PackList {
			retained[pe.Name] = struct{}{}
		}
		if g := time.Duration(sb.Params.TGraceSeconds) * time.Second; g > grace {
			grace = g
		}
		for _, c := range sb.Condemned {
			if o.Now.Sub(time.Unix(c.CondemnedAtUnix, 0)) < grace {
				retained[c.Name] = struct{}{}
			}
		}
	}

	branches, err := listNames(ctx, o.Inner, refs.RefDirKey)
	if err != nil {
		return nil, 0, fmt.Errorf("list refs: %w", err)
	}
	for _, b := range branches {
		f, err := o.Refs.Fetch(ctx, b)
		if err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): branch %s: %w", b, err)
		}
		absorb(f.Superblock)
		rep.Branches++
	}
	tags, err := listNames(ctx, o.Inner, refs.TagDirKey)
	if err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	for _, tname := range tags {
		sb, _, err := o.Refs.FetchTag(ctx, tname)
		if err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): tag %s: %w", tname, err)
		}
		absorb(sb)
		rep.Tags++
	}
	if rep.Branches+rep.Tags == 0 {
		return nil, 0, fmt.Errorf("gc aborted: no refs or tags found (a v2 volume always has at least one branch; refusing to treat every pack as garbage)")
	}
	return retained, grace, nil
}

func listNames(ctx context.Context, inner pelicanobj.Store, dir string) ([]string, error) {
	entries, err := inner.ListDir(ctx, dir)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not exist") {
			return nil, nil // directory absent = empty
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir || strings.HasSuffix(e.Name, ".tmp") {
			continue
		}
		names = append(names, e.Name)
	}
	return names, nil
}
