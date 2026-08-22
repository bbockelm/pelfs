package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bbockelm/pelfs/internal/merge"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdMerge reports what bringing another branch into this one would take.
//
// It is a report and only a report. Merging writes a generation, and the
// two things that stop one — a path both sides changed, or an inode both
// sides allocated — have to be seen before anything acts on them.
//
// THE BASE IS FOUND, NOT GUESSED. A branch created by `pelfs branch`
// records the hash of the generation it was cut from, so this looks for
// that exact generation among the tags and branch heads, and verifies what
// it finds. --base names one directly for the case where it is not
// addressable, and is verified the same way.
func cmdMerge(args []string) int {
	var into, base, pubkeyHex, signingKey string
	var apply bool
	o, pos, err := parseArgs("merge", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&apply, "apply", false, "carry the merge out (default: report only). "+
			"Only a fast-forward can be applied yet")
		fs.StringVar(&signingKey, "signing-key", "", signingKeyUsage)
		fs.StringVar(&into, "into", "main", "branch the other one would be merged INTO")
		fs.StringVar(&base, "base", "", "branch or tag holding the generation the two were cut from "+
			"(default: found from the fork record)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
	})
	if err != nil {
		return exitErr(err)
	}
	prefix, source := pos[0], pos[1]
	if source == into {
		return exitErr(fmt.Errorf("--into %s is also the branch being merged", into))
	}
	ctx := context.Background()
	inner, rstore, stateDir, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	ours, err := rstore.Fetch(ctx, into)
	if err != nil {
		return exitErr(fmt.Errorf("branch %s: %w", into, err))
	}
	theirs, err := rstore.Fetch(ctx, source)
	if err != nil {
		return exitErr(fmt.Errorf("branch %s: %w", source, err))
	}

	baseSB, baseRaw, err := resolveBase(ctx, inner, rstore, ours.Superblock, theirs.Superblock, base)
	if err != nil {
		return exitErr(err)
	}
	dek, err := volumeDEK(o, ours.Superblock)
	if err != nil {
		return exitErr(err)
	}
	plan, err := merge.Compute(ctx, merge.Options{
		Inner: inner, Base: baseSB, BaseRaw: baseRaw,
		Ours: ours.Superblock, Theirs: theirs.Superblock,
		DEK: dek, CacheDir: stateDir + "/gencache",
	})
	if err != nil {
		return exitErr(err)
	}
	printMergePlan(mergeReportWriter, plan, into, source, baseSB.Generation)
	if plan.Refusal != "" || !plan.Mergeable() {
		// Not an error in the shell sense on its own — but a script that
		// treats "cannot merge" as "merged" is a script that loses work,
		// so it exits nonzero.
		return 1
	}
	if !apply {
		if !plan.FastForward {
			fmt.Fprintln(mergeReportWriter, "nothing was written; applying a merged tree is not built yet")
		} else {
			fmt.Fprintln(mergeReportWriter, "nothing was written; re-run with --apply to fast-forward")
		}
		return 0
	}
	if !plan.FastForward {
		// The tree would have to be built and published, which is the next
		// piece of work. Refusing is the honest answer: the alternative is
		// taking one side, which is a discard wearing a merge's name.
		return exitErr(fmt.Errorf("this merge needs a tree built, and that is not implemented yet; "+
			"only a fast-forward can be applied. %d paths would come from %s", plan.TookTheirs, source))
	}
	key, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, signingKey), ours.Superblock)
	if err != nil {
		return exitErr(err)
	}
	l, err := maintenanceLease(ctx, o, prefix, into, "merge-"+newSessionID())
	if err != nil {
		return exitErr(err)
	}
	defer releaseLease(ctx, l)

	sb, err := merge.FastForward(ctx, merge.ApplyOptions{
		Plan: plan, Ours: ours.Superblock, Theirs: theirs.Superblock,
		Refs: rstore, Branch: into, SigningKey: key,
	})
	if err != nil {
		return exitErr(err)
	}
	if sb == nil {
		fmt.Fprintf(mergeReportWriter, "nothing to do: %s is already at or past %s\n", into, source)
		return 0
	}
	fmt.Fprintf(mergeReportWriter, "fast-forwarded %s to %s: published generation %d\n",
		into, source, sb.Generation)
	return 0
}

// mergeReportWriter is where the report goes. A variable so a test can
// read what this command's whole product is; everything else about the
// command is an exit code.
var mergeReportWriter io.Writer = os.Stdout

// resolveBase finds the generation two branches were cut from.
//
// The fork record says which generation that is; it does not say where to
// read it, because a generation is only addressable through a ref or a
// tag. So this searches what IS addressable and verifies by hash. A tag
// is checked first: tagging a fork point is the way to keep it findable
// and retained, and a tag is immutable, so a hit there is the answer
// rather than a coincidence.
func resolveBase(ctx context.Context, inner pelicanobj.Store, rstore *refs.Store,
	ours, theirs *superblock.Superblock, explicit string) (*superblock.Superblock, []byte, error) {

	want, ok := forkPoint(ours, theirs)
	if explicit != "" {
		sb, raw, err := fetchRef(ctx, rstore, explicit)
		if err != nil {
			return nil, nil, fmt.Errorf("--base %s: %w", explicit, err)
		}
		// Verified even when named explicitly. A hand-typed base is the
		// most likely one to be wrong, and merge.Compute would refuse it
		// anyway; saying so here names the flag that was wrong.
		if ok && superblock.Hash(raw) != want {
			return nil, nil, fmt.Errorf("--base %s is generation %d, but the branches were cut from a different one; "+
				"merging against the wrong base silently mis-attributes every change",
				explicit, sb.Generation)
		}
		return sb, raw, nil
	}
	if !ok {
		return nil, nil, fmt.Errorf("neither branch records where it was cut from, so the base cannot be found: " +
			"name it with --base. Branches created by this release record it; older ones do not")
	}
	// The tag the fork pinned, when there is one: it is the answer by
	// construction, and it is the only place guaranteed to still hold the
	// base after the source branch has sealed again.
	if tag := forkTag(ours, theirs); tag != "" {
		if sb, raw, err := rstore.FetchTag(ctx, tag); err == nil && superblock.Hash(raw) == want {
			return sb, raw, nil
		}
	}
	// Otherwise search what is addressable: tags first, then branch heads.
	for _, space := range []struct {
		dir   string
		fetch func(context.Context, string) (*superblock.Superblock, []byte, error)
	}{
		{refs.TagDirKey, func(c context.Context, n string) (*superblock.Superblock, []byte, error) {
			return rstore.FetchTag(c, n)
		}},
		{refs.RefDirKey, func(c context.Context, n string) (*superblock.Superblock, []byte, error) {
			f, err := rstore.Fetch(c, n)
			if err != nil {
				return nil, nil, err
			}
			return f.Superblock, f.Raw, nil
		}},
	} {
		names, err := listRefNames(ctx, inner, space.dir)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range names {
			sb, raw, err := space.fetch(ctx, n)
			if err != nil {
				// One unreadable ref is not fatal to a SEARCH: the base may
				// be behind the next name. It matters only if nothing is
				// found, and the message below says what to do then.
				continue
			}
			if superblock.Hash(raw) == want {
				return sb, raw, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("the branches were cut from generation %d, and no tag or branch names it any more: "+
		"tag that generation to make it findable, or pass --base. A merge base has to be readable, "+
		"and retention only keeps what a ref names", baseGeneration(ours, theirs))
}

// forkPoint is the generation both branches say they were cut from, and
// whether they agree.
func forkPoint(ours, theirs *superblock.Superblock) ([32]byte, bool) {
	switch {
	case ours.Fork != nil && theirs.Fork != nil:
		if ours.Fork.Base != theirs.Fork.Base {
			return [32]byte{}, false
		}
		return ours.Fork.Base, true
	case ours.Fork != nil:
		return ours.Fork.Base, true
	case theirs.Fork != nil:
		return theirs.Fork.Base, true
	}
	return [32]byte{}, false
}

// forkTag is the tag either branch says pins its base.
func forkTag(ours, theirs *superblock.Superblock) string {
	if ours.Fork != nil && ours.Fork.Tag != "" {
		return ours.Fork.Tag
	}
	if theirs.Fork != nil && theirs.Fork.Tag != "" {
		return theirs.Fork.Tag
	}
	return ""
}

func baseGeneration(ours, theirs *superblock.Superblock) uint64 {
	if ours.Fork != nil {
		return ours.Fork.BaseGeneration
	}
	if theirs.Fork != nil {
		return theirs.Fork.BaseGeneration
	}
	return 0
}

// fetchRef reads a name that may be a tag or a branch. Tag first, for the
// reason resolveBase checks tags first: a tag is what a fork point is
// pinned with.
func fetchRef(ctx context.Context, rstore *refs.Store, name string) (*superblock.Superblock, []byte, error) {
	if sb, raw, err := rstore.FetchTag(ctx, name); err == nil {
		return sb, raw, nil
	}
	f, err := rstore.Fetch(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	return f.Superblock, f.Raw, nil
}

// printMergePlan writes the report to w. A writer rather than stdout
// because the report IS the product of this command, so a test that could
// not read it would be testing an exit code.
func printMergePlan(w io.Writer, p *merge.Plan, into, source string, baseGen uint64) {
	if p.Refusal != "" {
		ui.Error("cannot merge: {reason}", "reason", p.Refusal)
		return
	}
	if p.FastForward {
		switch p.Direction {
		case "already equal":
			fmt.Fprintf(w, "%s and %s hold the same tree; there is nothing to merge\n", into, source)
		case "theirs":
			fmt.Fprintf(w, "%s has not moved since the fork: merging %s is a fast-forward, "+
				"no new generation needed\n", into, source)
		default:
			fmt.Fprintf(w, "%s has not moved since the fork; %s is already ahead of it\n", source, into)
		}
		return
	}
	fmt.Fprintf(w, "merging %s into %s, from generation %d\n", source, into, baseGen)
	fmt.Fprintf(w, "  unchanged:      %d\n  from %-10s %d\n  from %-10s %d\n",
		p.Unchanged, into+":", p.TookOurs, source+":", p.TookTheirs)
	for _, c := range p.Conflicts {
		fmt.Fprintf(w, "  CONFLICT %-14s %s (%s)\n", c.Kind, c.Path, c.Detail)
	}
	if len(p.Collisions) > 0 {
		// Reported as one problem with a count, not as a list to work
		// through: they are not resolved one at a time. Every one of them
		// is the same fact — the two branches allocated from one counter —
		// and the repair is to renumber a whole side.
		fmt.Fprintf(w, "  %d inode collisions: both branches allocated the same numbers for different files\n",
			len(p.Collisions))
		for i, c := range p.Collisions {
			if i == 3 {
				fmt.Fprintf(w, "      ... and %d more\n", len(p.Collisions)-i)
				break
			}
			fmt.Fprintf(w, "      %d: %s here, %s there\n", c.Inode, c.OursPath, c.TheirsPath)
		}
		fmt.Fprintf(w, "      these branches predate per-branch inode lineages; one side has to be renumbered "+
			"above %d before they can merge\n", p.FirstFreeInode)
	}
	switch {
	case len(p.Conflicts) > 0 && len(p.Collisions) > 0:
		fmt.Fprintf(w, "not mergeable: %d conflicts and %d inode collisions\n", len(p.Conflicts), len(p.Collisions))
	case len(p.Conflicts) > 0:
		fmt.Fprintf(w, "not mergeable: %d conflicts to resolve\n", len(p.Conflicts))
	case len(p.Collisions) > 0:
		fmt.Fprintf(w, "not mergeable: %d inode collisions\n", len(p.Collisions))
	default:
		fmt.Fprintln(w, "mergeable with no conflicts")
	}
}
