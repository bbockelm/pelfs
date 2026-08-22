package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/rotate"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdRotate replaces the volume's signing key, through the custody chain
// the format has always verified and nothing has ever written.
//
// IT REPORTS BY DEFAULT, for a reason stronger than repack's. A repack
// rewrites objects and a wrong one costs bandwidth; this one moves the key
// every reader of the volume pins, and the readers it breaks — sibling
// branches on the old key, and every tag ever taken — cannot be found from
// here, told, or repaired by re-running anything. So the default is a
// description of the damage and --apply is the opt-in, and the description
// is printed in the same shape whether or not --apply was given: a user who
// types the destructive form still reads the warning before the first flip.
//
// WHAT IT ROTATES, BY DEFAULT: every branch of the volume, to ONE successor
// key. That is not a convenience, it is the only default that leaves the
// volume in a state a reader can use, because the pin is per VOLUME — a run
// that moved main and left dev behind would break dev for every reader that
// fetched main first. Narrowing with --branch is allowed, and it is one of
// the two things --break-siblings exists to make you confirm.
//
// WHAT NOTHING CAN FIX: tags. A tag is a frozen, immutable superblock and
// FetchTag verifies it against the pinned key with no chain step, so every
// tag on the volume stops verifying for a reader whose pin has advanced.
// There is no republishing a tag (it is immutable by design — that is what
// makes it a pin), so the only way back to one is --volume-pubkey with the
// retired key. That is reported before acting and is the second thing
// --break-siblings confirms.
func cmdRotate(args []string) int {
	var branchList branches
	var pubkeyHex string
	var apply, abort, breakSiblings, announceOnly bool
	o, pos, err := parseArgs("rotate", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&apply, "apply", false, "publish the rotation (default: report what it would do and what it would break)")
		fs.BoolVar(&announceOnly, "announce-only", false, "publish only the ANNOUNCING generation and stop, so polling readers can record it before the key changes; re-run with --apply to finish")
		fs.BoolVar(&abort, "abort", false, "retract a rotation that announced a successor but has not used it, and delete the pending key")
		fs.Var(&branchList, "branch", "branch to rotate; repeatable (default: every branch of the volume, which is what the volume-wide pin requires)")
		fs.BoolVar(&breakSiblings, "break-siblings", false, "acknowledge that this run leaves objects no reader can verify: branches it does not rotate, and every existing tag")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
	})
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]
	ctx := context.Background()
	inner, rstore, stateDir, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return exitErr(err)
	}

	all, err := rstore.ListBranches(ctx)
	if err != nil {
		return exitErr(err)
	}
	if len(all) == 0 {
		return exitErr(fmt.Errorf("%s holds no pelfs volume (no refs)", prefix))
	}
	targets := all
	if len(branchList) > 0 {
		if targets, err = resolveBranches(branchList, all); err != nil {
			return exitErr(err)
		}
	}
	tags, err := volumeTags(ctx, inner)
	if err != nil {
		return exitErr(err)
	}
	left := notIn(all, targets)
	forks := pendingForkTags(ctx, rstore, all)

	// BEFORE ANYTHING. The warnings come first even on a dry run, because
	// the dry run's whole job is to be the thing that was read.
	reportConsequences(targets, left, tags, forks, announceOnly)
	if (len(left) > 0 || len(tags) > 0) && !breakSiblings {
		return exitErr(fmt.Errorf("refusing to rotate without --break-siblings: this run would leave %s "+
			"unverifiable for any reader whose pin advances (see above). The pin is one key per VOLUME, so "+
			"either rotate every branch (drop --branch) or accept the breakage explicitly",
			joinCounts(left, tags)))
	}

	opts := rotate.Options{
		Refs:         rstore,
		Branches:     targets,
		KeyPath:      signingKeyFileIn(stateDir, ""),
		Now:          time.Now().UnixNano(),
		DryRun:       !apply,
		AnnounceOnly: announceOnly,
	}
	if apply {
		// One lease per branch, held across the whole run: the announcement
		// and the generation that uses it must be consecutive on each
		// branch, and a concurrent seal landing between them would strand
		// the announcement (nothing carries NextPub forward). Taken before
		// the first flip so a run that cannot get them all does nothing.
		for _, b := range targets {
			l, lerr := maintenanceLease(ctx, o, prefix, b, "rotate-"+newSessionID())
			if lerr != nil {
				return exitErr(lerr)
			}
			defer releaseLease(ctx, l)
		}
	}

	run := rotate.Execute
	verb := "rotation"
	if abort {
		run, verb = rotate.Abort, "abort"
	}
	res, err := run(ctx, opts)
	if err != nil {
		return exitErr(explainRotateFailure(err, prefix))
	}
	printRotation(res, verb, apply)
	if !apply {
		fmt.Printf("\nnothing was written and no key was created; re-run with --apply to %s\n",
			map[bool]string{true: "retract it", false: "rotate"}[abort])
	}
	return 0
}

// branches collects a repeatable --branch flag. It exists because rotating
// a subset is a real request — a volume whose other branches are known
// dead, say — and comma-splitting one string would make a branch name
// containing a comma unnameable.
type branches []string

func (b *branches) String() string { return strings.Join(*b, ",") }

func (b *branches) Set(v string) error {
	if err := refs.ValidateName(v); err != nil {
		return err
	}
	*b = append(*b, v)
	return nil
}

// resolveBranches checks the requested names against what the volume has,
// and de-duplicates. A typo has to be an error rather than a branch that is
// quietly skipped: the whole risk of this command is leaving a branch
// behind, and "I named it and it did not happen" is the way that goes
// unnoticed.
func resolveBranches(want, have []string) ([]string, error) {
	present := make(map[string]bool, len(have))
	for _, h := range have {
		present[h] = true
	}
	seen := make(map[string]bool, len(want))
	var out []string
	for _, w := range want {
		if !present[w] {
			return nil, fmt.Errorf("no branch named %s on this volume (`pelfs branch --list` shows what is there)", w)
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out, nil
}

func notIn(all, targets []string) []string {
	t := make(map[string]bool, len(targets))
	for _, x := range targets {
		t[x] = true
	}
	var out []string
	for _, a := range all {
		if !t[a] {
			out = append(out, a)
		}
	}
	return out
}

// volumeTags lists the volume's tags with the two exclusions every
// enumeration of a ref key space applies (a directory is not a tag, and a
// ".tmp" suffix marks a partial write that every listing skips).
//
// It lists rather than verifies, which is the right way round here: the
// point is to count what this rotation is about to strand, and a tag that
// does not verify TODAY is stranded already — so verifying would only
// hide the ones already broken from a warning about breaking them.
//
// A volume with no tags has no tags directory, which is an empty listing
// and not a failure.
func volumeTags(ctx context.Context, inner pelicanobj.Store) ([]string, error) {
	entries, err := inner.ListDir(ctx, refs.TagDirKey)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list %s: %w", refs.TagDirKey, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir || strings.HasSuffix(e.Name, ".tmp") {
			continue
		}
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names, nil
}

// reportConsequences prints, before any flip, exactly what this rotation
// costs — one block, in the order a user cares: what moves, what stops
// verifying, and what to do about each.
// pendingForkTags names, per branch, the tag its Fork record relies on to
// make its merge base READABLE — because a rotation takes those away.
//
// THE INTERACTION, which is not obvious from either feature alone. A branch
// created by `pelfs branch` records where it was cut from
// (superblock.Fork), and Fork.Tag is a tag pinning that base generation.
// That pin is not a nicety: the base stops being any branch's head the
// moment the source branch seals again, and a generation is only addressable
// through a ref or a tag, so without the tag a merge has nothing to read.
//
// `pelfs merge` finds its base with refs.Store.FetchTag, which verifies
// against the PINNED key and takes no custody-chain step. So after a
// rotation every pre-rotation fork tag stops verifying, the fast path fails,
// the fallback search over tags and refs skips each unreadable name, and the
// merge fails to find a base it can no longer read. There is no repair
// afterwards: `pelfs tag` freezes a branch HEAD, so the fork point cannot be
// re-pinned once it is unreadable, and --volume-pubkey with the retired key
// cannot help either — it would then fail to verify the two rotated heads
// being merged.
//
// So the advice is the only one that works, and it has to come BEFORE the
// rotation: MERGE FIRST, THEN ROTATE.
//
// Best effort by design. A head that will not fetch is not a reason to
// refuse a rotation — an unverifiable head is among the things a rotation
// exists to move past — so an unreadable branch contributes nothing here
// rather than failing the run.
func pendingForkTags(ctx context.Context, rstore *refs.Store, branches []string) []string {
	var out []string
	for _, b := range branches {
		f, err := rstore.Fetch(ctx, b)
		if err != nil {
			continue
		}
		if fk := f.Superblock.Fork; fk != nil && fk.Tag != "" {
			out = append(out, fmt.Sprintf("%s (base pinned by tag %s)", b, fk.Tag))
		}
	}
	return out
}

func reportConsequences(targets, left, tags, forks []string, announceOnly bool) {
	fmt.Printf("rotating the volume signing key on %d branch(es): %s\n", len(targets), joinNames(targets))
	fmt.Printf("  each gets two generations: one ANNOUNCING the successor (signed by the current key),\n" +
		"  then one signed by the successor. A reader that has seen the first follows the second and\n" +
		"  moves its pinned key; a reader that has seen neither pins the new key on first use.\n")
	// THE READER WINDOW, said out loud every time, because it is the one
	// consequence a user cannot deduce from the format description and the
	// one that produces support questions. A pin advances by exactly ONE
	// lineage step, so a client whose recorded generation is older than the
	// announcement cannot get there.
	if announceOnly {
		fmt.Printf("  --announce-only: this run publishes ONLY the announcement and stops. Wait longer than\n" +
			"  your readers' poll interval — long enough that each has fetched and recorded the\n" +
			"  announcing generation — then re-run with --apply to finish. Writers are unaffected in\n" +
			"  the meantime: the head is still signed by the current key.\n")
	} else {
		ui.Warn("a pin advances by exactly ONE lineage step (superblock.VerifyChain), so a client whose " +
			"last recorded generation is older than the announcement cannot follow this rotation and will " +
			"refuse the new head. Such a client needs `--volume-pubkey <new key>` or a cleared state " +
			"directory. On a volume with long-idle readers, run `--announce-only` first, wait past their " +
			"poll interval, then finish with --apply")
	}
	if len(left) == 0 && len(tags) == 0 {
		fmt.Println("  nothing is left behind: every branch is rotated and this volume has no tags.")
		return
	}
	// Said BEFORE the general tag warning, because it is the one consequence
	// that cannot be undone afterwards by any means at all — and unlike a
	// lost tag, which costs a reader an old generation, this one costs a
	// merge that has not happened yet and will silently fail to find a base.
	if len(forks) > 0 {
		ui.Warn("MERGE THESE BRANCHES FIRST, or their merge base becomes unreachable: {forks}. `pelfs merge` "+
			"reads its base through the tag the fork pinned, and a tag takes no custody-chain step — so "+
			"after this rotation that tag no longer verifies, the base is no longer addressable, and there "+
			"is NO repair: `pelfs tag` can only freeze a branch head, so a fork point cannot be re-pinned "+
			"once it is unreadable",
			"forks", joinNames(forks))
	}
	ui.Warn("THE PIN IS PER VOLUME, NOT PER BRANCH. Once any reader's pin advances through a rotated " +
		"branch, every object still signed by the OLD key fails for that reader.")
	if len(left) > 0 {
		ui.Warn("branches NOT being rotated will fail for those readers until they are republished under "+
			"the new key: {branches}. Rotating them in this same run (drop --branch) is the only way to "+
			"keep them working, because a later run would mint a DIFFERENT successor",
			"branches", joinNames(left))
	}
	if len(tags) > 0 {
		ui.Warn("all {count} tag(s) stop verifying, permanently: {tags}. A tag is immutable and is verified "+
			"against the pinned key with no chain step, so it cannot be republished and there is no "+
			"rotation path to it. The only way back is `--volume-pubkey <old key>`, and the old key is "+
			"archived beside the new one for exactly that",
			"count", len(tags), "tags", joinNames(tags))
	}
}

func joinCounts(left, tags []string) string {
	var parts []string
	if len(left) > 0 {
		parts = append(parts, fmt.Sprintf("%d branch(es)", len(left)))
	}
	if len(tags) > 0 {
		parts = append(parts, fmt.Sprintf("%d tag(s)", len(tags)))
	}
	return strings.Join(parts, " and ")
}

// printRotation reports what was done, per branch, with the phases a
// resumed run skipped named rather than elided.
func printRotation(res *rotate.Result, verb string, applied bool) {
	fmt.Printf("\n%s: %s -> %s\n", verb, short(res.OldPub), short(res.NewPub))
	for _, p := range res.Plans {
		var steps []string
		if p.Announce > 0 {
			steps = append(steps, fmt.Sprintf("announce at generation %d", p.Announce))
		}
		if p.Execute > 0 {
			steps = append(steps, fmt.Sprintf("sign generation %d with the successor", p.Execute))
		}
		if len(steps) == 0 {
			steps = append(steps, "nothing left to do")
		}
		note := ""
		if p.Found != rotate.PhaseFresh {
			// A resumed run must say so. "Did less than the verb implies"
			// and "was already finished" look identical in a summary, and
			// only one of them means an earlier run crashed.
			note = fmt.Sprintf(" (resuming: found %s)", p.Found)
		}
		fmt.Printf("  %-20s head %d: %s%s\n", p.Branch, p.Head, strings.Join(steps, ", "), note)
	}
	if !applied {
		return
	}
	if res.Promoted {
		ui.Info("the successor key is now this volume's signing key; the retired key is archived read-only "+
			"at {path} (needed only to read tags frozen before this rotation, with --volume-pubkey)",
			"path", res.RetiredPath)
	}
}

func short(hexKey string) string {
	if len(hexKey) <= 16 {
		return hexKey
	}
	return hexKey[:16] + "..."
}

// explainRotateFailure turns the engine's sentinels into advice. The
// engine cannot write it: what to do about a key mismatch depends on
// whether the user has another state directory, and the only thing that can
// say so is the layer that knows where this one came from.
func explainRotateFailure(err error, prefix string) error {
	switch {
	case errors.Is(err, rotate.ErrKeyMismatch):
		return fmt.Errorf("%w. Rotation replaces the key that signed the head, so it needs that key: copy it "+
			"to this volume's state directory (`pelfs rotate --state-dir <dir> %s`), or point --signing-key "+
			"at it", err, prefix)
	case errors.Is(err, rotate.ErrForeignAnnouncement):
		return fmt.Errorf("%w. This is what an interrupted rotation looks like from a DIFFERENT machine than "+
			"the one that started it: finish it there, or copy that machine's <state-dir>/v2-signing.key.next "+
			"here first", err)
	}
	return err
}
