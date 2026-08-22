package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bbockelm/pelfs/internal/rescue"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdRescue rebuilds a volume's refs from its packs, for the day the refs
// are gone or unreadable.
//
// THE SITUATION IT IS FOR. refs/<branch> is the only mutable object in the
// format, which makes it the only one that can be lost by being overwritten
// — by a stray write token, by a client that mis-reported a length, by
// someone's `rm`. Everything else survives: packs carry the catalogs, the
// inode shards, the data, AND a signed superblock backup from every seal.
// So the recovery is a scavenging problem, and this is the scavenger.
//
// IT REPORTS BY DEFAULT, like repack and gc, and here the default matters
// more than for either: the report IS the deliverable most of the time. An
// operator staring at a broken volume wants to know which generations are
// recoverable, which branch each belongs to, and what the newest one is
// missing, and none of that requires writing anything or holding a key.
//
// IT NEVER DELETES. Not a pack, not a manifest, not the ref it replaces —
// a flip is a PUT. The moment this command runs is the moment nobody knows
// yet what is really missing, and deleting on that evidence is how a
// recoverable volume becomes an unrecoverable one.
//
// Related but different: `pelfs fsck` verifies a generation the refs still
// name. This one finds generations the refs no longer name at all.
func cmdRescue(args []string) int {
	var pubkeyHex, branch, pick string
	var apply, force bool
	var budget int
	o, pos, err := parseArgs("rescue", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&apply, "apply", false, "re-point the refs at the generations found (default: report only)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 key the scavenged backups must verify under (default: the pinned key)")
		fs.StringVar(&branch, "branch", "main", "which ref backups that name no branch belong to (v0.1.0 volumes recorded none)")
		fs.StringVar(&pick, "pick", "", "resolve an ambiguous head by candidate id, as printed by the report")
		fs.BoolVar(&force, "force", false, "apply a generation whose root catalog could not be located (a head that cannot serve its own root directory)")
		fs.IntVar(&budget, "trailer-budget", 0, "cap the pack trailers the scan reads (default 100000)")
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

	opts := rescue.Options{
		Inner: inner, Refs: rstore, Branch: branch, TrailerBudget: budget,
	}
	rep, err := rescue.Inventory(ctx, opts)
	if err != nil {
		return exitErr(explainRescueFailure(err))
	}
	printInventory(rep)
	if !apply {
		fmt.Println("\nnothing was written; re-run with --apply to re-point the refs at these generations")
		return 0
	}

	// The key is loaded only for --apply, and only after the report has
	// printed: a rescue that refused to describe the volume because no key
	// was present would be useless in exactly the situation it exists for.
	//
	// nil prev, deliberately. loadOrCreateSigningKey's mismatch check
	// compares the local key against a BRANCH HEAD, and the premise here is
	// that the head is missing or wrong — that is the whole reason to be
	// running this. So the check cannot help and would refuse the rescue on
	// the strength of the very document being rescued.
	key, err := loadOrCreateSigningKey(filepath.Join(stateDir, "v2-signing.key"), nil)
	if err != nil {
		return exitErr(err)
	}
	aopts := rescue.ApplyOptions{Options: opts, SigningKey: key, Now: time.Now().UnixNano()}

	failed := false
	for _, plan := range rep.Branches {
		if pick != "" && len(plan.Ambiguous) > 0 {
			if err := rescue.Pick(plan, pick); err != nil {
				ui.Error("{error}", "error", err)
				failed = true
				continue
			}
			if err := rescue.Resolve(ctx, opts, plan); err != nil {
				ui.Error("{error}", "error", err)
				failed = true
				continue
			}
		}
		res, err := rescue.Apply(ctx, aopts, plan, force)
		if err != nil {
			ui.Error("{error}", "error", err)
			failed = true
			continue
		}
		printApplied(res, rep)
	}
	if failed {
		return 1
	}
	return 0
}

// printInventory is the report: what was scanned, what was found, and per
// branch what is on offer.
func printInventory(rep *rescue.Report) {
	fmt.Printf("scanned %d pack(s), read %d trailer(s)\n", rep.PacksSeen, rep.TrailersRead)
	if rep.Truncated {
		// This is the one line in the report that changes what the rest of
		// it MEANS: with packs unread, "the newest I found" is not "the
		// newest there is", and an operator who applies on that basis
		// restores an old generation and has no way to notice.
		ui.Warn("the trailer budget ran out with packs unread, so the newest recoverable generation may not "+
			"have been seen at all. Raise --trailer-budget past {read} before trusting these numbers",
			"read", rep.TrailersRead)
	}
	if rep.TrailersFailed > 0 {
		ui.Warn("{count} pack trailer(s) or backup entries could not be read: this scan was partly blind, so "+
			"a generation missing from this report is not proven to be gone", "count", rep.TrailersFailed)
	}
	if len(rep.Rejected) > 0 {
		// Not an error, and worth a warning anyway: on a healthy volume this
		// is zero. Anything else is a second volume sharing the pack space
		// or somebody planting documents, and either way the operator is
		// looking at a volume with a story.
		ui.Warn("{count} superblock-shaped pack entr(ies) did NOT verify under the trusted key and were not "+
			"considered. That is the defence working — a rescue that trusted a planted backup would be the "+
			"attack — but it is also worth knowing they are there (first: {pack} at offset {off})",
			"count", len(rep.Rejected), "pack", rep.Rejected[0].Pack, "off", rep.Rejected[0].Offset)
	}
	if rep.Unattributed > 0 {
		ui.Warn("{count} backup(s) name no branch (a v0.1.0 writer sealed them) and were assigned to the "+
			"--branch value by ASSUMPTION, not by evidence", "count", rep.Unattributed)
	}
	for _, p := range rep.Branches {
		fmt.Printf("\n%s\n", p.Branch)
		switch {
		case p.Current.Verified:
			fmt.Printf("  ref now:    generation %d, verifies\n", p.Current.Generation)
		case p.Current.Present:
			fmt.Printf("  ref now:    present but UNUSABLE (%s)\n", p.Current.Problem)
		default:
			fmt.Printf("  ref now:    MISSING\n")
		}
		for _, s := range p.Skipped {
			// Newer candidates that were passed over, each with its reason.
			// The spec calls this "falls back a generation when a closure
			// has holes"; printing it is what stops a fallback from looking
			// like a scan that saw nothing newer.
			fmt.Printf("  skipped:    generation %d (%s): %s\n", s.Generation, s.ID, s.Reason)
		}
		if len(p.Ambiguous) > 0 {
			ui.Warn("generation {gen} has {count} verifiable candidates and a rescue does not choose between "+
				"them: re-run with --pick <id>",
				"gen", p.Ambiguous[0].SB.Generation, "count", len(p.Ambiguous))
			for _, c := range p.Ambiguous {
				fmt.Printf("    %s  in pack %s  (branch %q)\n", c.ID(), c.Pack, c.SB.Branch)
			}
			continue
		}
		if p.Chosen == nil {
			fmt.Printf("  offer:      nothing recoverable\n")
			continue
		}
		fmt.Printf("  offer:      generation %d (%s) from pack %s, %d pack(s)\n",
			p.Chosen.SB.Generation, p.Chosen.ID(), p.Chosen.Pack, len(p.Packs))
		if p.Root.Located {
			fmt.Printf("  root:       located in %s\n", p.Root.Pack)
		} else {
			ui.Warn("root catalog NOT located: {note}. --apply refuses this without --force", "note", p.Root.Note)
		}
	}
}

func printApplied(res *rescue.Applied, rep *rescue.Report) {
	verb := "created"
	if res.Replaced {
		verb = "replaced"
	}
	extra := ""
	if res.ManifestObject != "" {
		extra = fmt.Sprintf(" via manifest segment %s", res.ManifestObject[:16])
	}
	ui.Info("{verb} refs/{branch} at generation {gen}, naming {packs} pack(s) {shape}{extra}",
		"verb", verb, "branch", res.Branch, "gen", res.Generation,
		"packs", res.Packs, "shape", res.Shape, "extra", extra)
	// A rescued head is a NEW document, so the identity that signed it is
	// worth naming: it may not be the identity that signed the generation
	// being restored (a pre-rotation backup verified with --volume-pubkey
	// and re-signed with the live key), and that is re-issuing history under
	// a new name.
	ui.Info("signed by {key} — a rescued head is re-signed, so this is the key readers must trust for it",
		"key", res.SignedBy[:16]+"...")
	// The rollback check is local state, so this advice can only be given
	// and not acted on from here.
	ui.Warn("a client that already accepted a HIGHER generation on this branch will refuse the rescued head " +
		"as a stale read; that check is purely local, so clearing that client's state directory is what " +
		"clears it")
}

func explainRescueFailure(err error) error {
	if errors.Is(err, rescue.ErrNoCandidates) {
		return fmt.Errorf("%w. Two things look like this and need opposite responses: the packs holding the "+
			"backups are gone, or the key is wrong — a backup that does not verify is not counted, and no "+
			"key is pinned until a branch has been fetched successfully at least once. Try "+
			"--volume-pubkey <the volume's key>", err)
	}
	return err
}
