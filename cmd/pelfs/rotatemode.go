package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/rotate"
	"github.com/bbockelm/pelfs/internal/ui"
)

// runModeChange carries out `pelfs rotate --to-unsigned` / `--to-signed`:
// the two operations that move a volume between having an integrity root
// and not having one.
//
// IT REPORTS BY DEFAULT, like every other shape of `pelfs rotate`, and for
// a stronger reason than a key rotation has. A key rotation breaks readers
// that can be repaired by re-pinning a key you still hold. A downgrade
// breaks every reader in a way only a human can clear, and it cannot be
// undone by running it backwards: --to-signed mints a NEW identity, so the
// readers stay broken either way.
func runModeChange(ctx context.Context, o *cmdOpts, prefix, stateDir string, rstore *refs.Store,
	targets, left, tags []string, toUnsigned, apply, breakSiblings bool) int {

	reportModeConsequences(targets, left, tags, toUnsigned)
	if (len(left) > 0 || len(tags) > 0) && !breakSiblings {
		return exitErr(fmt.Errorf("refusing without --break-siblings: this run would leave %s unreadable "+
			"for every client of this volume (see above). The pin is one per VOLUME, so either change every "+
			"branch (drop --branch) or accept the breakage explicitly", joinCounts(left, tags)))
	}

	opts := rotate.Options{
		Refs:     rstore,
		Branches: targets,
		KeyPath:  signingKeyFileIn(stateDir, ""),
		Now:      time.Now().UnixNano(),
		DryRun:   !apply,
	}
	if apply {
		// One lease per branch, held across the run, for the reason a key
		// rotation takes them: a concurrent seal landing between the fetch
		// and the flip would publish a generation in the OLD mode on top of
		// the new one, and the volume would end up half changed.
		for _, b := range targets {
			l, lerr := maintenanceLease(ctx, o, prefix, b, "rotate-"+newSessionID())
			if lerr != nil {
				return exitErr(lerr)
			}
			defer releaseLease(ctx, l)
		}
	}

	run, verb := rotate.ToSigned, "signed"
	if toUnsigned {
		run, verb = rotate.ToUnsigned, "unsigned"
	}
	res, err := run(ctx, opts)
	if err != nil {
		if errors.Is(err, rotate.ErrAlreadyInMode) {
			ui.Info("{error}", "error", err)
			return 0
		}
		return exitErr(explainRotateFailure(err, prefix))
	}
	printModeChange(res, verb, apply)
	if !apply {
		fmt.Printf("\nnothing was written; re-run with --apply to make this volume %s\n", verb)
	}
	return 0
}

// reportModeConsequences prints, before any flip, what this costs. One
// block, in the order a user cares about: what changes, who breaks, and
// what they do about it.
func reportModeConsequences(targets, left, tags []string, toUnsigned bool) {
	if toUnsigned {
		fmt.Printf("dropping the signature from %d branch(es): %s\n", len(targets), joinNames(targets))
		fmt.Printf("  one unsigned generation each. The signing key is ARCHIVED read-only, not deleted:\n" +
			"  it is the only way back to a tag frozen before this (--volume-pubkey).\n")
		ui.Warn("EVERY OTHER CLIENT OF THIS VOLUME REFUSES IT after this, and no flag on their side " +
			"overrides that: an honest downgrade and a forged one are the same document, so the refusal is " +
			"the only safe answer. Each has to delete its own <state-dir>/refs/volume.pub and re-read with " +
			"--allow-unsigned. This machine re-pins itself, because it is the one that ran the command")
		ui.Warn("nothing this volume publishes afterwards is authenticated: anyone who can write the prefix " +
			"can replace its contents undetectably. Chunk hashes still catch corruption BELOW the " +
			"superblock, and encryption is untouched — but the root they hang off is no longer signed")
	} else {
		fmt.Printf("signing %d branch(es): %s\n", len(targets), joinNames(targets))
		fmt.Printf("  one signed generation each, under a key minted here if there is not one already.\n")
		ui.Warn("THIS DOES NOT MAKE THE PAST TRUSTWORTHY. The signature attests to what the volume holds " +
			"NOW — pack set, root catalog, every identity below it — and says nothing about how it got " +
			"there. While it was unsigned, anyone who could write the prefix could change it, and this " +
			"signs whatever they left")
		ui.Warn("every other client refuses this volume until it clears its pin: it recorded the volume as " +
			"unsigned, and a key appearing on an unsigned volume is what a takeover looks like")
	}
	if len(left) == 0 && len(tags) == 0 {
		fmt.Println("  nothing is left behind: every branch changes and this volume has no tags.")
		return
	}
	if len(left) > 0 {
		ui.Warn("branches NOT being changed stay in the old mode and will fail for every client of this "+
			"volume, in whichever direction their pin ends up: {branches}",
			"branches", joinNames(left))
	}
	if len(tags) > 0 {
		ui.Warn("all {count} tag(s) stop verifying: {tags}. A tag is immutable and is checked against the "+
			"pinned identity with no chain step, so it cannot be republished. After a downgrade the "+
			"archived key still reads them with --volume-pubkey; after an upgrade nothing does, because "+
			"they were never signed",
			"count", len(tags), "tags", joinNames(tags))
	}
}

func printModeChange(res *rotate.ModeResult, verb string, applied bool) {
	fmt.Printf("\nvolume is now %s", verb)
	if res.NewPub != "" {
		fmt.Printf(" under key %s", short(res.NewPub))
	}
	fmt.Println()
	for _, p := range res.Branches {
		fmt.Printf("  %-20s head %d: generation %d\n", p.Branch, p.Head, p.Execute)
	}
	for _, b := range res.AlreadyThere {
		fmt.Printf("  %-20s already %s; nothing to do\n", b, verb)
	}
	if !applied {
		return
	}
	if res.RetiredPath != "" {
		ui.Info("the retired signing key is archived read-only at {path} — the only way to read a tag "+
			"frozen before this, with --volume-pubkey", "path", res.RetiredPath)
	}
}
