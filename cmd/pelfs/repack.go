package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdRepack rewrites the packs that are mostly garbage and publishes a
// generation that stops naming the old ones.
//
// It is `repack-plan` plus the writing half, and it REPORTS BY DEFAULT
// for the reason gc does: this is the one maintenance operation that
// publishes a generation, and a user who typed the wrong prefix should
// get a description rather than a new head. --apply is the opt-in.
//
// Deliberately not folded into `repack-plan`. That command is readable by
// anyone with read access and no key; this one needs the volume's signing
// key and moves the branch. Two names, two blast radii.
func cmdRepack(args []string) int {
	var branch, pubkeyHex, grace string
	var liveness float64
	var workers int
	var apply bool
	o, pos, err := parseArgs("repack", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&apply, "apply", false, "rewrite the packs and publish a generation (default: report only)")
		fs.StringVar(&branch, "branch", "main", "branch to repack and publish onto")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.StringVar(&grace, "grace", "", "widen the age guard past what the superblocks state (e.g. 168h)")
		fs.Float64Var(&liveness, "liveness", repack.DefaultLiveFraction, "rewrite packs below this live fraction")
		fs.IntVar(&workers, "workers", 0, "concurrent fetchers for the sweep (default 8)")
	})
	if err != nil {
		return exitErr(err)
	}
	if liveness <= 0 || liveness > 1 {
		return exitErr(fmt.Errorf("--liveness must be in (0, 1]"))
	}
	ctx := context.Background()
	inner, rstore, stateDir, err := volumeStore(ctx, o, pos[0], pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	live, head, err := liveGenerations(ctx, inner, rstore, branch)
	if err != nil {
		return exitErr(err)
	}
	dek, err := volumeDEK(o, head)
	if err != nil {
		return exitErr(err)
	}

	opts := repack.ExecOptions{
		Options: repack.Options{
			Inner:    inner,
			Live:     live,
			Head:     head,
			DEK:      dek,
			CacheDir: filepath.Join(stateDir, "gencache"),
			Workers:  workers,
			PackLive: liveness,
			RefLive:  liveness,
		},
		Refs:     rstore,
		Branch:   branch,
		SpoolDir: filepath.Join(stateDir, "repack"),
		DryRun:   !apply,
	}
	if grace != "" {
		if opts.Grace, err = time.ParseDuration(grace); err != nil {
			return exitErr(fmt.Errorf("--grace: %w", err))
		}
	}
	if apply {
		// Loaded only when it will be used, so a report needs no key.
		key, err := loadOrCreateSigningKey(filepath.Join(stateDir, "v2-signing.key"), head)
		if err != nil {
			return exitErr(err)
		}
		opts.SigningKey = key
		// Taken around the rewrite, not just the flip: the flip is the
		// only step that can CONFLICT, but everything before it is the
		// work that would be wasted by losing one. On the branch being
		// repacked, which is the only one this run will flip.
		l, err := maintenanceLease(ctx, o, pos[0], branch, "repack-"+newSessionID())
		if err != nil {
			return exitErr(err)
		}
		defer releaseLease(ctx, l)
	}

	res, err := repack.Execute(ctx, opts)
	if err != nil {
		return exitErr(err)
	}
	if res.Plan.Refused() {
		// Same rule as repack-plan: "nothing could be decided" must not
		// read as "nothing to do", or a script repacks never and says why
		// never.
		ui.Error("no repack: {reason}", "reason", res.Plan.Refusal)
		for _, n := range res.Plan.Notes {
			fmt.Printf("  %s\n", n)
		}
		return 1
	}
	printPlan(res.Plan, liveness)
	if res.Plan.Empty() {
		return 0
	}
	if res.DryRun {
		fmt.Println("\nnothing was written; re-run with --apply to rewrite these packs")
		return 0
	}
	fmt.Printf("\nrewrote %d packs into %d, moved %d entries (%v), reclaimed %v\n"+
		"published generation %d on %s\n",
		len(res.CondemnedPacks), len(res.NewPacks), res.MovedEntries,
		ui.ByteCount(res.MovedBytes), ui.ByteCount(res.ReclaimedBytes), res.Generation, branch)
	// The bytes are not free yet, and saying so here is the difference
	// between a user who runs gc and one who wonders why nothing shrank.
	fmt.Printf("the condemned packs are held for the grace window (%s), then `pelfs gc --delete` removes them\n",
		res.Plan.Grace)
	return 0
}
