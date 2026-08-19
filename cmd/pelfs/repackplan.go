package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdRepackPlan sweeps every live generation and prints what a repack
// would rewrite: the packs that are mostly garbage, the index and
// manifest refs whose packs are mostly gone, what rewriting them would
// reclaim, and what it would cost to move.
//
// It is a dry run by definition rather than by default — executing a plan
// means publishing a generation, and nothing does that yet — so there is
// no --delete twin of gc's here to forget.
func cmdRepackPlan(args []string) int {
	var branch, pubkeyHex, grace string
	var liveness float64
	var workers int
	o, pos, err := parseArgs("repack-plan", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch whose head supplies the index and manifest refs to judge")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.StringVar(&grace, "grace", "", "widen the age guard past what the superblocks state (e.g. 168h)")
		fs.Float64Var(&liveness, "liveness", repack.DefaultLiveFraction, "propose packs and refs below this live fraction")
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

	opts := repack.Options{
		Inner:    inner,
		Live:     live,
		Head:     head,
		DEK:      dek,
		CacheDir: filepath.Join(stateDir, "gencache"),
		Workers:  workers,
		PackLive: liveness,
		RefLive:  liveness,
	}
	if grace != "" {
		if opts.Grace, err = time.ParseDuration(grace); err != nil {
			return exitErr(fmt.Errorf("--grace: %w", err))
		}
	}
	plan, err := repack.Compute(ctx, opts)
	if err != nil {
		return exitErr(err)
	}
	if plan.Refused() {
		// The sweep could not measure the volume, so the only honest plan
		// is no plan. It is an error rather than an empty success: a script
		// that treats "nothing to do" and "nothing could be decided" alike
		// is a script that never repacks and never says why.
		ui.Error("no plan: {reason}", "reason", plan.Refusal)
		for _, n := range plan.Notes {
			fmt.Printf("  %s\n", n)
		}
		return 1
	}
	printPlan(plan, liveness)
	return 0
}

// liveGenerations is the live set the sweep must be given: every branch
// head and every tag, which is everything a sweep can enumerate (a
// retired generation is addressable only by hash). It fails closed on any
// ref it cannot verify, exactly as the GC sweep does — an unverifiable
// ref means the live set is unknown, and a plan built on an incomplete
// live set proposes condemning packs something still reads.
func liveGenerations(ctx context.Context, inner pelicanobj.Store, rstore *refs.Store, branch string) ([]*superblock.Superblock, *superblock.Superblock, error) {
	var live []*superblock.Superblock
	seen := map[string]bool{}
	add := func(sb *superblock.Superblock) {
		// Two refs at the same generation are the same generation: a tag
		// pinning the branch head is the common case, and sweeping it twice
		// would only inflate the counters.
		key := fmt.Sprintf("%d/%x", sb.Generation, sb.RootCatalog)
		if seen[key] {
			return
		}
		seen[key] = true
		live = append(live, sb)
	}

	var head *superblock.Superblock
	branches, err := listRefNames(ctx, inner, refs.RefDirKey)
	if err != nil {
		return nil, nil, err
	}
	for _, b := range branches {
		f, err := rstore.Fetch(ctx, b)
		if err != nil {
			return nil, nil, fmt.Errorf("aborted (fail closed): branch %s: %w", b, err)
		}
		add(f.Superblock)
		if b == branch {
			head = f.Superblock
		}
	}
	tags, err := listRefNames(ctx, inner, refs.TagDirKey)
	if err != nil {
		return nil, nil, err
	}
	for _, tname := range tags {
		sb, _, err := rstore.FetchTag(ctx, tname)
		if err != nil {
			return nil, nil, fmt.Errorf("aborted (fail closed): tag %s: %w", tname, err)
		}
		add(sb)
	}
	if head == nil {
		return nil, nil, fmt.Errorf("no branch %q in this volume", branch)
	}
	return live, head, nil
}

// listRefNames lists one ref key space, treating an absent directory as
// an empty one (a volume with no tags has no tags directory) and any
// other listing failure as fatal — retention's rule, and for its reason:
// a ref space we could not read is a live set we do not know.
func listRefNames(ctx context.Context, inner pelicanobj.Store, dir string) ([]string, error) {
	entries, err := inner.ListDir(ctx, dir)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not exist") {
			return nil, nil
		}
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir || len(e.Name) > 4 && e.Name[len(e.Name)-4:] == ".tmp" {
			continue
		}
		names = append(names, e.Name)
	}
	return names, nil
}

// volumeDEK unwraps the volume's data key from --encrypt-key, which the
// sweep needs to decode catalogs on an encrypted volume.
func volumeDEK(o *cmdOpts, sb *superblock.Superblock) ([]byte, error) {
	if o.encryptKeyPath == "" {
		return nil, nil
	}
	kek, err := superblock.LoadRSAPrivateKeyFile(o.encryptKeyPath, keyPassphrase())
	if err != nil {
		return nil, fmt.Errorf("load --encrypt-key: %w", err)
	}
	for _, ke := range sb.KeyTable {
		if ke.Kind != superblock.KeyKindDEK {
			continue
		}
		dek, err := superblock.UnwrapKey(kek, ke.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("unwrap key %d: %w", ke.ID, err)
		}
		return dek, nil
	}
	return nil, nil
}

func printPlan(p *repack.Plan, liveness float64) {
	fmt.Printf("generations:      %d\npacks:            %d, %v (%v live)\ngrace window:     %s\n",
		p.Generations, p.ScannedPacks, ui.ByteCount(p.Bytes), ui.Percent(liveFraction(p.LiveBytes, p.Bytes)), p.Grace)
	if p.SkippedYoung > 0 {
		fmt.Printf("held back:        %d inside the grace window: %v\n", p.SkippedYoung, p.SkippedYoungNames)
	}
	for _, n := range p.Notes {
		fmt.Printf("note:             %s\n", n)
	}
	if p.Empty() {
		// The answer a healthy volume must be able to get.
		fmt.Printf("nothing to do: nothing is below %v live\n", ui.Percent(liveness))
		return
	}
	if len(p.Packs) > 0 {
		var move, reclaim int64
		fmt.Printf("\nrepack %s:\n", ui.Count(len(p.Packs), "pack"))
		for _, c := range p.Packs {
			fmt.Printf("  %s  %8v  %4v live  move %8v  reclaim %8v\n",
				c.Name, ui.ByteCount(c.Size), ui.Percent(c.LiveFraction), ui.ByteCount(c.Move), ui.ByteCount(c.Reclaim))
			move += c.Move
			reclaim += c.Reclaim
		}
		fmt.Printf("  move %v into %s to reclaim %v\n", ui.ByteCount(move), ui.Count(p.IntoPacks, "pack"), ui.ByteCount(reclaim))
	}
	if len(p.Refs) > 0 {
		fmt.Printf("\nretire %s (each is a rewrite, so it moves what it holds):\n", ui.Count(len(p.Refs), "ref"))
		for _, c := range p.Refs {
			fmt.Printf("  %-8s %s  %8v  %d/%d packs live (%v)  move %8v  reclaim %8v\n",
				c.Kind, c.Name, ui.ByteCount(c.Size), c.LivePacks, c.Packs, ui.Percent(c.LiveFraction),
				ui.ByteCount(c.Move), ui.ByteCount(c.Reclaim))
		}
	}
	// The one line an operator should read before agreeing to any of it.
	fmt.Printf("\ntotal: move %v to reclaim %v\n", ui.ByteCount(p.Move()), ui.ByteCount(p.Reclaim()))
	fmt.Println("this command only plans; nothing executes it yet")
}

func liveFraction(live, total int64) float64 {
	if total <= 0 {
		return 1
	}
	return float64(live) / float64(total)
}
