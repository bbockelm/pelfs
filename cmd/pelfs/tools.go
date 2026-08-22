package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/retention"
)

// volumeStore opens the raw transport for an offline tool and the verified
// ref store beside it. The tools all need the same two things, and both
// have to agree on the state directory the trust pin lives in.
func volumeStore(ctx context.Context, o *cmdOpts, prefix, pubkeyHex string) (pelicanobj.Store, *refs.Store, string, error) {
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, nil, "", err
	}
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return nil, nil, "", err
	}
	var trusted ed25519.PublicKey
	if pubkeyHex != "" {
		k, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, nil, "", errors.New("--volume-pubkey must be 64 hex characters")
		}
		trusted = k
	}
	rstore, err := refs.New(inner, stateDir, trusted)
	if err != nil {
		return nil, nil, "", err
	}
	return inner, rstore, stateDir, nil
}

// joinGenerations renders a generation list for a report line.
func joinGenerations(gens []uint64) string {
	parts := make([]string, len(gens))
	for i, g := range gens {
		parts[i] = strconv.FormatUint(g, 10)
	}
	return strings.Join(parts, ", ")
}

// cmdGC sweeps pack objects no retained generation references. The sweep
// is set arithmetic over verified superblocks and fails closed: a ref that
// cannot be verified means the retained set is unknown, and nothing is
// deleted.
func cmdGC(args []string) int {
	var pubkeyHex string
	var grace string
	var retainK uint
	o, pos, err := parseArgs("gc", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&o.gcDelete, "delete", false, "delete unreferenced packs (default: report only)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.StringVar(&grace, "grace", "", "widen the age guard past what the superblocks state (e.g. 168h)")
		fs.UintVar(&retainK, "retain-k", 0, "how many generations of each branch to retain (default: the head's Params.RetainK)")
	})
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	inner, rstore, _, err := volumeStore(ctx, o, pos[0], pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	opts := retention.Options{Inner: inner, Refs: rstore, Delete: o.gcDelete}
	if grace != "" {
		if opts.Grace, err = time.ParseDuration(grace); err != nil {
			return exitErr(fmt.Errorf("--grace: %w", err))
		}
	}
	if retainK > 0 {
		opts.RetainK = uint32(retainK)
	}
	rep, err := retention.GC(ctx, opts)
	if err != nil {
		return exitErr(err)
	}
	// The window is printed beside the counts because "too young" means
	// nothing without it, and because it is a per-volume parameter now
	// (`pelfs init --grace`) rather than a number every volume shares.
	fmt.Printf("refs scanned:     %d branches, %d tags\ngrace window:     %s\npacks retained:   %d\npacks scanned:    %d\n  too young:      %d\n  unreferenced:   %d (%d bytes)\n",
		rep.Branches, rep.Tags, rep.Grace, rep.RetainedPacks, rep.ScannedPacks, rep.SkippedYoung, rep.Candidates, rep.CandidateBytes)
	for _, n := range rep.CandidateNames {
		fmt.Printf("  %s\n", n)
	}
	// The derived key spaces print only when they exist: an index or
	// manifest sweep on a volume that has neither is noise.
	printSpace := func(what string, sp retention.SpaceReport) {
		if sp.Scanned == 0 && sp.Retained == 0 {
			return
		}
		fmt.Printf("%-17s %d retained, %d scanned, %d too young, %d unreferenced (%d bytes)\n",
			what+":", sp.Retained, sp.Scanned, sp.SkippedYoung, sp.Candidates, sp.CandidateBytes)
	}
	printSpace("pack indexes", rep.Indexes)
	printSpace("pack manifests", rep.Manifests)
	// The retain window, per branch. It prints the two numbers that can
	// differ — what the head asked for and what the sweep could establish
	// — because a short window is a silent outcome otherwise: the run
	// succeeds, and the generations it could not describe are the ones
	// whose objects were just collected.
	for _, w := range rep.Windows {
		fmt.Printf("retain window:    branch %s keeps %d of %d generations\n", w.Branch, w.Generations, w.K)
		if len(w.Unresolved) > 0 {
			fmt.Printf("  not retained:   generation(s) %s (no readable superblock backup)\n",
				joinGenerations(w.Unresolved))
		}
	}
	if o.gcDelete {
		fmt.Printf("deleted:          %d packs, %d indexes, %d manifests\n",
			rep.Deleted, rep.Indexes.Deleted, rep.Manifests.Deleted)
	} else if rep.Candidates+rep.Indexes.Candidates+rep.Manifests.Candidates > 0 {
		fmt.Println("re-run with --delete to remove them")
	}
	return 0
}
