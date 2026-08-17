package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
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

// cmdGC sweeps pack objects no retained generation references. The sweep
// is set arithmetic over verified superblocks and fails closed: a ref that
// cannot be verified means the retained set is unknown, and nothing is
// deleted.
func cmdGC(args []string) int {
	var pubkeyHex string
	var grace string
	o, pos, err := parseArgs("gc", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&o.gcDelete, "delete", false, "delete unreferenced packs (default: report only)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.StringVar(&grace, "grace", "", "widen the age guard past what the superblocks state (e.g. 168h)")
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
	rep, err := retention.GC(ctx, opts)
	if err != nil {
		return exitErr(err)
	}
	fmt.Printf("refs scanned:     %d branches, %d tags\npacks retained:   %d\npacks scanned:    %d\n  too young:      %d\n  unreferenced:   %d (%d bytes)\n",
		rep.Branches, rep.Tags, rep.RetainedPacks, rep.ScannedPacks, rep.SkippedYoung, rep.Candidates, rep.CandidateBytes)
	for _, n := range rep.CandidateNames {
		fmt.Printf("  %s\n", n)
	}
	if o.gcDelete {
		fmt.Printf("deleted:          %d\n", rep.Deleted)
	} else if rep.Candidates > 0 {
		fmt.Println("re-run with --delete to remove them")
	}
	return 0
}
