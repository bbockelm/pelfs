package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// cmdFsckGen checks one published v2 generation: pack list, catalog and
// shard reachability, structural invariants, and chunk presence (chunk
// CONTENT only with --deep). It is named fsck-gen rather than fsck because
// the v1 `pelfs fsck` — which verifies JuiceFS block objects against the
// metadata engine — still exists; the two check different eras of the
// format and will merge when the v1 engine is deleted.
func cmdFsckGen(args []string) int {
	var branch, tag, pubkeyHex string
	var deep bool
	var workers int
	o, pos, err := parseArgs("fsck-gen", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch to check")
		fs.StringVar(&tag, "tag", "", "check a tag instead of a branch head")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&deep, "deep", false, "fetch and decode every chunk instead of only checking that it is present")
		fs.IntVar(&workers, "workers", 0, "concurrent fetchers for --deep (default 8)")
	})
	if err != nil {
		return exitErr(err)
	}
	prefix := pos[0]
	ctx := context.Background()

	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return exitErr(err)
	}
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix, TokenPath: o.token, Insecure: o.insecure,
	})
	if err != nil {
		return exitErr(err)
	}
	var trusted ed25519.PublicKey
	if pubkeyHex != "" {
		k, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return exitErr(errors.New("--volume-pubkey must be 64 hex characters"))
		}
		trusted = k
	}
	rstore, err := refs.New(inner, stateDir, trusted)
	if err != nil {
		return exitErr(err)
	}
	// The superblock is the integrity root: fsck checks what it signs, so
	// it must be verified before anything below it means anything.
	var sb *superblock.Superblock
	if tag != "" {
		if sb, _, err = rstore.FetchTag(ctx, tag); err != nil {
			return exitErr(err)
		}
	} else {
		f, err := rstore.Fetch(ctx, branch)
		if err != nil {
			return exitErr(err)
		}
		sb = f.Superblock
	}

	var dek []byte
	if o.encryptKeyPath != "" {
		kek, err := superblock.LoadRSAPrivateKeyFile(o.encryptKeyPath, []byte(os.Getenv("JFS_RSA_PASSPHRASE")))
		if err != nil {
			return exitErr(fmt.Errorf("load --encrypt-key: %w", err))
		}
		for _, ke := range sb.KeyTable {
			if ke.Kind != superblock.KeyKindDEK {
				continue
			}
			if dek, err = superblock.UnwrapKey(kek, ke.Wrapped); err != nil {
				return exitErr(fmt.Errorf("unwrap key %d: %w", ke.ID, err))
			}
		}
	}

	rep, cerr := fsck.Check(ctx, fsck.Options{
		Inner:    inner,
		SB:       sb,
		DEK:      dek,
		CacheDir: filepath.Join(stateDir, "gencache"),
		Deep:     deep,
		Workers:  workers,
	})
	if rep != nil {
		printFsckReport(sb.Generation, deep, rep)
	}
	if cerr != nil {
		return exitErr(cerr)
	}
	if !rep.OK() {
		fmt.Fprintf(os.Stderr, "pelfs: generation %d is damaged: %d problem(s)\n", sb.Generation, len(rep.Problems))
		return 1
	}
	fmt.Println("generation is consistent")
	return 0
}

func printFsckReport(gen uint64, deep bool, rep *fsck.Report) {
	fmt.Printf("generation %d\n", gen)
	fmt.Printf("  objects: %d packs, %d catalogs, %d inode shards\n", rep.Packs, rep.Catalogs, rep.Shards)
	fmt.Printf("  tree:    %d dirs, %d files (%d inline), %d symlinks, %d logical bytes\n",
		rep.Dirs, rep.Files, rep.InlineFiles, rep.Symlinks, rep.Bytes)
	if deep {
		fmt.Printf("  data:    %d chunks referenced, %d fetched and verified\n", rep.Chunks, rep.ChunksVerified)
	} else {
		fmt.Printf("  data:    %d chunks referenced, presence only (--deep verifies content)\n", rep.Chunks)
	}
	for _, p := range rep.Problems {
		fmt.Printf("  %s: %s: %s\n", p.Kind, p.Path, p.Detail)
	}
}
