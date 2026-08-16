package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// cmdMountGen mounts a published v2 generation read-only through the
// catalog-native phase-3 stack — genfs + the raw FUSE binding, no JuiceFS
// anywhere. Linux/macFUSE only (the Docker/NFS fallback stays v1 for
// now). Experimental.
func cmdMountGen(args []string) int {
	var branch, tag, pubkeyHex string
	o, pos, err := parseArgs("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch to mount")
		fs.StringVar(&tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
	})
	if err != nil {
		return exitErr(err)
	}
	prefix, mountpoint := pos[0], pos[1]
	ctx := context.Background()

	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return exitErr(err)
	}

	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix, TokenPath: o.token})
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
			if ke.Kind == superblock.KeyKindDEK {
				if dek, err = superblock.UnwrapKey(kek, ke.Wrapped); err != nil {
					return exitErr(fmt.Errorf("unwrap DEK: %w", err))
				}
			}
		}
	}

	gfs, err := genfs.Open(ctx, genfs.Options{
		Inner:    inner,
		SB:       sb,
		DEK:      dek,
		CacheDir: filepath.Join(stateDir, "gencache"),
	})
	if err != nil {
		return exitErr(err)
	}
	defer gfs.Close() //nolint:errcheck

	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return exitErr(err)
	}
	srv, err := rawfuse.Mount(mountpoint, gfs, o.debug)
	if err != nil {
		return exitErr(fmt.Errorf("mount: %w (mount-gen needs Linux FUSE or macFUSE)", err))
	}
	fmt.Fprintf(os.Stderr, "pelfs: generation %d mounted read-only on %s (catalog-native)\n",
		sb.Generation, mountpoint)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		_ = srv.Unmount()
	}()
	srv.Wait()
	return 0
}
