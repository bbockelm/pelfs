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
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/nfsmount"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// cmdMountGen mounts a published v2 generation read-only through the
// catalog-native phase-3 stack — genfs + the raw FUSE binding, no JuiceFS
// anywhere. Linux/macFUSE only (the Docker/NFS fallback stays v1 for
// now). Experimental.
func cmdMountGen(args []string) int {
	var branch, tag, pubkeyHex string
	var rw, noSeal bool
	var signingKeyPath, backend string
	var poll time.Duration
	o, pos, err := parseArgs("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch to mount")
		fs.StringVar(&tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&rw, "rw", false, "mount read-write through a local overlay; unmount SEALS the changes into the next generation")
		fs.BoolVar(&noSeal, "no-seal", false, "with --rw, keep the overlay at unmount instead of publishing it (resume by remounting)")
		fs.StringVar(&backend, "backend", "fuse", "how to attach: fuse (Linux/macFUSE) or nfs (loopback NFS server + the OS client; works on macOS with no kext)")
		fs.DurationVar(&poll, "poll", 0, "read-only: re-check the branch head this often and swap generations live (0 = pinned, the reproducible-batch default)")
		fs.StringVar(&signingKeyPath, "signing-key", "", "hex Ed25519 volume signing key file to seal with (default: <state-dir>/v2-signing.key; a volume's key is per-VOLUME, so a second machine must import it)")
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
	var prevRaw []byte
	if tag != "" {
		if sb, prevRaw, err = rstore.FetchTag(ctx, tag); err != nil {
			return exitErr(err)
		}
		if rw {
			// A tag names a frozen generation; sealing onto it would have
			// to advance SOME branch, and guessing which is worse than
			// refusing.
			return exitErr(errors.New("--rw cannot mount a tag: mount the branch you intend to advance"))
		}
	} else {
		f, err := rstore.Fetch(ctx, branch)
		if err != nil {
			return exitErr(err)
		}
		sb, prevRaw = f.Superblock, f.Raw
	}

	var dek, identityKey []byte
	var keyID uint32
	if o.encryptKeyPath != "" {
		kek, err := superblock.LoadRSAPrivateKeyFile(o.encryptKeyPath, []byte(os.Getenv("JFS_RSA_PASSPHRASE")))
		if err != nil {
			return exitErr(fmt.Errorf("load --encrypt-key: %w", err))
		}
		for _, ke := range sb.KeyTable {
			key, err := superblock.UnwrapKey(kek, ke.Wrapped)
			if err != nil {
				return exitErr(fmt.Errorf("unwrap key %d: %w", ke.ID, err))
			}
			switch ke.Kind {
			case superblock.KeyKindDEK:
				dek, keyID = key, ke.ID
			case superblock.KeyKindIdentity:
				// Sealing MUST reuse the volume's identity key: it defines
				// the dedup domain, and a new one would re-upload the world.
				identityKey = key
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

	var srv *fuse.Server
	var nfsSrv *nfsmount.Server
	var ov *overlay.FS
	overlayDir := filepath.Join(stateDir, "overlay")
	if rw {
		// The write path: a crash-safe local overlay shadows the immutable
		// generation, and unmount seals it into the next one. Nothing
		// mutates the base, so an interrupted session loses at most the
		// unsealed overlay — which survives on disk for a remount.
		ov, err = overlay.Open(overlayDir, gfs, overlay.Options{
			NextInode:      gfs.NextInode(),
			BaseRoot:       gfs.RootCatalog(),
			BaseGeneration: gfs.Generation(),
		})
		if err != nil {
			return exitErr(fmt.Errorf("open overlay: %w", err))
		}
		defer ov.Close() //nolint:errcheck
	}
	switch backend {
	case "nfs":
		// A loopback NFS server over the same stack: the only way to
		// mount on macOS without macFUSE. Generation swap cannot push
		// invalidations here — NFS caching is client-driven — so --poll
		// is refused rather than silently doing nothing.
		var bfs billy.Filesystem
		if rw {
			bfs = vfsbilly.New(ov)
		} else {
			bfs = vfsbilly.NewReadOnly(gfs)
		}
		nfsSrv, err = nfsmount.Serve(bfs)
		if err == nil {
			defer nfsSrv.Close() //nolint:errcheck
			err = nfsSrv.Mount(mountpoint, "pelfs")
		}
	case "fuse", "":
		if rw {
			srv, err = rawfuse.MountRW(mountpoint, ov, o.debug)
		} else {
			srv, err = rawfuse.Mount(mountpoint, gfs, o.debug)
		}
	default:
		return exitErr(fmt.Errorf("unknown --backend %q (want fuse or nfs)", backend))
	}
	if err != nil {
		return exitErr(fmt.Errorf("mount: %w (fuse needs Linux FUSE or macFUSE; try --backend nfs)", err))
	}
	mode := "read-only"
	if rw {
		mode = "read-write (overlay; unmount seals)"
	}
	fmt.Fprintf(os.Stderr, "pelfs: generation %d mounted %s on %s (catalog-native)\n",
		sb.Generation, mode, mountpoint)

	// Live refresh: read-only mounts can follow the branch. Writable
	// mounts never do — the overlay is pinned to the generation it
	// shadows, and swapping underneath it would strand its dirty state.
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	defer stopRefresh()
	if poll > 0 && nfsSrv != nil {
		fmt.Fprintln(os.Stderr, "pelfs: --poll ignored with --backend nfs (NFS caching is client-driven; there is no invalidation channel to push to)")
	} else if poll > 0 && !rw && tag == "" {
		r := rawfuse.NewRefresher(gfs, srv, func(c context.Context) (*superblock.Superblock, error) {
			f, err := rstore.Fetch(c, branch)
			if err != nil {
				return nil, err
			}
			return f.Superblock, nil
		}, poll)
		go r.Run(refreshCtx)
		fmt.Fprintf(os.Stderr, "pelfs: following %s, re-checking every %s\n", branch, poll)
	} else if poll > 0 {
		fmt.Fprintln(os.Stderr, "pelfs: --poll ignored (writable mounts and tags are pinned by design)")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	if nfsSrv != nil {
		<-sigs
		if err := nfsmount.Unmount(mountpoint); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", err)
		}
	} else {
		go func() {
			<-sigs
			_ = srv.Unmount()
		}()
		srv.Wait()
	}

	if !rw || noSeal {
		if rw {
			fmt.Fprintf(os.Stderr, "pelfs: overlay kept at %s (--no-seal); remount to resume or seal\n", overlayDir)
		}
		return 0
	}

	st, err := ov.Stats()
	if err == nil && st.DirtyNodes == 0 && st.DirtyEdges == 0 {
		fmt.Fprintln(os.Stderr, "pelfs: nothing changed; no new generation")
		return 0
	}
	fmt.Fprintln(os.Stderr, "pelfs: sealing the overlay into the next generation...")
	keyPath := signingKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(stateDir, "v2-signing.key")
	}
	signingKey, err := loadOrCreateSigningKey(keyPath, sb)
	if err != nil {
		return exitErr(err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay:        ov,
		Inner:          inner,
		SpoolDir:       stateDir,
		Branch:         branch,
		SigningKey:     signingKey,
		Prev:           sb,
		PrevRaw:        prevRaw,
		DEK:            dek,
		IdentityKey:    identityKey,
		KeyID:          keyID,
		KeyTable:       sb.KeyTable,
		DedupIndexPath: filepath.Join(stateDir, "v2-dedup.db"),
	})
	if err != nil {
		return exitErr(fmt.Errorf("seal: %w (the overlay is intact at %s; remount to retry)", err, overlayDir))
	}
	fmt.Fprintf(os.Stderr, "pelfs: sealed generation %d (%d chunks, %d catalogs, %d packs)\n",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks))

	// The overlay's contents are now published, and it is pinned to the
	// generation it shadowed — which is no longer the head. Leaving it
	// would make this state directory single-use: the next mount would
	// refuse with a generation mismatch. Retire it now that its work is
	// durable.
	_ = ov.Close()
	if err := os.RemoveAll(overlayDir); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: sealed, but the spent overlay at %s could not be removed: %v\n",
			overlayDir, err)
	}
	return 0
}
