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
	var subshell bool
	var poll time.Duration
	o, pos, err := parseArgs("mount-gen", args, 2, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch to mount")
		fs.StringVar(&tag, "tag", "", "mount a tag instead of a branch head (pinned exactly)")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&rw, "rw", false, "mount read-write through a local overlay; unmount SEALS the changes into the next generation")
		fs.BoolVar(&noSeal, "no-seal", false, "with --rw, keep the overlay at unmount instead of publishing it (resume by remounting)")
		fs.BoolVar(&subshell, "subshell", false, "run a subshell in the mount and unmount (sealing, with --rw) when it exits — the `pelfs shell` workflow on the catalog-native stack")
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

	// A path-based frontend re-descends from the root on every operation,
	// so its residency can be bounded; a FUSE binding's cannot, because
	// the kernel owns those lifetimes and tells us when to drop them.
	maxResident := 0
	if backend == "nfs" {
		maxResident = 100000
	}
	gfs, err := genfs.Open(ctx, genfs.Options{
		Inner:       inner,
		SB:          sb,
		DEK:         dek,
		CacheDir:    filepath.Join(stateDir, "gencache"),
		MaxResident: maxResident,
	})
	if err != nil {
		return exitErr(err)
	}
	defer gfs.Close() //nolint:errcheck

	// --prefetch is a common flag; phase 3 honors the same three modes.
	switch o.prefetch {
	case "", "none":
	case "all":
		fmt.Fprintln(os.Stderr, "pelfs: prefetching the generation into the local cache...")
		rep, err := gfs.Prefetch(ctx, pelicanobj.TransferWorkers())
		if err != nil {
			return exitErr(fmt.Errorf("prefetch: %w", err))
		}
		if rep.Failed > 0 {
			return exitErr(fmt.Errorf("prefetch: %d chunk(s) could not be fetched (%v); refusing to mount",
				rep.Failed, rep.Sample))
		}
		fmt.Fprintf(os.Stderr, "pelfs: prefetched %d chunks (%d already cached) across %d files, %.1f MB\n",
			rep.Chunks, rep.Cached, rep.Files, float64(rep.Bytes)/1e6)
	case "background":
		go func() {
			// Half the transfer pool, so warming never starves the
			// interactive I/O the mount is serving.
			rep, err := gfs.Prefetch(ctx, max(1, pelicanobj.TransferWorkers()/2))
			if err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: background prefetch: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "pelfs: background prefetch done: %d chunks, %d failed\n",
				rep.Chunks, rep.Failed)
		}()
	default:
		return exitErr(fmt.Errorf("unknown --prefetch %q (want none, all, or background)", o.prefetch))
	}

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

	if subshell {
		// The shell owns the session: when it exits we unmount, and the
		// seal (with --rw) happens on the way out just as it does for a
		// signalled mount.
		code := launchSubshell(o, prefix, mountpoint)
		if nfsSrv != nil {
			if err := nfsmount.Unmount(mountpoint); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", err)
			}
		} else {
			if err := srv.Unmount(); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: unmount: %v\n", err)
			}
			srv.Wait()
		}
		if sealErr := sealOverlay(ctx, sealArgs{
			rw: rw, noSeal: noSeal, ov: ov, overlayDir: overlayDir,
			inner: inner, stateDir: stateDir, branch: branch, sb: sb, prevRaw: prevRaw,
			dek: dek, identityKey: identityKey, keyID: keyID, signingKeyPath: signingKeyPath,
		}); sealErr != nil {
			return exitErr(sealErr)
		}
		return code
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

	if err := sealOverlay(ctx, sealArgs{
		rw: rw, noSeal: noSeal, ov: ov, overlayDir: overlayDir,
		inner: inner, stateDir: stateDir, branch: branch, sb: sb, prevRaw: prevRaw,
		dek: dek, identityKey: identityKey, keyID: keyID, signingKeyPath: signingKeyPath,
	}); err != nil {
		return exitErr(err)
	}
	return 0
}

// sealArgs carries what sealing a writable mount needs at exit; both the
// signalled path and the subshell path end there.
type sealArgs struct {
	rw, noSeal     bool
	ov             *overlay.FS
	overlayDir     string
	inner          pelicanobj.Store
	stateDir       string
	branch         string
	sb             *superblock.Superblock
	prevRaw        []byte
	dek            []byte
	identityKey    []byte
	keyID          uint32
	signingKeyPath string
}

// sealOverlay publishes a writable mount's changes as the next
// generation and retires the spent overlay. A read-only mount, an
// unchanged session, or --no-seal all return without publishing.
func sealOverlay(ctx context.Context, a sealArgs) error {
	if !a.rw || a.noSeal {
		if a.rw {
			fmt.Fprintf(os.Stderr, "pelfs: overlay kept at %s (--no-seal); remount to resume or seal\n", a.overlayDir)
		}
		return nil
	}
	st, err := a.ov.Stats()
	if err == nil && st.DirtyNodes == 0 && st.DirtyEdges == 0 {
		fmt.Fprintln(os.Stderr, "pelfs: nothing changed; no new generation")
		return nil
	}
	fmt.Fprintln(os.Stderr, "pelfs: sealing the overlay into the next generation...")
	keyPath := a.signingKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(a.stateDir, "v2-signing.key")
	}
	signingKey, err := loadOrCreateSigningKey(keyPath, a.sb)
	if err != nil {
		return err
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay:        a.ov,
		Inner:          a.inner,
		SpoolDir:       a.stateDir,
		Branch:         a.branch,
		SigningKey:     signingKey,
		Prev:           a.sb,
		PrevRaw:        a.prevRaw,
		DEK:            a.dek,
		IdentityKey:    a.identityKey,
		KeyID:          a.keyID,
		KeyTable:       a.sb.KeyTable,
		DedupIndexPath: filepath.Join(a.stateDir, "v2-dedup.db"),
	})
	if err != nil {
		return fmt.Errorf("seal: %w (the overlay is intact at %s; remount to retry)", err, a.overlayDir)
	}
	fmt.Fprintf(os.Stderr, "pelfs: sealed generation %d (%d chunks, %d catalogs, %d packs)\n",
		res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks))

	// The overlay's contents are now published, and it is pinned to the
	// generation it shadowed — which is no longer the head. Leaving it
	// would make this state directory single-use: the next mount would
	// refuse with a generation mismatch.
	_ = a.ov.Close()
	if err := os.RemoveAll(a.overlayDir); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: sealed, but the spent overlay at %s could not be removed: %v\n",
			a.overlayDir, err)
	}
	return nil
}
