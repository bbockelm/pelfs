package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// cmdPublish translates the volume's local metadata + blocks into a v2
// generation: cut (VACUUM INTO), transform into catalogs/packs, sign, and
// flip refs/<branch>. Experimental while phase 2 stabilizes; reading the
// published generation back is `internal/hydrate`'s job and is not yet
// wired into mounts.
func cmdPublish(args []string) int {
	var branch, pubkeyHex string
	o, pos, err := parseArgs("publish", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "ref name to publish to")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
	})
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	s, err := toolSession(ctx, o, pos[0], true)
	if err != nil {
		return exitErr(err)
	}
	defer s.cleanupTemp()

	res, err := publishCore(ctx, s, branch, pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	st := res.Stats
	fmt.Printf("published generation %d to %s/%s\n", res.Superblock.Generation, refs.RefDirKey, branch)
	fmt.Printf("  tree: %d dirs, %d files (%d inline, %d chunked), %d symlinks; %d hardlinked inodes promoted\n",
		st.Dirs, st.Files, st.InlineFiles, st.ChunkedFiles, st.Symlinks, st.PromotedInodes)
	fmt.Printf("  data: %d chunks uploaded (%.1f MB), %d deduped (%d via index)\n",
		st.ChunksAdded, float64(st.ChunkBytes)/1e6, st.ChunksDeduped, st.DedupIndexChunks)
	fmt.Printf("  meta: %d catalogs, %d shards, %d new packs\n", st.Catalogs, st.Shards, len(res.NewPacks))
	return 0
}

// publishCore runs the full v2 publish for a session: cut, trust-verified
// predecessor fetch, key wiring, publish. Shared by the CLI command and
// the control socket's POST /v1/publish.
func publishCore(ctx context.Context, s *session, branch, pubkeyHex string) (*publish.Result, error) {
	// The cut: an instant snapshot of the local metadata. Publish reads
	// only this copy; the live database is never touched again.
	cutPath := filepath.Join(s.stateDir, "v2-cut.db")
	_ = os.Remove(cutPath)
	if err := vacuumInto(s.metaPath, cutPath); err != nil {
		return nil, fmt.Errorf("cut: %w", err)
	}
	defer os.Remove(cutPath) //nolint:errcheck

	// Trust: refs go through the pinning store over the direct-read
	// transport (the superblock is the one mutable object; it must never
	// be read through federation caches).
	var trusted ed25519.PublicKey
	if pubkeyHex != "" {
		k, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, errors.New("--volume-pubkey must be 64 hex characters")
		}
		trusted = k
	}
	rstore, err := refs.New(s.metaStore, s.stateDir, trusted)
	if err != nil {
		return nil, err
	}
	var prev *superblock.Superblock
	var prevRaw []byte
	if f, err := rstore.Fetch(ctx, branch); err == nil {
		prev, prevRaw = f.Superblock, f.Raw
	} else if !isNotFoundErr(err) {
		return nil, fmt.Errorf("fetch ref %s: %w", branch, err)
	}

	signingKey, err := loadOrCreateSigningKey(filepath.Join(s.stateDir, "v2-signing.key"), prev)
	if err != nil {
		return nil, err
	}

	popts := publish.Options{
		CutPath:        cutPath,
		Blob:           s.data,
		CacheDir:       s.cacheDir,
		Inner:          s.store,
		SpoolDir:       s.stateDir,
		Branch:         branch,
		SigningKey:     signingKey,
		Prev:           prev,
		PrevRaw:        prevRaw,
		DedupIndexPath: filepath.Join(s.stateDir, "v2-dedup.db"),
	}
	if s.encryptPEM != "" {
		if err := wireEncryption(&popts, s.encryptPEM, prev); err != nil {
			return nil, err
		}
	}
	return publish.Publish(ctx, popts)
}

// vacuumInto snapshots src into dst (the CUT primitive).
func vacuumInto(src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	_, err = db.Exec(fmt.Sprintf("VACUUM INTO '%s'", dst))
	return err
}

// loadOrCreateSigningKey reads the volume signing key (64-byte Ed25519
// private key, hex) or generates one for a brand-new volume. Publishing a
// SUCCESSOR generation without the key that signed the predecessor would
// produce a superblock every reader rejects, so that is refused here
// rather than discovered by readers.
func loadOrCreateSigningKey(path string, prev *superblock.Superblock) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("corrupt signing key %s", path)
		}
		priv := ed25519.PrivateKey(k)
		if prev != nil {
			pub := priv.Public().(ed25519.PublicKey)
			if !strings.EqualFold(hex.EncodeToString(pub), hex.EncodeToString(prev.SigningPub[:])) {
				return nil, fmt.Errorf("signing key %s does not match the branch head's key %x (readers would reject the generation; import the volume key or rotate via NextPub)",
					path, prev.SigningPub[:8])
			}
		}
		return priv, nil
	}
	if prev != nil {
		return nil, fmt.Errorf("no signing key at %s but the branch already has generations signed by %x — import the volume signing key",
			path, prev.SigningPub[:8])
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "pelfs: generated volume signing key %s (public key %s)\n",
		path, hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return priv, nil
}

// wireEncryption sets the DEK/identity key and key table: generation 0
// mints fresh keys and wraps them under the user KEK; later generations
// unwrap the keys the previous generation recorded (the SAME identity key
// must be used forever — it is the volume's dedup identity domain).
func wireEncryption(popts *publish.Options, kekPEM string, prev *superblock.Superblock) error {
	kek, err := superblock.LoadRSAPrivateKeyPEM([]byte(kekPEM), []byte(os.Getenv("JFS_RSA_PASSPHRASE")))
	if err != nil {
		return fmt.Errorf("load --encrypt-key: %w", err)
	}
	if prev == nil {
		dek := make([]byte, entrycodec.KeySize)
		idKey := make([]byte, entrycodec.KeySize)
		if _, err := rand.Read(dek); err != nil {
			return err
		}
		if _, err := rand.Read(idKey); err != nil {
			return err
		}
		wDEK, err := superblock.WrapKey(&kek.PublicKey, dek)
		if err != nil {
			return err
		}
		wID, err := superblock.WrapKey(&kek.PublicKey, idKey)
		if err != nil {
			return err
		}
		popts.DEK, popts.IdentityKey, popts.KeyID = dek, idKey, 1
		popts.KeyTable = []superblock.KeyEntry{
			{ID: 1, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wDEK},
			{ID: 2, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wID},
		}
		return nil
	}
	for _, ke := range prev.KeyTable {
		key, err := superblock.UnwrapKey(kek, ke.Wrapped)
		if err != nil {
			return fmt.Errorf("unwrap key %d with --encrypt-key: %w", ke.ID, err)
		}
		switch ke.Kind {
		case superblock.KeyKindDEK:
			popts.DEK, popts.KeyID = key, ke.ID
		case superblock.KeyKindIdentity:
			popts.IdentityKey = key
		}
	}
	if popts.DEK == nil {
		return errors.New("previous generation is encrypted but records no DEK in its key table")
	}
	popts.KeyTable = prev.KeyTable
	return nil
}

// isNotFoundErr reports a missing-object read (a branch with no
// generations yet).
func isNotFoundErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "not found") || strings.Contains(msg, "no such")
}
