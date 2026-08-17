package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// keyPassphrase is the optional passphrase protecting the PEM key file
// given to --encrypt-key. An empty result means "unencrypted PEM", which
// is what the key loaders expect.
func keyPassphrase() []byte { return []byte(os.Getenv("PELFS_KEY_PASSPHRASE")) }

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
	kek, err := superblock.LoadRSAPrivateKeyPEM([]byte(kekPEM), keyPassphrase())
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

// cmdInit creates a brand-new volume: generation 0 with an empty root.
func cmdInit(args []string) int {
	var branch string
	o, pos, err := parseArgs("init", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "ref name to create")
	})
	if err != nil {
		return exitErr(err)
	}
	if err := initVolumeAt(o, pos[0], branch); err != nil {
		return exitErr(err)
	}
	fmt.Printf("  mount it:    pelfs shell %s\n", pos[0])
	return 0
}

// initVolumeAt creates a brand-new volume: generation 0 with an empty
// root, its volume id and signing key minted locally. It is what
// `pelfs init` runs, and what `pelfs shell` runs when it is pointed at an
// empty prefix.
func initVolumeAt(o *cmdOpts, prefix, branch string) error {
	ctx := context.Background()
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = volDir(prefix)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: prefix, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return err
	}
	rstore, err := refs.New(inner, stateDir, nil)
	if err != nil {
		return err
	}
	if f, err := rstore.Fetch(ctx, branch); err == nil {
		return fmt.Errorf("%s/%s already exists at generation %d; refusing to reinitialize",
			refs.RefDirKey, branch, f.Superblock.Generation)
	} else if !isNotFoundErr(err) {
		return fmt.Errorf("check for an existing volume: %w", err)
	}
	signingKey, err := loadOrCreateSigningKey(filepath.Join(stateDir, "v2-signing.key"), nil)
	if err != nil {
		return err
	}
	var volID [16]byte
	if _, err := rand.Read(volID[:]); err != nil {
		return err
	}
	popts := publish.Options{
		Inner:      inner,
		SpoolDir:   stateDir,
		Branch:     branch,
		SigningKey: signingKey,
		VolumeID:   volID,
	}
	if o.encryptKeyPath != "" {
		pem, err := os.ReadFile(o.encryptKeyPath)
		if err != nil {
			return fmt.Errorf("read --encrypt-key: %w", err)
		}
		if err := wireEncryption(&popts, string(pem), nil); err != nil {
			return err
		}
	}
	if _, err := publish.InitVolume(ctx, popts); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "pelfs: created volume %x on %s/%s (generation 0)\n", volID, refs.RefDirKey, branch)
	return nil
}
