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
	"github.com/bbockelm/pelfs/internal/ui"
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
				// The advice has to be advice a user can take. This used to
				// offer "or rotate via NextPub", which is not a thing anyone
				// can do: the format carries a successor-key announcement and
				// nothing in this tool writes one, so the only way forward is
				// the key that signed the branch.
				return nil, fmt.Errorf("signing key %s does not match the branch head's key %x — readers would "+
					"reject the generation, so import the key that signed this volume (key rotation is not supported yet)",
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
	ui.Info("generated volume signing key {path} (public key {key})",
		"path", path, "key", hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
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

// signingKeyFileIn is where a volume's signing key lives: the explicit
// --signing-key when one is given, and the state directory's copy
// otherwise.
//
// One resolver for every path that signs — init, the seal at unmount, a
// checkpoint, a background repack — because a volume's identity is a
// property of the VOLUME, not of the command that happens to be running.
// Two of these that disagreed would mint a second identity and publish a
// generation every existing reader rejects.
func signingKeyFileIn(stateDir, override string) string {
	if override != "" {
		return override
	}
	return filepath.Join(stateDir, "v2-signing.key")
}

// cmdInit creates a brand-new volume: generation 0 with an empty root.
func cmdInit(args []string) int {
	var branch, signingKey string
	o, pos, err := parseArgs("init", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "ref name to create")
		fs.StringVar(&signingKey, "signing-key", "", signingKeyUsage)
	})
	if err != nil {
		return exitErr(err)
	}
	if err := initVolumeAt(o, pos[0], branch, signingKey); err != nil {
		return exitErr(err)
	}
	fmt.Printf("  mount it:    pelfs shell %s\n", pos[0])
	return 0
}

// initVolumeAt creates a brand-new volume: generation 0 with an empty
// root, its volume id and signing key minted locally. It is what
// `pelfs init` runs, and what `pelfs shell` runs when it is pointed at an
// empty prefix.
func initVolumeAt(o *cmdOpts, prefix, branch, signingKeyPath string) error {
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
	// An explicit key here means "create this volume under an identity I
	// already have", which is how a volume gets a key its owner keeps
	// somewhere other than the state directory. Absent, one is minted at
	// that path — the ordinary case.
	signingKey, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, signingKeyPath), nil)
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
	ui.Info("created volume {volume} on {ref} (generation 0)",
		"volume", fmt.Sprintf("%x", volID), "ref", refs.RefDirKey+"/"+branch)
	return nil
}

// signingKeyUsage is the one description of --signing-key, shared by
// every command that has it.
//
// It says what to DO with it, because the flag exists for one situation
// and it is not one a user reasons their way to: a volume's identity is
// per-VOLUME, so publishing from a second machine means putting the same
// private key there. Reading needs nothing — the public half travels
// inside every superblock and is pinned on first use — so the failure
// only ever shows up at the first seal, long after the mount worked.
const signingKeyUsage = "hex Ed25519 volume signing key to publish with " +
	"(default: <state-dir>/v2-signing.key). A volume's key is per-VOLUME: to write from a second " +
	"machine, copy that file across and point this at it. Reading needs no key"
