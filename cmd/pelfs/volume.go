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
	"time"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/rotate"
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
// An UNSIGNED volume returns (nil, nil): there is no key, publishing takes
// none, and — the part that matters — this function must not MINT one. A
// mint here would sign the next seal of a volume every reader has pinned
// as unsigned, which is a volume that stops verifying for everyone at the
// first checkpoint. See superblock.SignAs.
func loadOrCreateSigningKey(path string, prev *superblock.Superblock) (ed25519.PrivateKey, error) {
	if prev != nil && prev.IsUnsigned() {
		return nil, nil
	}
	// A ROTATION INTERRUPTED AFTER ITS LAST FLIP LANDS HERE, and this is
	// the one place that can finish it. `pelfs rotate` publishes the
	// generation signed by the successor and then promotes the successor to
	// be the live local key; a crash between those two leaves a head whose
	// key is sitting in a file named `.next`, and the check below would
	// refuse every seal until someone re-ran a command they may not know
	// about. Reconcile promotes on evidence — the pending key's public half
	// IS the key the head is signed with — and does nothing otherwise, so a
	// wrong state directory still gets the refusal it deserves.
	if promoted, err := rotate.Reconcile(path, prev); err != nil {
		return nil, err
	} else if promoted {
		ui.Warn("completed an interrupted key rotation: {path} now holds the key generation {gen} is signed "+
			"by, and the previous key is archived beside it", "path", path, "gen", prev.Generation)
	}
	if b, err := os.ReadFile(path); err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("corrupt signing key %s", path)
		}
		priv := ed25519.PrivateKey(k)
		if prev != nil {
			pub := priv.Public().(ed25519.PublicKey)
			if !strings.EqualFold(hex.EncodeToString(pub), hex.EncodeToString(prev.SigningPub[:])) {
				// The advice has to be advice a user can take, and BOTH
				// halves of it are now takeable. It once said "or rotate via
				// NextPub", which was not a thing anyone could do; then it
				// said rotation was unsupported, which stopped being true
				// when `pelfs rotate` landed. What has never changed is that
				// a mismatch cannot be fixed by publishing: rotation starts
				// from the key that signed the head, so the key still has to
				// arrive from somewhere first.
				return nil, fmt.Errorf("signing key %s does not match the branch head's key %x — readers would "+
					"reject the generation, so import the key that signed this volume. Once it is here, "+
					"`pelfs rotate --apply` replaces it through the custody chain (which is a decision, not a "+
					"repair: it retires the pin volume-wide)", path, prev.SigningPub[:8])
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
	var branch, signingKey, grace string
	var unsigned bool
	o, pos, err := parseArgs("init", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "ref name to create")
		fs.StringVar(&signingKey, "signing-key", "", signingKeyUsage)
		fs.StringVar(&grace, "grace", "", graceUsage)
		fs.BoolVar(&unsigned, "unsigned", false, unsignedUsage)
	})
	if err != nil {
		return exitErr(err)
	}
	if unsigned && signingKey != "" {
		return exitErr(errors.New("--unsigned and --signing-key contradict each other: an unsigned volume " +
			"has no signing key at all"))
	}
	window, err := parseGrace(grace)
	if err != nil {
		return exitErr(err)
	}
	if window > 0 {
		gracePacingNotice(window, o.snapshotInterval)
	}
	if err := initVolumeAt(o, pos[0], branch, signingKey, window, unsigned); err != nil {
		return exitErr(err)
	}
	fmt.Printf("  mount it:    pelfs shell %s\n", pos[0])
	return 0
}

// graceUsage is the one description of `pelfs init --grace`.
//
// It says what the window IS rather than what it is set to, because the
// number only means something against the two things it protects: how long
// an object nothing names any more survives, and therefore how long a
// reader may hold a generation the branch has moved past.
const graceUsage = "the volume's GC grace window, recorded in the superblock and used by every " +
	"later seal, repack and gc (default 72h, floor 1h). It is how long an object nothing " +
	"references survives, and so how long a reader may go on using a generation the branch has " +
	"moved past. Set once at creation: seals carry the recorded value forward"

// parseGrace turns the flag into a window, refusing the footgun BEFORE a
// volume exists rather than inside a publish that has already uploaded.
func parseGrace(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--grace: %w", err)
	}
	if d < publish.MinGrace {
		return 0, fmt.Errorf("--grace %s is under the %s floor: the grace window is what makes a sweep "+
			"safe to run beside a live writer with no coordination, so a shorter one lets `pelfs gc` "+
			"delete a pack a concurrent seal is about to reference", d, publish.MinGrace)
	}
	return d, nil
}

// gracePacingNotice says out loud what a large window costs, at the moment
// the number is chosen.
//
// THE INTERACTION IT REPORTS. The condemned ledgers are what keep an object
// alive for the window once no enumerable generation names it, and they are
// capped in BYTES (superblock.CondemnedBudgetBytes) because they share the
// superblock's write budget. They grow at one row per checkpoint per key
// space, so the rows a window asks for are grace/checkpoint-interval — and
// past about 517 hash-named rows the CAP BINDS BEFORE THE WINDOW DOES. The
// volume then behaves as though its window were 517 checkpoints long, and a
// repack paces its plan to the room the ledger has instead of condemning
// everything it found (repack.trimToLedger).
//
// That is safe — every enumerable root names its own objects directly, so
// nothing a sweep can walk is at risk, and pacing only delays reclamation —
// but it is the difference between what an operator asked for and what
// retired generations get, and finding it out from a ledger months later is
// strictly worse than being told here.
func gracePacingNotice(grace, interval time.Duration) {
	if interval <= 0 {
		return
	}
	rows, capacity := superblock.LedgerWindow(grace, interval)
	if capacity <= 0 || rows <= capacity {
		return
	}
	ui.Warn("--grace {grace} at a {interval} checkpoint interval asks the condemned ledgers for about "+
		"{rows} rows and their share of the superblock carries about {capacity}: the byte cap binds "+
		"first, so objects only a RETIRED generation names keep about {effective} rather than {grace}, "+
		"and repacks are paced to the room the ledger has. Nothing a branch head or tag names is "+
		"affected. Fewer checkpoints (--snapshot-interval) buys window; a tag pins a generation for "+
		"as long as the tag exists",
		"grace", grace, "interval", interval, "rows", rows, "capacity", capacity,
		"effective", (time.Duration(capacity) * interval).Round(time.Minute))
}

// initVolumeAt creates a brand-new volume: generation 0 with an empty
// root, its volume id and signing key minted locally. It is what
// `pelfs init` runs, and what `pelfs shell` runs when it is pointed at an
// empty prefix.
//
// grace is the volume's T_grace, zero meaning the format's default. It can
// only be set HERE, because generation 0 is the only generation that
// chooses it: every seal after this carries the recorded value forward.
func initVolumeAt(o *cmdOpts, prefix, branch, signingKeyPath string, grace time.Duration, unsigned bool) error {
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
	// that path — the ordinary case. --unsigned mints nothing at all.
	var signingKey ed25519.PrivateKey
	if !unsigned {
		if signingKey, err = loadOrCreateSigningKey(signingKeyFileIn(stateDir, signingKeyPath), nil); err != nil {
			return err
		}
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
		Unsigned:   unsigned,
		VolumeID:   volID,
		Grace:      grace,
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
	if unsigned {
		// THIS MACHINE consented by typing --unsigned, so it records the
		// consent and does not have to type --allow-unsigned at every verb
		// afterwards. Every OTHER machine still does: the pin is local, and
		// it is the only thing that makes an unsigned volume readable.
		if err := rstore.AcceptUnsigned(); err != nil {
			return err
		}
	}
	// The window is worth reporting even when it is the default: it is
	// recorded on generation 0 and every later seal carries it, so this is
	// the one moment it is decided and the only place a user sees the
	// number they will be living with.
	window := publish.DefaultGrace
	if grace > 0 {
		window = grace
	}
	ui.Info("created volume {volume} on {ref} (generation 0, grace window {grace})",
		"volume", fmt.Sprintf("%x", volID), "ref", refs.RefDirKey+"/"+branch, "grace", window)
	if unsigned {
		ui.Warn("UNSIGNED volume: anyone who can write this prefix can replace it undetectably. " +
			"Other machines need --allow-unsigned to read it")
	}
	return nil
}

// unsignedUsage is the one description of `pelfs init --unsigned`.
//
// It leads with what is GIVEN UP rather than with what is saved, because
// the saving is obvious from the flag name and the cost is not.
const unsignedUsage = "create a volume with NO signing key, so nothing it publishes is authenticated. " +
	"For throwaway work on a prefix only you can write: anyone else who can write it can replace the " +
	"volume undetectably, and readers must pass --allow-unsigned. `pelfs rotate --to-signed` gives one a " +
	"key later, but signs whatever it finds"

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
