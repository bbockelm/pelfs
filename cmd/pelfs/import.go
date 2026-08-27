package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/importvol"
	"github.com/bbockelm/pelfs/internal/inodemap"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// `pelfs import <volume> <path> <source-prefix>`.
//
// Copies another pelfs volume's tree into this one at <path>, renumbered
// into inode lineages this volume owns, with every byte carried into this
// volume's own packs and the whole thing re-signed under this volume's
// key. AFTERWARDS NOTHING IN THE IMPORTED TREE RESOLVES ANYWHERE ELSE —
// which is the entire difference from `pelfs graft`, and the reason to
// pay for the copy.
//
// The argument order is `<volume> <path> <source>`, matching `pelfs graft`
// exactly, because the two commands do the same thing to the same place
// with a different bargain and having them disagree about which argument
// is which would be a trap. The source's branch, tag or generation is
// selected with --from-branch / --from-tag / --from-generation rather than
// by decorating the prefix, so the prefix stays the same string every
// other command takes.
//
// The phases, and where each can fail:
//
//  1. PREFLIGHT, before a byte is read: the destination path is resolved,
//     the collision is classified, the encryption domains are compared,
//     and the signing key is loaded. All of it costs one listing per path
//     component, and all of it is news that has to arrive in the first
//     second rather than the last.
//  2. SCAN, O(catalog bytes): the source's namespace is walked to find
//     the inode lineages it contains — which nothing in the format
//     records — the identity set to copy, and what to report.
//  3. COPY, O(data bytes): every wanted entry is carried STORED from the
//     source's packs into new packs of ours. Checkpointed, so a killed
//     run resumes.
//  4. PUBLISH: the lease, a re-read of the head, the splice, and the ref
//     flip. Nothing before this point has changed what the branch serves.
func cmdImport(args []string) int {
	var (
		pubkeyHex    string
		srcPubkeyHex string
		branch       string
		fromBranch   string
		fromTag      string
		fromGen      int64
		replace      bool
		list         bool
		dryRun       bool
		restart      bool
		packSize     int64
	)
	o, pos, err := parseArgs("import", args, 1, 3, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 key to trust for THIS volume (default: pin on first use)")
		fs.StringVar(&srcPubkeyHex, "source-pubkey", "", "hex Ed25519 key to trust for the SOURCE volume (default: pin on first use)")
		fs.StringVar(&branch, "branch", "main", "branch of this volume to seal onto")
		fs.StringVar(&fromBranch, "from-branch", "main", "branch of the SOURCE volume to import")
		fs.StringVar(&fromTag, "from-tag", "", "tag of the SOURCE volume to import, instead of a branch head")
		fs.Int64Var(&fromGen, "from-generation", -1, "refuse unless the source generation being imported is exactly this number")
		fs.BoolVar(&replace, "replace", false, "permit the imported tree to displace a populated directory, or a file, already at <path>")
		fs.BoolVar(&list, "list", false, "report what this volume has imported and exit")
		fs.BoolVar(&dryRun, "dry-run", false, "scan and report what would be imported, then stop before copying a byte")
		fs.BoolVar(&restart, "restart", false, "discard the checkpoint and copy the whole source again")
		fs.Int64Var(&packSize, "pack-size", 0, "cut the packs this writes at about this many bytes")
	})
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	inner, rstore, stateDir, err := volumeStore(ctx, o, pos[0], pubkeyHex)
	if err != nil {
		return exitErr(err)
	}

	if list {
		return reportImports(ctx, rstore, branch, pos[0])
	}
	if len(pos) != 3 {
		return exitErr(errors.New("usage: pelfs import <volume> <path> <source-prefix>"))
	}
	if fromTag != "" && fromBranch != "main" {
		return exitErr(errors.New("--from-tag pins a generation exactly and --from-branch follows a " +
			"head; pass one of them"))
	}
	mountPath := cleanGraftPath(pos[1])
	source := pos[2]
	if source == pos[0] {
		return exitErr(fmt.Errorf("the source and the destination are the same prefix (%s); an "+
			"import copies BETWEEN volumes, and `pelfs branch` is what copies a line of history "+
			"inside one", source))
	}

	head, err := rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(fmt.Errorf("read %s/%s: %w", refs.RefDirKey, branch, err))
	}

	// ---- the source, opened and verified ----
	//
	// The source gets its own state directory — the ordinary per-prefix
	// one — so that its key is pinned on first use exactly as a mount of
	// it would pin it, and a second import from the same source checks
	// against the same pin.
	srcStateDir := volDir(source)
	if o.stateDir != "" {
		srcStateDir = filepath.Join(o.stateDir, "import-src", filepath.Base(volDir(source)))
	}
	if err := os.MkdirAll(srcStateDir, 0700); err != nil {
		return exitErr(err)
	}
	srcInner, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: source, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return exitErr(fmt.Errorf("open the import source %s: %w", source, err))
	}
	srcRefs, err := refsFor(o, srcInner, srcStateDir, srcPubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	// THE SOURCE'S SIGNATURE IS CHECKED HERE AND NOWHERE LATER. Both
	// Fetch and FetchTag verify it against the pinned key; what that buys
	// is the confirmation that we imported what they published, and after
	// the copy their signature has nothing left to sign in our document.
	srcSB, srcRaw, srcRefName, err := fetchSource(ctx, srcRefs, fromBranch, fromTag)
	if err != nil {
		return exitErr(err)
	}
	if fromGen >= 0 && srcSB.Generation != uint64(fromGen) {
		// A generation is addressable only through a ref or a tag, so
		// --from-generation cannot RESOLVE one. What it can do, and what
		// it is for, is refuse to import anything but the number a script
		// was written against.
		return exitErr(fmt.Errorf("--from-generation %d, but %s of %s is at generation %d. A "+
			"generation is addressable only through a branch or a tag, so this flag asserts which "+
			"one you meant rather than selecting it: tag the generation on the source and use "+
			"--from-tag", fromGen, srcRefName, source, srcSB.Generation))
	}
	if srcSB.VolumeID == head.Superblock.VolumeID {
		return exitErr(fmt.Errorf("%s and %s are the same volume (%x). Importing a volume into "+
			"itself would renumber its own tree into new lineages and store a second copy of every "+
			"byte; `pelfs branch` is what makes a second line of history",
			source, pos[0], srcSB.VolumeID[:8]))
	}

	// ---- everything that can fail cheaply, before the hours start ----
	signingKey, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, ""), head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	kek, err := loadKEK(o)
	if err != nil {
		return exitErr(err)
	}
	custody, err := importvol.CheckCustody(srcSB, head.Superblock, kek)
	if err != nil {
		return exitErr(err)
	}
	base, err := openGraftBase(ctx, o, inner, stateDir, head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	preflight, err := publish.ImportPreflight(ctx, publish.ImportSpliceOptions{
		Base: base, Prev: head.Superblock, Mount: mountPath, Replace: replace,
	})
	base.Close() //nolint:errcheck
	if err != nil {
		return exitErr(err)
	}
	plan := importPlan{ImportPlan: preflight, generationAtPreflight: head.Superblock.Generation}
	reportImportPlan(preflight, mountPath, source, srcRefName, srcSB)
	warnAboutLeftoverOverlay(stateDir)

	// ---- the scan ----
	srcFS, err := genfs.Open(ctx, genfs.Options{
		Inner: srcInner, SB: srcSB, CacheDir: filepath.Join(srcStateDir, "gencache"),
		GraftOpener: graftOpenerQuiet(o),
	})
	if err != nil {
		return exitErr(fmt.Errorf("read generation %d of %s: %w", srcSB.Generation, source, err))
	}
	defer srcFS.Close() //nolint:errcheck

	ui.Info("scanning {source} {ref} (generation {gen}): reading its catalogs to find the inode "+
		"lineages it holds, which nothing in the format records",
		"source", source, "ref", srcRefName, "gen", srcSB.Generation)
	scan, err := importvol.Walk(ctx, importvol.ScanOptions{
		FS: srcFS, SB: srcSB, SpoolDir: filepath.Join(stateDir, "import"),
		Progress: reportImportProgress,
	})
	if err != nil {
		return exitErr(err)
	}
	defer scan.Wants.Close() //nolint:errcheck
	ui.Info("{inodes} inodes ({dirs} directories, {files} files, {symlinks} symlinks, "+
		"{hardlinks} hard-linked), {bytes} bytes, {chunks} distinct chunk identities named "+
		"{refs} times, in {lineages} inode lineage(s)",
		"inodes", scan.Inodes, "dirs", scan.Dirs, "files", scan.Files,
		"symlinks", scan.Symlinks, "hardlinks", scan.Hardlinks, "bytes", scan.Bytes,
		"chunks", scan.Chunks, "refs", scan.ChunkRefs, "lineages", len(scan.Lineages))

	// ---- the renumbering ----
	//
	// The lineages come from the SAME allocator branches and tags draw
	// from, checked across every ref this volume can name, so a later
	// `pelfs branch` cannot take one this import has handed out.
	taken, err := takenLineages(ctx, inner, rstore)
	if err != nil {
		return exitErr(err)
	}
	imap, err := inodemap.DrawFor(scan.Lineages, inodemap.TakenIn(taken))
	if err != nil {
		return exitErr(err)
	}
	ui.Info("renumbering: source lineage(s) {from} become {to} — drawn from the same allocator "+
		"`pelfs branch` draws from, so nothing here can hand out a number twice",
		"from", scan.Lineages, "to", imap.Destinations())

	if dryRun {
		ui.Info("--dry-run: nothing was copied and the branch was not touched. The import would "+
			"place {bytes} bytes at {path} and take {n} inode lineage(s)",
			"bytes", scan.Bytes, "path", mountPath, "n", imap.Len())
		return 0
	}

	// ---- the copy ----
	srcPacks, err := manifest.Packs(ctx, srcInner, srcSB)
	if err != nil {
		return exitErr(fmt.Errorf("resolve the source's pack set: %w", err))
	}
	if packSize <= 0 {
		packSize = 64 << 20
	}
	ckptPath := importvol.CheckpointPath(stateDir, mountPath, source)
	if restart {
		if err := os.Remove(ckptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return exitErr(err)
		}
	}
	ckpt, err := importvol.OpenCheckpoint(ckptPath, importvol.Header{
		SourceVolumeID: srcSB.VolumeID, SourceGeneration: srcSB.Generation,
		SourceHash: superblock.Hash(srcRaw), Path: mountPath, TargetPackSize: packSize,
	})
	if err != nil {
		return exitErr(err)
	}
	defer ckpt.Close() //nolint:errcheck
	if why := ckpt.Discarded(); why != "" {
		ui.Warn("starting the copy from the beginning: the checkpoint at {path} could not be "+
			"used because {why}", "path", ckptPath, "why", why)
	}
	spool := filepath.Join(stateDir, "import", "spool")
	if err := os.MkdirAll(spool, 0700); err != nil {
		return exitErr(err)
	}
	defer os.RemoveAll(spool) //nolint:errcheck

	ui.Info("copying {bytes} bytes out of {packs} of {source}'s packs. The entries are carried "+
		"STORED — already compressed, already encrypted — so this needs no data key and cannot "+
		"change what a chunk resolves to",
		"bytes", scan.Bytes, "packs", len(srcPacks), "source", source)
	cp, err := importvol.Copy(ctx, importvol.CopyOptions{
		Src: srcInner, SrcPacks: srcPacks, Dst: inner, SpoolDir: spool,
		Wants: scan.Wants, TargetPackSize: packSize, Checkpoint: ckpt,
		Progress: reportImportProgress,
	})
	if err != nil {
		ui.Warn("the copy stopped; {branch} still serves generation {gen}, and everything this "+
			"run uploaded is unreferenced and will be collected by `pelfs gc`. The checkpoint at "+
			"{path} is kept: run the same command again to carry on from it",
			"branch", branch, "gen", head.Superblock.Generation, "path", ckptPath)
		return exitErr(err)
	}
	ui.Info("carried {copied} entries ({bytes} bytes) in {elapsed}; {resumed} entries "+
		"({resumedbytes} bytes) were already here from an earlier run and were not read again",
		"copied", cp.Copied, "bytes", cp.CopiedBytes, "elapsed", cp.Elapsed.Round(time.Second),
		"resumed", cp.Resumed, "resumedbytes", cp.ResumedBytes)

	// ---- the publish ----
	//
	// THE LEASE IS TAKEN HERE AND NOT BEFORE THE COPY. The copy reads a
	// third party's storage and writes objects nothing references;
	// holding the branch for the hours that takes would stop a mount
	// checkpointing for no reason. What needs protecting is the window
	// from "read the head" to "flip the ref".
	lease, err := maintenanceLease(ctx, o, pos[0], branch, "import-"+newSessionID())
	if err != nil {
		return exitErr(err)
	}
	defer releaseLease(ctx, lease)

	// AND THE HEAD IS RE-READ, because the copy took as long as it took.
	// Splicing against the generation this command started from would
	// publish a tree that never existed: every write a mount checkpointed
	// while the copy ran would be silently reverted.
	head, err = rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(fmt.Errorf("re-read %s/%s after the copy: %w", refs.RefDirKey, branch, err))
	}
	if head.Superblock.Generation != plan.generationAtPreflight {
		ui.Warn("the branch moved from generation {was} to {now} while the source was being "+
			"copied; the tree is spliced into {now}, and the preflight is re-run against it",
			"was", plan.generationAtPreflight, "now", head.Superblock.Generation)
	}
	// Re-checked against the RE-READ head, not redeclared: the preflight
	// loaded this key hours ago and the head moved under it. An import
	// publishes a successor, so it must sign the way the head signs NOW —
	// and on an UNSIGNED volume it must not MINT a key, which is what a
	// nil predecessor would have it do. `pelfs graft` re-loads here for
	// exactly this reason.
	signingKey, err = loadOrCreateSigningKey(signingKeyFileIn(stateDir, ""), head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	base, err = openGraftBase(ctx, o, inner, stateDir, head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	defer base.Close() //nolint:errcheck
	splice, err := publish.NewImportSpliceSource(ctx, publish.ImportSpliceOptions{
		Base: base, Prev: head.Superblock, Src: srcFS, Map: imap,
		SourceMark: srcSB.NextInode, Mount: mountPath, Replace: replace,
		Packs: cp.Packs, Entries: cp.Entries, TranslateKeyID: custody.Translate,
	})
	if err != nil {
		return exitErr(err)
	}
	entry := superblock.ImportEntry{
		Path: splice.Mount(), Source: source, SourceBranch: srcRefName,
		SourceVolumeID: srcSB.VolumeID, SourceGeneration: srcSB.Generation,
		SourceHash: superblock.Hash(srcRaw), SourcePub: srcSB.SigningPub,
		ImportedUnixNano: time.Now().UnixNano(), Lineages: imap.Pairs(),
		Files: scan.Files, Inodes: scan.Inodes, Bytes: scan.Bytes,
	}
	popts := publish.Options{
		Source: splice, Inner: inner, SpoolDir: stateDir, Branch: branch,
		SigningKey: signingKey, Prev: head.Superblock, PrevRaw: head.Raw,
		DedupIndexPath: filepath.Join(stateDir, dedupIndexName),
		// The parent's imports plus this one. Options.Imports REPLACES
		// the list, so it is stated whole — and no entry is ever removed,
		// because every one of them is a permanent lineage claim.
		Imports: append(append([]superblock.ImportEntry(nil), head.Superblock.Imports...), entry),
	}
	if o.encryptKeyPath != "" {
		pem, err := os.ReadFile(o.encryptKeyPath)
		if err != nil {
			return exitErr(fmt.Errorf("read --encrypt-key: %w", err))
		}
		if err := wireEncryption(&popts, string(pem), head.Superblock); err != nil {
			return exitErr(err)
		}
	}
	pub, err := publish.Publish(ctx, popts)
	if err != nil {
		return exitErr(err)
	}
	if err := ckpt.Remove(); err != nil {
		ui.Warn("the import landed but its checkpoint could not be removed: {err}", "err", err)
	}

	ui.Info("imported {files} files ({bytes} bytes) at {path} from {source} {ref} generation {gen}",
		"files", scan.Files, "bytes", scan.Bytes, "path", entry.Path, "source", source,
		"ref", srcRefName, "gen", srcSB.Generation)
	// The honest sentence, said at the one moment the person doing it is
	// paying attention — and it is the opposite of the one `pelfs graft`
	// has to say.
	ui.Info("this volume now holds those bytes itself: nothing under {path} resolves to {source}, "+
		"and `pelfs gc` on the source cannot take it away", "path", entry.Path, "source", source)
	ui.Info("their inodes were renumbered into lineage(s) {to}, which this volume has taken for "+
		"good: `pelfs branch` will never draw one of them", "to", imap.Destinations())
	ui.Info("generation {gen} is the previous tree with {path} spliced in: {carried} catalogs "+
		"carried forward unchanged, {wrote} rewritten",
		"gen", pub.Superblock.Generation, "path", entry.Path,
		"carried", pub.Stats.CatalogsReused, "wrote", pub.Stats.Catalogs)
	return 0
}

// importPlan is a preflight plus the generation it was run against, so
// the second preflight can say whether the branch moved.
type importPlan struct {
	*publish.ImportPlan
	generationAtPreflight uint64
}

// reportImports is `pelfs import --list`: what this volume has taken in,
// and which inode lineages that cost it.
//
// It is worth a verb of its own because after an import the tree is
// indistinguishable from one this volume produced — that is the point —
// so the superblock is the ONLY record of where those files came from.
func reportImports(ctx context.Context, rstore *refs.Store, branch, prefix string) int {
	head, err := rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(fmt.Errorf("read %s/%s: %w", refs.RefDirKey, branch, err))
	}
	if len(head.Superblock.Imports) == 0 {
		ui.Info("generation {gen} of {prefix} has imported nothing",
			"gen", head.Superblock.Generation, "prefix", prefix)
		return 0
	}
	for _, im := range head.Superblock.Imports {
		var pairs []string
		for _, l := range im.Lineages {
			pairs = append(pairs, fmt.Sprintf("%d->%d", l.From, l.To))
		}
		ui.Info("{path} <- {source} {ref} generation {gen} of volume {volume} "+
			"({files} files, {inodes} inodes, {bytes} bytes; lineages {lineages}; signed by {pub})",
			"path", im.Path, "source", im.Source, "ref", im.SourceBranch,
			"gen", im.SourceGeneration, "volume", fmt.Sprintf("%x", im.SourceVolumeID[:8]),
			"files", im.Files, "inodes", im.Inodes, "bytes", im.Bytes,
			"lineages", strings.Join(pairs, " "), "pub", fmt.Sprintf("%x", im.SourcePub[:8]))
	}
	ui.Info("these are PROVENANCE and a lineage claim, not a dependency: the bytes are in this " +
		"volume's own packs, and the entries stay even if the trees are moved or deleted, " +
		"because the inode numbers they name are still out there")
	return 0
}

// fetchSource resolves the source generation and verifies its signature.
func fetchSource(ctx context.Context, rs *refs.Store, branch, tag string) (
	*superblock.Superblock, []byte, string, error) {

	if tag != "" {
		sb, raw, err := rs.FetchTag(ctx, tag)
		if err != nil {
			return nil, nil, "", fmt.Errorf("read the source's tag %s: %w", tag, err)
		}
		return sb, raw, "tags/" + tag, nil
	}
	f, err := rs.Fetch(ctx, branch)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read the source's %s/%s: %w", refs.RefDirKey, branch, err)
	}
	return f.Superblock, f.Raw, branch, nil
}

// refsFor opens a refs store over the SOURCE prefix, pinning its key on
// first use unless one was named.
//
// A SECOND TOFU SURFACE IS WHAT AN IMPORT ADDS, and it is worth naming:
// this command trusts a key it may never have seen, once, to decide what
// bytes to copy. It is a smaller surface than a graft's or a reference's
// because it is not ongoing — after the import nothing here consults that
// key again, and what was copied is covered by OUR signature — but the
// first fetch is still a trust decision, which is why --source-pubkey
// exists and why the plan report names the key that signed what was read.
func refsFor(o *cmdOpts, inner pelicanobj.Store, stateDir, pubkeyHex string) (*refs.Store, error) {
	var trusted ed25519.PublicKey
	if pubkeyHex != "" {
		k, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, errors.New("--source-pubkey must be 64 hex characters")
		}
		trusted = k
	}
	// --allow-unsigned reaches the SOURCE as well, and it has to: an
	// unsigned volume never TOFUs, so without the flag an import of one is
	// refused before a byte is read — which is the right default, because
	// there is no key to bootstrap trust in and accepting would mean
	// nothing more than "whoever can write that prefix". The flag is the
	// consent, and it is the same consent a mount of that volume needs.
	return refs.NewWithPolicy(inner, stateDir, refs.Policy{
		Trusted: trusted, AllowUnsigned: o.allowUnsigned,
	})
}

// loadKEK reads --encrypt-key when one was given. It is needed only when
// either volume is encrypted, and CheckCustody says so when it is missing
// rather than this refusing up front.
func loadKEK(o *cmdOpts) (*rsa.PrivateKey, error) {
	if o.encryptKeyPath == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(o.encryptKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read --encrypt-key: %w", err)
	}
	return superblock.LoadRSAPrivateKeyPEM(pem, keyPassphrase())
}

// reportImportPlan says what is about to happen to the path, BEFORE the
// hours of copying start. Every line is a thing that could have been done
// silently.
func reportImportPlan(p *publish.ImportPlan, mount, source, ref string, sb *superblock.Superblock) {
	switch p.Placement {
	case publish.ImportPlaceReplacedDir:
		ui.Warn("--replace: {path} holds {n} entries and they will NOT be in the next generation. "+
			"The generation that holds them stays readable until it ages out of the retention "+
			"window, and nothing about an import will bring them back",
			"path", mount, "n", p.DisplacedEntries)
	case publish.ImportPlaceReplacedFile:
		ui.Warn("--replace: the {kind} at {path} will not be in the next generation",
			"kind", graftTypeWord(p.DisplacedType), "path", mount)
	case publish.ImportPlaceEmptyDir:
		ui.Info("importing into the empty directory already at {path}", "path", mount)
	case publish.ImportPlaceNew:
		if len(p.SyntheticDirs) > 0 {
			ui.Info("{path} does not exist yet; these directories will be created for it: {dirs}",
				"path", mount, "dirs", p.SyntheticDirs)
		}
	}
	if sb.IsUnsigned() {
		// Said as a WARNING, because it is the one fact about this import
		// that no later check can recover. An unsigned source carries no
		// evidence of who produced it, so what lands here is "whatever was
		// at that prefix when we looked" — and once it is copied in and
		// re-signed under OUR key, our signature vouches for it. There is
		// no way to tell afterwards, which is why --allow-unsigned had to
		// be typed to get here at all.
		ui.Warn("source {source} {ref} is generation {gen} of volume {volume} and is UNSIGNED: "+
			"nothing attests that it is what its owner published. Importing it copies those bytes "+
			"in under this volume's own signature, and no later check can undo that",
			"source", source, "ref", ref, "gen", sb.Generation,
			"volume", fmt.Sprintf("%x", sb.VolumeID[:8]))
		return
	}
	ui.Info("source {source} {ref} is generation {gen} of volume {volume}, signed by {pub} "+
		"(verified before anything was read)",
		"source", source, "ref", ref, "gen", sb.Generation,
		"volume", fmt.Sprintf("%x", sb.VolumeID[:8]), "pub", fmt.Sprintf("%x", sb.SigningPub[:8]))
}

// reportImportProgress is the line a person watching an hours-long copy
// sees. It is on a TIMER rather than per object, for the reason the
// graft's is: a source of one enormous file has no per-object event to
// hang a line on.
func reportImportProgress(p importvol.Progress) {
	switch p.Phase {
	case "scanning":
		ui.Info("scanning: {done} inodes read, {rate}/s", "done", p.Done, "rate", int64(p.Rate()))
	default:
		pct := 0
		if p.Total > 0 {
			pct = int(p.Done * 100 / p.Total)
		}
		ui.Info("copying: {done}/{total} bytes ({pct}%), pack {packs}/{packtotal}, "+
			"{rate} bytes/s, about {eta} left",
			"done", p.Done, "total", p.Total, "pct", pct, "packs", p.Packs,
			"packtotal", p.PacksTotal, "rate", int64(p.Rate()), "eta", p.ETA().Round(time.Second))
	}
}
