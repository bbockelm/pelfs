package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// `pelfs graft <volume> <path> <source>`.
//
// Spiders a foreign Pelican prefix, records a block digest for every byte
// of it, and publishes a generation that serves the tree at <path> with
// no copy of the data under the volume's own prefix.
//
// The tree is SPLICED into the volume: everything the volume already
// serves stays exactly as the previous generation published it, and only
// the catalogs from the graft path to the root are rewritten
// (internal/publish/graftsplice.go). What happens when something is
// already at the graft path is a decision per case, and every refusal ends
// in what to do instead — the table is in docs/design-graft.md.
//
// What is proven and what is not is in docs/design-graft.md.

func cmdGraft(args []string) int {
	var (
		pubkeyHex string
		block     int64
		blockMax  int64
		perObject int
		branch    string
		list      bool
		refresh   bool
		conc      int
		span      int64
		restart   bool
		replace   bool
		remove    bool
	)
	o, pos, err := parseArgs("graft", args, 1, 3, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.Int64Var(&block, "block", graft.DefaultBlock, "base (smallest) block the spider cuts and digests at")
		fs.Int64Var(&blockMax, "block-max", graft.DefaultBlockMax, "largest block the per-object ladder will climb to; equal to --block disables the ladder")
		fs.IntVar(&perObject, "blocks-per-object", graft.DefaultBlocksPerObject, "blocks one object may be cut into before its block size doubles")
		fs.StringVar(&branch, "branch", "main", "branch to seal onto")
		fs.BoolVar(&list, "list", false, "report the grafts this volume serves and exit")
		fs.BoolVar(&refresh, "refresh", false, "re-spider the graft already recorded at <path>, reusing its source and block rule")
		fs.IntVar(&conc, "concurrency", 0, "ranged reads of the source in flight (default: the transfer pool)")
		fs.Int64Var(&span, "span", graft.DefaultSpanBytes, "most bytes one ranged read of the source covers")
		fs.BoolVar(&restart, "restart", false, "discard the checkpoint and re-read the whole source")
		fs.BoolVar(&replace, "replace", false, "permit the graft to displace a populated directory, or a file, already at <path>")
		fs.BoolVar(&remove, "remove", false, "drop the graft at <path> and publish a generation without it")
	})
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	inner, rstore, stateDir, err := volumeStore(ctx, o, pos[0], pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	head, err := rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(fmt.Errorf("read %s/%s: %w", refs.RefDirKey, branch, err))
	}

	if list {
		// A reader is entitled to know what a mount will reach out to
		// BEFORE it reads a byte. The signature makes these URLs
		// tamper-evident, not safe, so "which third parties does this
		// volume send my client to" is a question with a right to a cheap
		// answer — it comes out of the superblock alone, no index fetch.
		if len(head.Superblock.Grafts) == 0 {
			ui.Info("generation {generation} serves no grafts", "generation", head.Superblock.Generation)
			return 0
		}
		for _, g := range head.Superblock.Grafts {
			ui.Info("{path} <- {source} ({files} files, {bytes} bytes in {blocks} blocks; "+
				"index {index} bytes, read {mode})",
				"path", g.Path, "source", g.Source, "files", g.Files,
				"bytes", g.Bytes, "blocks", g.Blocks, "index", g.Size,
				"mode", indexReadMode(g))
		}
		return 0
	}

	if refresh && remove {
		return exitErr(fmt.Errorf("--refresh re-reads a graft and --remove deletes one; " +
			"pass one of them"))
	}
	policy := graft.BlockPolicy{Block: block, Max: blockMax, PerObject: perObject}
	var mountPath, source string
	switch {
	case remove:
		// A removal reads nothing: it publishes the previous generation's
		// tree with one subtree taken out and the superblock's graft entry
		// dropped. The path is the only argument, and the source comes
		// from the recorded entry so that the report can say what stopped
		// being depended on.
		if len(pos) != 2 {
			return exitErr(fmt.Errorf("usage: pelfs graft --remove <volume> <path>"))
		}
		mountPath = cleanGraftPath(pos[1])
	case refresh:
		// A refresh must cut IDENTICALLY or every identity moves and it is
		// a new graft rather than a refresh, so the source and the rule
		// come out of the recorded entry rather than off the command line.
		if len(pos) != 2 {
			return exitErr(fmt.Errorf("usage: pelfs graft --refresh <volume> <path>"))
		}
		mountPath = cleanGraftPath(pos[1])
		var found bool
		for _, g := range head.Superblock.Grafts {
			if g.Path == mountPath {
				source, policy, found = g.Source, policyOf(g), true
			}
		}
		if !found {
			return exitErr(fmt.Errorf("this generation serves no graft at %s (`pelfs graft --list %s` shows what it does serve)",
				mountPath, pos[0]))
		}
		ui.Info("refreshing {path} from {source}, cut as it was cut before ({block}-{blockmax} bytes, {per} blocks per object)",
			"path", mountPath, "source", source, "block", policy.Block,
			"blockmax", policy.Max, "per", policy.PerObject)
	default:
		if len(pos) != 3 {
			return exitErr(fmt.Errorf("usage: pelfs graft <volume> <path> <source-url>"))
		}
		mountPath, source = cleanGraftPath(pos[1]), pos[2]
	}
	if err := policy.Validate(); err != nil {
		return exitErr(err)
	}

	if head.Superblock.CatalogKeyID != 0 {
		// Refused at the writer too, so an encrypted volume never carries
		// a graft that its own readers would then refuse to mount. The
		// reason is in genfs.openGrafts: nothing there can verify a
		// grafted block on a keyed-identity volume.
		return exitErr(fmt.Errorf("volume %s is encrypted; a graft's blocks carry no AEAD tag and "+
			"its identities are keyed, so no reader could verify them "+
			"(docs/design-graft.md, \"Encryption\")", pos[0]))
	}

	// THE SECURITY DECISION, enforced at the writer as well as the reader.
	//
	// A graft makes OTHER PEOPLE's clients fetch a URL this volume's
	// author chose, from their network position and with their credentials
	// — a class of exposure packs do not have, because a pack lives under
	// the volume's own prefix and a reader who trusts the volume already
	// trusts that prefix. Signing the URL makes it tamper-evident; it does
	// nothing about the URL being a bad idea in the first place.
	//
	// So the scheme is allowlisted, and file:// is refused absolutely: a
	// graft naming a local path would resolve to a DIFFERENT tree on every
	// machine that mounted the volume, which is not a filesystem. The
	// reader has an independent veto in genfs (Options.GraftOpener), and
	// that is the one that actually protects a reader — this check only
	// stops an author publishing something no reader should accept.
	if !remove {
		if err := checkGraftSource(source); err != nil {
			return exitErr(err)
		}
	}

	// EVERYTHING THAT CAN FAIL CHEAPLY FAILS HERE, before a byte of
	// somebody else's storage has been read. A graft streams the whole
	// source once, which at TB scale is hours, so "there is a populated
	// directory at that path" and "this state directory does not hold this
	// volume's signing key" are both news that has to arrive in the first
	// second rather than the last.
	signingKey, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, ""), head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	plan, err := graftPreflight(ctx, o, inner, stateDir, head.Superblock, mountPath, source, replace, refresh, remove)
	if err != nil {
		return exitErr(err)
	}
	reportGraftPlan(plan, mountPath, source, remove)
	warnAboutLeftoverOverlay(stateDir)

	if remove {
		return graftRemove(ctx, graftPublishArgs{
			o: o, inner: inner, refs: rstore, stateDir: stateDir, prefix: pos[0],
			branch: branch, head: head, key: signingKey, mount: mountPath,
		})
	}

	src, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: source, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return exitErr(fmt.Errorf("open graft source %s: %w", source, err))
	}

	// THE CHECKPOINT. A graft reads every byte of the source once, which
	// at TB scale is hours; a walk that could not survive a Ctrl-C, an
	// eviction or a token expiring would not be usable at that size. It is
	// also what makes a refresh cost only what CHANGED.
	ckptPath := graft.CheckpointPath(stateDir, mountPath, source)
	if restart {
		if err := os.Remove(ckptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return exitErr(err)
		}
	}
	ckpt, discarded, err := graft.OpenCheckpoint(ckptPath, graft.CheckpointHeader{
		Source: source, Mount: mountPath, Block: policy.Block, BlockMax: policy.Max,
		PerObject: policy.PerObject, Hasher: "blake3-256",
	})
	if err != nil {
		return exitErr(err)
	}
	defer ckpt.Close() //nolint:errcheck
	if discarded != "" {
		ui.Warn("starting the walk from the beginning: {why}", "why", discarded)
	} else if n := ckpt.Resumed(); n > 0 {
		ui.Info("resuming: {bytes} bytes of this source were already digested "+
			"(each is re-checked against the source listing before it is trusted)",
			"bytes", n)
	}

	spool := filepath.Join(stateDir, "graft", "spool")
	if err := os.MkdirAll(spool, 0700); err != nil {
		return exitErr(err)
	}
	defer os.RemoveAll(spool) //nolint:errcheck
	idx, err := graft.NewWriter(spool, policy.Block)
	if err != nil {
		return exitErr(err)
	}
	defer idx.Close() //nolint:errcheck

	ui.Info("spidering {source}: every byte is read ONCE to digest it, which is network you pay "+
		"now and never again — the volume stores no copy of it", "source", source)
	res, err := graft.Spider(ctx, graft.SpiderOptions{
		Src: src, Index: idx, Policy: policy, Checkpoint: ckpt,
		Concurrency: conc, SpanBytes: span,
		Progress: reportGraftProgress,
	})
	if err != nil {
		return exitErr(err)
	}
	if len(res.Files) == 0 {
		return exitErr(fmt.Errorf("graft source %s holds no objects", source))
	}
	if err := ckpt.Close(); err != nil {
		return exitErr(err)
	}
	ui.Info("digested {hashed} bytes in {elapsed} ({rate}/s); {resumed} bytes were already "+
		"checkpointed and were not read again",
		"hashed", res.BytesHashed, "elapsed", res.Elapsed.Round(time.Second),
		"rate", int64(graft.Progress{BytesHashed: res.BytesHashed, Elapsed: res.Elapsed}.Rate()),
		"resumed", res.BytesResumed)

	entry, err := idx.Publish(ctx, inner, graft.PublishOptions{
		Mount: mountPath, Source: source, Policy: policy,
		Bytes: res.Bytes, Files: len(res.Files) - res.Inlined,
	})
	if err != nil {
		return exitErr(err)
	}
	gsrc, err := publish.NewGraftSource(publish.GraftSourceOptions{
		Mount:  mountPath,
		Result: res,
	})
	if err != nil {
		return exitErr(err)
	}

	// THE LEASE, taken HERE and not before the walk. The walk touches
	// nothing of this volume — it reads a third party's storage — and
	// holding the branch for the hours that takes would stop a mount from
	// checkpointing for no reason at all. What needs protecting is the
	// window from "read the head" to "flip the ref", which is what
	// everything below is.
	lease, err := maintenanceLease(ctx, o, pos[0], branch, "graft-"+newSessionID())
	if err != nil {
		return exitErr(err)
	}
	defer releaseLease(ctx, lease)

	// AND THE HEAD IS RE-READ, because the walk took as long as it took.
	// Splicing against the generation this command started from would
	// publish a tree that never existed: every write a mount checkpointed
	// while the spider ran would be silently reverted. The preflight runs
	// again for the same reason — a directory may have appeared at the
	// graft path in the meantime — and it is cheap enough to pay twice.
	head, err = rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(fmt.Errorf("re-read %s/%s after the walk: %w", refs.RefDirKey, branch, err))
	}
	if head.Superblock.Generation != plan.generation {
		ui.Warn("the branch moved from generation {was} to {now} while the source was being read; "+
			"the graft is spliced into {now}, and the preflight is being re-run against it",
			"was", plan.generation, "now", head.Superblock.Generation)
	}
	base, err := openGraftBase(ctx, o, inner, stateDir, head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	defer base.Close() //nolint:errcheck
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: head.Superblock, Graft: gsrc, Source: source,
		Mount: mountPath, Replace: replace, Refresh: refresh,
	})

	// Re-checked against the RE-READ head, not redeclared: the preflight
	// above already loaded this key, but the walk took hours and the head
	// moved under it. A graft publishes a successor, so it must sign the way
	// the head does NOW — and on an unsigned volume it must not MINT a key,
	// which is what a nil predecessor would have it do.
	signingKey, err = loadOrCreateSigningKey(signingKeyFileIn(stateDir, ""), head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	// The parent's grafts plus this one. Options.Grafts REPLACES the list,
	// so it has to be stated whole — carrying the parent's forward is what
	// keeps a second graft from deleting the first.
	grafts := graftListWith(head.Superblock.Grafts, entry)
	pub, err := publish.Publish(ctx, publish.Options{
		Source:     splice,
		Inner:      inner,
		SpoolDir:   stateDir,
		Branch:     branch,
		SigningKey: signingKey,
		Prev:       head.Superblock,
		PrevRaw:    head.Raw,
		Grafts:     grafts,
	})
	if err != nil {
		return exitErr(err)
	}
	ui.Info("grafted {files} files ({bytes} bytes) at {path} from {source}",
		"files", len(res.Files)-res.Inlined, "bytes", res.Bytes-res.InlinedBytes,
		"path", entry.Path, "source", source)
	if res.Inlined > 0 {
		// Said out loud rather than left to be inferred: these files are
		// COPIED into the volume and are not grafted at all. They no longer
		// depend on the source, which is a feature, but a user counting
		// files would otherwise be counting the wrong thing.
		ui.Info("{inlined} files under {keep} bytes were stored inline in the catalog "+
			"({inlinedbytes} bytes) and are not grafted: they no longer depend on the source",
			"inlined", res.Inlined, "keep", graft.InlineKeep, "inlinedbytes", res.InlinedBytes)
	}
	ui.Info("{blocks} blocks across {objects} source objects; index is {index} bytes, read {mode}",
		"blocks", entry.Blocks, "objects", entry.Objects,
		"index", entry.Size, "mode", indexReadMode(entry))
	// The honest sentence about what was just published, said at the one
	// moment the person doing it is paying attention: the volume now
	// depends on somebody else's storage staying exactly as it is.
	ui.Info("this volume now depends on {source}; a change there fails reads under {path} "+
		"rather than serving wrong bytes", "source", source, "path", entry.Path)
	ui.Info("the checkpoint at {path} is kept: `pelfs graft --refresh {volume} {mount}` will "+
		"re-read only what changed", "path", ckptPath, "volume", pos[0], "mount", entry.Path)
	// What a person grafting into a volume they care about most wants to
	// hear: the rest of it was not rewritten. The carried count is the
	// measure — those catalogs are the previous generation's bytes,
	// referenced rather than rebuilt.
	ui.Info("generation {gen} is the previous tree with {path} spliced in: {carried} catalogs "+
		"carried forward unchanged, {wrote} rewritten, {reused} files' content records reused "+
		"as published",
		"gen", pub.Superblock.Generation, "path", entry.Path,
		"carried", pub.Stats.CatalogsReused, "wrote", pub.Stats.Catalogs,
		"reused", pub.Stats.ReusedFiles)
	return 0
}

// reportGraftProgress is the line a person watching an hours-long walk
// sees. The owner's standing complaint about operations that go quiet for
// minutes is the reason it exists, and the reason it is on a TIMER rather
// than per object: a graft of one enormous file has no per-object event
// to hang a line on.
func reportGraftProgress(p graft.Progress) {
	done := p.BytesResumed + p.BytesHashed
	pct := 0
	if p.BytesTotal > 0 {
		pct = int(done * 100 / p.BytesTotal)
	}
	ui.Info("spidering: {done}/{total} bytes ({pct}%), {objects}/{objtotal} objects, "+
		"{blocks} blocks, {rate} bytes/s, about {eta} left",
		"done", done, "total", p.BytesTotal, "pct", pct,
		"objects", p.ObjectsDone, "objtotal", p.Objects, "blocks", p.Blocks,
		"rate", int64(p.Rate()), "eta", p.ETA().Round(time.Second))
}

// policyOf recovers the block rule a recorded graft was cut with. A
// generation written before the ladder existed carries a zero ceiling,
// which means "one global size" — exactly what it was cut with.
func policyOf(g superblock.GraftEntry) graft.BlockPolicy {
	p := graft.BlockPolicy{Block: g.Block, Max: g.BlockMax, PerObject: int(g.BlocksPerObject)}
	if p.Max == 0 {
		p.Max = p.Block
	}
	if p.PerObject == 0 {
		p.PerObject = 1 << 30 // never doubles: the pre-ladder behaviour
	}
	return p
}

// indexReadMode says whether a mount will hold this index or window it,
// which is the difference between one round trip at mount and one small
// one per distinct block read. It is a fact worth printing because it is
// the thing that changes as a graft grows.
func indexReadMode(g superblock.GraftEntry) string {
	if g.Size <= 4<<20 {
		return "whole"
	}
	return "by window"
}

// cleanGraftPath normalizes a graft mount path.
func cleanGraftPath(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return p
	}
	return p
}

// checkGraftSource applies the writer-side scheme allowlist, and says out
// loud when a source is allowed only because tests need it to be.
func checkGraftSource(source string) error {
	return checkGraftSourceScheme(source, true)
}

// checkGraftSourceQuiet is the same check with the advisory line
// suppressed, for the paths that apply it more than once in a run.
//
// `pelfs graft` opens the generation it is splicing into twice (once for
// the preflight, once for the publish) and each open builds a transport
// per graft the volume already serves, so the loud form would repeat the
// same sentence four or six times about a source the command has already
// named. The CHECK still runs every time; only the narration is dropped.
func checkGraftSourceQuiet(source string) error {
	return checkGraftSourceScheme(source, false)
}

func checkGraftSourceScheme(source string, loud bool) error {
	u, err := url.Parse(source)
	if err != nil {
		return fmt.Errorf("graft source %q is not a URL: %w", source, err)
	}
	switch u.Scheme {
	case "pelican", "osdf":
		return nil
	case "http", "https":
		// The test/dev transport (fakeorigin, plain WebDAV). Allowed
		// because the volume prefix itself may be one, so refusing it
		// would make a graft untestable without a federation — but it is
		// the case a reader-side veto exists for, and the writer says so.
		if loud {
			ui.Warn("graft source {source} is a direct HTTP prefix, not a federated one: "+
				"no director, no failover, and every reader of this volume will fetch that host "+
				"directly", "source", source)
		}
		return nil
	case "file", "":
		// Refused absolutely, and not as a policy preference. A graft is
		// part of a SHARED, signed generation; a local path resolves to a
		// different tree on every machine that mounts it, so a volume
		// carrying one is not a filesystem — it is a filesystem whose
		// contents depend on who is looking.
		return fmt.Errorf("graft source %q names a local path; a graft is published to every "+
			"reader of this volume, and a local path is a different tree on each of their machines",
			source)
	default:
		return fmt.Errorf("graft source %q uses scheme %q; grafts allow pelican:// and osdf:// "+
			"(and http(s):// for testing)", source, u.Scheme)
	}
}

// graftOpener is the READER's side of the same decision: which graft
// sources this mount is willing to open (genfs.Options.GraftOpener).
//
// It exists because the writer's allowlist protects nobody. The URL in a
// signed superblock is tamper-evident, so a reader knows the volume's
// author chose it — and that is the whole of what the signature says. The
// author may be careless, or may be someone who obtained the signing key,
// and either way the fetch happens from the READER's network position with
// the READER's credentials. A mount that could not refuse would be a
// mount that outsources its egress policy to whoever holds a key.
//
// The default here is permissive-but-visible: the same allowlist the
// writer applies, and one log line per source naming what will be
// fetched, so a reader can at least see it in a mount's output. The real
// policy knob — a `--graft` / `--no-graft` mount flag, and an allowlist
// of federations — is argued in docs/design-graft.md and is not
// implemented.
func graftOpener(o *cmdOpts) func(context.Context, string) (pelicanobj.Store, error) {
	return graftOpenerLoud(o, true)
}

// graftOpenerQuiet is the same veto without the per-source narration, for
// a command that opens a generation only to WRITE the next one and has
// already said which third parties are involved (see
// checkGraftSourceQuiet).
func graftOpenerQuiet(o *cmdOpts) func(context.Context, string) (pelicanobj.Store, error) {
	return graftOpenerLoud(o, false)
}

func graftOpenerLoud(o *cmdOpts, loud bool) func(context.Context, string) (pelicanobj.Store, error) {
	return func(ctx context.Context, source string) (pelicanobj.Store, error) {
		check := checkGraftSourceQuiet
		if loud {
			check = checkGraftSource
		}
		if err := check(source); err != nil {
			return nil, err
		}
		if loud {
			ui.Info("graft source: reads under a grafted path will fetch {source}", "source", source)
		}
		return pelicanobj.New(ctx, pelicanobj.Config{
			PrefixURL: source, TokenPath: o.token, Insecure: o.insecure,
			AcquireToken: !o.noAcquireToken,
		})
	}
}
