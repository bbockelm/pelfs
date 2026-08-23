package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// `pelfs graft <volume> <path> <source>` — SPIKE.
//
// Spiders a foreign Pelican prefix, records a fixed-size block digest for
// every byte of it, and publishes a generation that serves the tree at
// <path> with no copy of the data under the volume's own prefix.
//
// What is proven and what is not is in docs/design-graft.md. The two
// limits a user would hit first: the graft replaces the tree rather than
// being spliced into it (so this is `pelfs init` then `pelfs graft`, not
// a graft into a populated volume), and `--refresh`, `--remove` and
// `--list` are argued in the doc but not implemented here.

func cmdGraft(args []string) int {
	var (
		pubkeyHex string
		block     int64
		branch    string
		list      bool
	)
	o, pos, err := parseArgs("graft", args, 1, 3, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.Int64Var(&block, "block", graft.DefaultBlock, "fixed block size the spider cuts and digests at")
		fs.StringVar(&branch, "branch", "main", "branch to seal onto")
		fs.BoolVar(&list, "list", false, "report the grafts this volume serves and exit")
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
			ui.Info("{path} <- {source} ({blocks} blocks of {block}, {bytes} bytes)",
				"path", g.Path, "source", g.Source,
				"blocks", g.Blocks, "block", g.Block, "bytes", g.Bytes)
		}
		return 0
	}

	if len(pos) != 3 {
		return exitErr(fmt.Errorf("usage: pelfs graft <volume> <path> <source-url>"))
	}
	mountPath, source := pos[1], pos[2]

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
	if err := checkGraftSource(source); err != nil {
		return exitErr(err)
	}

	src, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL: source, TokenPath: o.token, Insecure: o.insecure,
		AcquireToken: !o.noAcquireToken,
	})
	if err != nil {
		return exitErr(fmt.Errorf("open graft source %s: %w", source, err))
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

	start := time.Now()
	ui.Info("spidering {source}", "source", source)
	res, err := graft.Spider(ctx, graft.SpiderOptions{Src: src, Block: block})
	if err != nil {
		return exitErr(err)
	}
	if len(res.Files) == 0 {
		return exitErr(fmt.Errorf("graft source %s holds no objects", source))
	}
	spidered := time.Since(start)

	entry, err := graft.Put(ctx, inner, cleanGraftPath(mountPath), source, res.Index, res.Bytes)
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
	signingKey, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, ""), nil)
	if err != nil {
		return exitErr(err)
	}
	// The parent's grafts plus this one. Options.Grafts REPLACES the list,
	// so it has to be stated whole — carrying the parent's forward is what
	// keeps a second graft from deleting the first.
	grafts := append([]superblock.GraftEntry(nil), head.Superblock.Grafts...)
	replaced := false
	for i := range grafts {
		if grafts[i].Path == entry.Path {
			grafts[i] = entry
			replaced = true
		}
	}
	if !replaced {
		grafts = append(grafts, entry)
	}
	if _, err := publish.Publish(ctx, publish.Options{
		Source:     gsrc,
		Inner:      inner,
		SpoolDir:   stateDir,
		Branch:     branch,
		SigningKey: signingKey,
		Prev:       head.Superblock,
		PrevRaw:    head.Raw,
		Grafts:     grafts,
	}); err != nil {
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
	ui.Info("{blocks} blocks of {block} bytes digested in {spidered}; index is {index} bytes",
		"blocks", entry.Blocks, "block", entry.Block,
		"spidered", spidered.Round(time.Millisecond), "index", entry.Size)
	// The honest sentence about what was just published, said at the one
	// moment the person doing it is paying attention: the volume now
	// depends on somebody else's storage staying exactly as it is.
	ui.Info("this volume now depends on {source}; a change there fails reads under {path} "+
		"rather than serving wrong bytes", "source", source, "path", entry.Path)
	return 0
}

// cleanGraftPath normalizes a graft mount path.
func cleanGraftPath(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return p
	}
	return p
}

// checkGraftSource applies the writer-side scheme allowlist.
func checkGraftSource(source string) error {
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
		ui.Warn("graft source {source} is a direct HTTP prefix, not a federated one: "+
			"no director, no failover, and every reader of this volume will fetch that host "+
			"directly", "source", source)
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
	return func(ctx context.Context, source string) (pelicanobj.Store, error) {
		if err := checkGraftSource(source); err != nil {
			return nil, err
		}
		ui.Info("graft source: reads under a grafted path will fetch {source}", "source", source)
		return pelicanobj.New(ctx, pelicanobj.Config{
			PrefixURL: source, TokenPath: o.token, Insecure: o.insecure,
			AcquireToken: !o.noAcquireToken,
		})
	}
}
