package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdTag freezes a branch head under a name, and lists what has been
// frozen.
//
// This is the verb every honest limit in the retention design ends with. A
// sweep can enumerate exactly two things — branch heads and tags — so the
// grace window is the whole of what an UNTAGGED older generation gets: past
// it, the refs a retired generation alone named age off the condemned
// ledger and the objects behind them are collected. A tag is the escape,
// and the only one: it puts a generation into the live set permanently, so
// nothing it names is ever a sweep candidate.
//
// It deliberately does not take the mount lease. The lease serializes
// PUBLISHERS, because two of them race for one mutable ref; a tag writes an
// object no one else writes and that refuses to be overwritten, so taking
// the lease would only mean that pinning a generation could be blocked by
// whoever happens to be writing.
func cmdTag(args []string) int {
	var branch, pubkeyHex string
	var list bool
	o, pos, err := parseArgs("tag", args, 1, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch whose head is frozen")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&list, "list", false, "list this volume's tags instead of creating one")
	})
	if err != nil {
		return exitErr(err)
	}
	switch {
	case list && len(pos) != 1:
		return exitErr(errors.New("usage: pelfs tag --list <prefix>"))
	case !list && len(pos) != 2:
		return exitErr(errors.New("usage: pelfs tag [--branch b] <prefix> <name>, or pelfs tag --list <prefix>"))
	}
	prefix := pos[0]
	ctx := context.Background()

	if list {
		return exitErr(listTags(ctx, o, prefix, pubkeyHex))
	}

	// Validate before anything is fetched: a name the key space cannot
	// carry is worth saying so about immediately, not after a round trip.
	name := pos[1]
	if err := refs.ValidateName(name); err != nil {
		return exitErr(fmt.Errorf("tag: %w", err))
	}

	_, rstore, _, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	// The head goes through the ordinary Fetch, so a tag is signed bytes
	// this client has verified: the pinned key (or TOFU's first sight of
	// it) and the rollback check both apply. Tagging a superblock that had
	// not been verified would freeze whatever the origin happened to serve.
	f, err := rstore.Fetch(ctx, branch)
	if err != nil {
		return exitErr(err)
	}
	if err := rstore.Tag(ctx, name, f.Raw); err != nil {
		return exitErr(explainTagFailure(ctx, rstore, name, err))
	}
	ui.Info("tagged generation {generation} of branch {branch} as {tag}; the sweep now retains it permanently, "+
		"and `pelfs mount --tag {tag}` reads it",
		"generation", f.Superblock.Generation, "branch", branch, "tag", name)
	return 0
}

// explainTagFailure turns the immutability refusal into advice. The bare
// error says a name is taken; what the user needs is which generation has
// it, because the two live questions ("did my earlier run already do
// this?" and "did I typo a name in use?") have different answers and the
// generation number distinguishes them.
func explainTagFailure(ctx context.Context, rstore *refs.Store, name string, err error) error {
	if !errors.Is(err, refs.ErrTagExists) {
		return err
	}
	sb, _, ferr := rstore.FetchTag(ctx, name)
	if ferr != nil {
		return fmt.Errorf("tag %s already exists and tags are immutable; choose another name", name)
	}
	return fmt.Errorf("tag %s already names generation %d and tags are immutable; choose another name "+
		"(a tag that could be moved would unpin whatever a reader — or the retention sweep — was holding through it)",
		name, sb.Generation)
}

// listTags prints the volume's tags, one per line.
//
// It lists rather than verifies. Verifying each would need a trusted key,
// which a client that has not yet fetched a branch does not have, and
// answering "what tags exist" is a question about the key space — `pelfs
// fsck --tag` is the verb that answers whether one is sound.
func listTags(ctx context.Context, o *cmdOpts, prefix, pubkeyHex string) error {
	inner, _, _, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return err
	}
	entries, err := inner.ListDir(ctx, refs.TagDirKey)
	if err != nil {
		// A volume with no tags has no tags directory: nothing has ever
		// written to it. That is an empty listing, not a failure.
		if isNotFoundErr(err) {
			fmt.Println("no tags")
			return nil
		}
		return fmt.Errorf("list %s: %w", refs.TagDirKey, err)
	}
	var names []string
	for _, e := range entries {
		// The same two exclusions the sweep applies when it enumerates
		// roots, so this listing shows exactly what is retained.
		if e.IsDir || strings.HasSuffix(e.Name, ".tmp") {
			continue
		}
		names = append(names, e.Name)
	}
	if len(names) == 0 {
		fmt.Println("no tags")
		return nil
	}
	// Listing order is the server's business; ours is to be stable, so a
	// script can diff two runs.
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}
