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
// sweep enumerates a branch head, the last Params.RetainK generations
// behind it (internal/retention/lastk.go), and every tag — so past the
// grace window, and past the retain window, an UNTAGGED older generation
// loses the refs it alone named and the objects behind them are collected.
// A tag is the escape from BOTH windows: it puts a generation into the
// live set outright, so nothing it names is a sweep candidate while the
// tag is there.
//
// The pin is not permanent, and that is `--rm`: deleting a tag takes its
// generation back out of the root set, after which the next sweep reclaims
// whatever it alone was holding. Immutability is about the OBJECT — a name
// in use never silently moves to another generation — not about the name,
// which is free again once nothing is under it.
//
// It deliberately does not take the mount lease. The lease serializes
// PUBLISHERS, because two of them race for one mutable ref; a tag writes an
// object no one else writes and that refuses to be overwritten, so taking
// the lease would only mean that pinning a generation could be blocked by
// whoever happens to be writing.
func cmdTag(args []string) int {
	var branch, pubkeyHex string
	var list, rm bool
	o, pos, err := parseArgs("tag", args, 1, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&branch, "branch", "main", "branch whose head is frozen")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&list, "list", false, "list this volume's tags instead of creating one")
		fs.BoolVar(&rm, "rm", false, "delete a tag instead of creating one; the next gc reclaims what it pinned")
	})
	if err != nil {
		return exitErr(err)
	}
	switch {
	case list && rm:
		return exitErr(errors.New("--list and --rm do different things; pick one"))
	case list && len(pos) != 1:
		return exitErr(errors.New("usage: pelfs tag --list <prefix>"))
	case !list && len(pos) != 2:
		return exitErr(errors.New("usage: pelfs tag [--branch b] <prefix> <name>, " +
			"pelfs tag --rm <prefix> <name>, or pelfs tag --list <prefix>"))
	}
	prefix := pos[0]
	ctx := context.Background()

	if list {
		return exitErr(listTags(ctx, o, prefix, pubkeyHex))
	}
	if rm {
		return exitErr(removeTag(ctx, o, prefix, pos[1], pubkeyHex))
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
	ui.Info("tagged generation {generation} of branch {branch} as {tag}; the sweep retains it until the tag "+
		"is deleted (`pelfs tag --rm`), and `pelfs mount --tag {tag}` reads it",
		"generation", f.Superblock.Generation, "branch", branch, "tag", name)
	return 0
}

// removeTag deletes a tag, and says what that did and did not do.
//
// THIS IS THE OTHER HALF OF THE PIN. Creating one is what a workflow does
// when it needs a generation to outlive the grace window; without a way to
// undo it, "tag it" meant "hold these packs forever", and the retention
// design's escape hatch was a one-way door. Deleting the object is what
// finally lets the space go.
//
// It reports the generation, and that is the part worth building rather
// than assuming. A tag name is a label a human chose; what it PINS is a
// generation number, and the two questions a user has at this moment
// ("is this the release I meant to retire?" and "how much am I about to
// let go of?") are both about the number. So the tag is fetched and
// verified BEFORE it is removed — not to authorize the removal, which
// needs no signature (refs.Store.DeleteTag says why), but so the
// confirmation can name what was there.
//
// And it says out loud that nothing has been reclaimed yet. Deletion takes
// the generation out of the sweep's root set; the objects go on the next
// `pelfs gc`, subject to the same age guard as everything else. A user who
// deletes a tag, checks the volume's size and sees no change has either
// been told this or has been handed a mystery.
func removeTag(ctx context.Context, o *cmdOpts, prefix, name, pubkeyHex string) error {
	if err := refs.ValidateName(name); err != nil {
		return fmt.Errorf("tag --rm: %w", err)
	}
	_, rstore, _, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return err
	}
	// Best effort, and deliberately not fatal: a tag whose signature no
	// longer verifies — one a rotated or compromised key left behind — is
	// among the ones most worth removing, so an unverifiable tag is
	// reported without a generation rather than made undeletable.
	gen, known := "", false
	if sb, _, ferr := rstore.FetchTag(ctx, name); ferr == nil {
		gen, known = fmt.Sprintf("%d", sb.Generation), true
	}
	if err := rstore.DeleteTag(ctx, name); err != nil {
		if errors.Is(err, refs.ErrNoSuchTag) {
			return fmt.Errorf("no tag named %s on this volume (`pelfs tag --list %s` shows what is pinned)",
				name, prefix)
		}
		return err
	}
	if known {
		ui.Info("deleted tag {tag}, which pinned generation {generation}; that generation is no longer a "+
			"retention root — space is reclaimed by the next `pelfs gc` after the grace window",
			"tag", name, "generation", gen)
	} else {
		ui.Info("deleted tag {tag} (its superblock does not verify, so the generation it pinned cannot be "+
			"named); space is reclaimed by the next `pelfs gc` after the grace window", "tag", name)
	}
	return nil
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
