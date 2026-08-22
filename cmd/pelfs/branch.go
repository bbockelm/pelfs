package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"time"

	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdBranch makes a volume hold more than one line of history, lists them,
// and removes one.
//
// UNTIL THIS EXISTED THE `--branch` FLAG WAS A PROMISE NOTHING KEPT. Every
// command takes one — mount, shell, tag, fsck, repack, repack-plan — and
// `pelfs init` writes "main", so the only value any of them could be given
// was the one branch the volume had. The retention design has always
// described its root set as "every branch head", and the sweep has always
// enumerated refs/ as though there could be several; there could not.
//
// WHAT A BRANCH IS HERE. refs/<name> holds a signed superblock, and
// nothing in it names a branch — a generation is a document, and a branch
// is a NAME POINTING AT ONE. So creating a branch is copying the bytes of
// a head under a second name, and from that instant the two names advance
// independently: each seal reads the head of the branch it publishes onto
// and flips that one ref.
//
// The bytes are the VERIFIED ones. Creation fetches the source through the
// ordinary path (refs.Store.Fetch: the pinned key or TOFU, plus the
// rollback check), never a raw read, so a branch is never rooted in
// whatever the origin happened to serve. That matters more here than for a
// tag: a tag freezes a generation, and a branch is something a writer will
// build on.
//
// CREATE-IF-ABSENT, and the refusal is the feature. Flip with an empty
// expect-ETag refuses a ref that already exists, so `pelfs branch` cannot
// move a branch someone is writing on — which would strand their next
// publish and silently reparent their work. Moving a branch is what
// publishing does, and it goes through the CAS guard.
//
// THE WRITE LEASE IS PER BRANCH, stated here because a user meets the
// question here first: the advisory lease is meta/lease-<branch>.json
// (internal/lease), so two writable mounts on DIFFERENT branches of one
// volume run concurrently and only a second writer on the SAME branch is
// refused. v0.1.0 had one object for the whole volume and excluded both;
// that was a limit, not a design position, and it is gone.
//
// The exception is a v0.1.0 CLIENT still on the federation. It holds
// meta/lease.json, which says nothing about which branch it is writing, so
// it excludes every branch — and it cannot see a v0.2 writer at all. The
// mixed-version rule is in the internal/lease package comment and in the
// README; the seal's refusal to publish over a moved ref is what actually
// keeps that case safe, as it always was.
func cmdBranch(args []string) int {
	var from, fromTag, pubkeyHex, signingKey string
	var list, rm bool
	o, pos, err := parseArgs("branch", args, 1, 2, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.StringVar(&from, "from", "main", "branch whose current head the new branch starts at")
		fs.StringVar(&signingKey, "signing-key", "", signingKeyUsage)
		fs.StringVar(&fromTag, "from-tag", "", "start the new branch at a tagged generation instead of a branch head")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&list, "list", false, "list this volume's branches instead of creating one")
		fs.BoolVar(&rm, "rm", false, "delete a branch instead of creating one; the next gc reclaims what it alone named")
	})
	if err != nil {
		return exitErr(err)
	}
	switch {
	case list && rm:
		return exitErr(errors.New("--list and --rm do different things; pick one"))
	case list && len(pos) != 1:
		return exitErr(errors.New("usage: pelfs branch --list <prefix>"))
	case !list && len(pos) != 2:
		return exitErr(errors.New("usage: pelfs branch [--from b | --from-tag t] <prefix> <name>, " +
			"pelfs branch --rm <prefix> <name>, or pelfs branch --list <prefix>"))
	case fromTag != "" && (list || rm):
		return exitErr(errors.New("--from-tag only applies when creating a branch"))
	}
	prefix := pos[0]
	ctx := context.Background()

	if list {
		return exitErr(listBranches(ctx, o, prefix, pubkeyHex))
	}
	if rm {
		return exitErr(removeBranch(ctx, o, prefix, pos[1], pubkeyHex))
	}
	return exitErr(createBranch(ctx, o, prefix, pos[1], from, fromTag, pubkeyHex, signingKey))
}

// createBranch writes the verified source head under a second name.
func createBranch(ctx context.Context, o *cmdOpts, prefix, name, from, fromTag, pubkeyHex, signingKeyPath string) error {
	// Validated before anything is fetched, for the reason `pelfs tag` does
	// it: a name the key space cannot carry is worth saying so about
	// immediately, not after a round trip. The `.tmp` rule is the one that
	// is not cosmetic — every listing of refs/ skips such a name, so the
	// branch would mount and be invisible to the sweep that is supposed to
	// keep it alive.
	if err := refs.ValidateName(name); err != nil {
		return fmt.Errorf("branch: %w", err)
	}
	inner, rstore, stateDir, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return err
	}

	// The source, through the trust path in both cases. A tag is a frozen
	// generation of some branch, so branching from one is how a release
	// gets a maintenance line without the trunk having to still be there.
	var (
		sb     *superblock.Superblock
		raw    []byte
		source string
	)
	if fromTag != "" {
		if sb, raw, err = rstore.FetchTag(ctx, fromTag); err != nil {
			return err
		}
		source = fmt.Sprintf("tag %s", fromTag)
	} else {
		f, ferr := rstore.Fetch(ctx, from)
		if ferr != nil {
			return ferr
		}
		sb, raw, source = f.Superblock, f.Raw, fmt.Sprintf("branch %s", from)
	}

	// The branch's first generation records WHERE IT CAME FROM and takes
	// its own slice of the inode space (superblock.Fork).
	//
	// This used to copy the source's bytes verbatim, which was elegant —
	// no key needed, trust preserved exactly — and left the branch unable
	// to say anything about itself. Two things depend on it being able to.
	// A merge needs the generation the branches diverged from, and nothing
	// else in the format can supply one: refs and tags are the only
	// addressable entry points, so PrevHash chains cannot be walked back
	// to where they meet. And two branches allocating inodes from one
	// counter assign the same number to different files, which makes
	// merging them a renumbering of a whole side rather than a merge.
	//
	// The cost is a signature, so this verb now needs the volume key. That
	// is no real loss: creating a ref is a write, and publishing onto the
	// branch afterwards needs the key anyway — a branch nobody can seal
	// onto is not a branch.
	//
	// No new content: the generation names the same root, the same
	// catalogs, the same packs. It is a superblock and nothing else.
	key, err := loadOrCreateSigningKey(signingKeyFileIn(stateDir, signingKeyPath), sb)
	if err != nil {
		return err
	}
	lineage, err := pickLineage(ctx, inner, rstore)
	if err != nil {
		return err
	}
	forkRaw, fork, err := forkGeneration(sb, raw, from, fromTag, lineage, key)
	if err != nil {
		return err
	}

	// Empty expect-ETag: create-if-absent. refs.Flip refuses a ref that is
	// already there, which is what keeps this verb from repointing a branch
	// somebody is publishing onto.
	if err := rstore.Flip(ctx, name, forkRaw, ""); err != nil {
		return explainBranchFailure(ctx, rstore, name, err)
	}
	ui.Info("created branch {branch} at generation {generation} of {source}; "+
		"`pelfs mount --branch {branch} --rw` publishes onto it, and it advances independently of {source}",
		"branch", name, "generation", fork.Generation, "source", source)
	ui.Info("it allocates inodes from lineage {lineage} (first {first}), so it can be merged back without "+
		"renumbering, and it records {base} as the point it was cut from",
		"lineage", fork.Fork.Lineage, "first", fork.NextInode, "base", fmt.Sprintf("generation %d", sb.Generation))
	// It used to warn here that the two branches shared one lease. They no
	// longer do, and the replacement is INFORMATION rather than a warning:
	// a user who has just been handed a second branch should be told what
	// concurrency it buys, in the same breath, rather than discovering it
	// by trying.
	ui.Info("the write lease is per branch ({key}), so a writable mount of {branch} runs alongside a writable "+
		"mount of {source} — only a second writer on the SAME branch is refused",
		"key", leaseKeyFor(name), "branch", name, "source", source)
	return nil
}

// removeBranch deletes a branch, having first refused the one deletion
// that cannot be undone.
//
// THE REFUSAL THAT MATTERS is the last branch. Every other object in a
// volume is reachable from a ref: `pelfs branch` starts from a branch head
// or a tag, `pelfs mount` opens a branch head or a tag, and the retention
// sweep refuses outright to run on a volume with no refs at all ("refusing
// to treat every pack as garbage"). So a volume whose last branch is gone
// has no head to mount, nothing for a new branch to start FROM unless a tag
// happens to exist, and no CLI path back — the packs are all still there
// and nothing can name them. That is not a deletion, it is destroying the
// volume with a verb whose name says otherwise.
//
// EVERYTHING ELSE IS ALLOWED, INCLUDING `main`. It is tempting to refuse
// that one too, since every command's --branch defaults to it, but the
// refusal would be about a default rather than about the volume: a project
// that renames its trunk has done nothing wrong, and a tool that will not
// let go of a name it chose is a tool with an opinion instead of a rule.
// What is owed instead is loudness — the generation being let go, and that
// every command will now need --branch.
func removeBranch(ctx context.Context, o *cmdOpts, prefix, name, pubkeyHex string) error {
	if err := refs.ValidateName(name); err != nil {
		return fmt.Errorf("branch --rm: %w", err)
	}
	_, rstore, _, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return err
	}
	names, err := rstore.ListBranches(ctx)
	if err != nil {
		return err
	}
	present := false
	for _, b := range names {
		if b == name {
			present = true
		}
	}
	if present && len(names) == 1 {
		return fmt.Errorf("refusing to delete branch %s: it is this volume's only branch, and a volume with "+
			"no branch has no head to mount, nothing for a new branch to start from, and no way back from the "+
			"CLI — the packs would still be there with nothing able to name them. Create another branch first "+
			"(`pelfs branch %s <other>`), or remove the whole prefix if that is what you meant", name, prefix)
	}

	// Best effort, and deliberately not fatal, exactly as for a tag: a
	// branch head whose signature no longer verifies — one a rotated or
	// compromised key left behind — is among the ones most worth removing,
	// so an unverifiable head is reported without a generation rather than
	// made undeletable.
	gen, known := "", false
	if f, ferr := rstore.Fetch(ctx, name); ferr == nil {
		gen, known = fmt.Sprintf("%d", f.Superblock.Generation), true
	}
	if err := rstore.DeleteBranch(ctx, name); err != nil {
		if errors.Is(err, refs.ErrNoSuchBranch) {
			return fmt.Errorf("no branch named %s on this volume (`pelfs branch --list %s` shows what is there)",
				name, prefix)
		}
		return err
	}
	if known {
		ui.Info("deleted branch {branch}, which named generation {generation}; that generation is no longer a "+
			"retention root — whatever it alone named is reclaimed by the next `pelfs gc` after the grace "+
			"window, and anything a surviving branch or tag still names is untouched",
			"branch", name, "generation", gen)
	} else {
		ui.Info("deleted branch {branch} (its superblock does not verify, so the generation it named cannot be "+
			"named here); whatever it alone named is reclaimed by the next `pelfs gc` after the grace window",
			"branch", name)
	}
	if name == "main" {
		ui.Warn("main is gone: every command's --branch defaults to it, so mount, tag, fsck and repack now "+
			"need --branch naming one of {remaining}", "remaining", remaining(names, name))
	}
	return nil
}

// remaining renders the branches left after one is removed, for the
// warning that has to tell a user what to type instead.
func remaining(names []string, gone string) string {
	var out []string
	for _, n := range names {
		if n != gone {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return "(none)"
	}
	return joinNames(out)
}

func joinNames(names []string) string {
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}

// explainBranchFailure turns the create-if-absent refusal into advice. The
// bare error says a ref already exists; what a user needs is which
// generation it names, because "my earlier run already did this" and "I
// typed a name that is in use" have different answers and the generation
// number is what tells them apart.
func explainBranchFailure(ctx context.Context, rstore *refs.Store, name string, err error) error {
	if !errors.Is(err, refs.ErrStaleFlip) {
		return err
	}
	f, ferr := rstore.Fetch(ctx, name)
	if ferr != nil {
		return fmt.Errorf("branch %s already exists; a branch is created, never moved — publish onto it, "+
			"or pick another name", name)
	}
	return fmt.Errorf("branch %s already names generation %d; a branch is created, never moved — publish onto "+
		"it (`pelfs mount --branch %s --rw`), or pick another name (moving a ref out from under a writer would "+
		"strand its next publish and reparent its work)", name, f.Superblock.Generation, name)
}

// listBranches prints the volume's branches, one per line.
//
// Like `pelfs tag --list` it lists rather than verifies: answering "what
// branches exist" is a question about the key space, and `pelfs fsck
// --branch` is the verb that answers whether one is sound.
func listBranches(ctx context.Context, o *cmdOpts, prefix, pubkeyHex string) error {
	_, rstore, _, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return err
	}
	names, err := rstore.ListBranches(ctx)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		// A prefix with no refs directory holds no volume. Reported rather
		// than printed as an empty list, because "no branches" is the one
		// answer that cannot be true of a volume that exists.
		fmt.Println("no branches (this prefix holds no pelfs volume)")
		return nil
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

// forkGeneration builds the branch's first generation: the source's tree
// exactly, plus a record of where it came from and its own inode lineage.
//
// Nothing about the namespace changes — same root catalog, same catalog
// list, same shards, same packs — so this writes no content and reads
// none. What it changes is the three things that make the branch a branch:
// its parent, its fork record, and where it allocates inodes.
func forkGeneration(src *superblock.Superblock, srcRaw []byte, from, fromTag string,
	lineage uint32, key ed25519.PrivateKey) ([]byte, *superblock.Superblock, error) {

	sb := *src
	sb.Generation = src.Generation + 1
	sb.CreatedUnixNano = time.Now().UnixNano()
	sb.PrevHash = superblock.Hash(srcRaw)
	sb.Signature = [64]byte{}
	source := from
	if fromTag != "" {
		source = "tags/" + fromTag
	}
	sb.Fork = &superblock.Fork{
		Base:           superblock.Hash(srcRaw),
		BaseGeneration: src.Generation,
		BaseNextInode:  src.NextInode,
		From:           source,
		Lineage:        lineage,
	}
	// The branch allocates from its own slice from here on. Everything
	// already in the tree keeps the number it has: those inodes mean the
	// same file on both sides of the fork, which is exactly what makes
	// them safe to share.
	sb.NextInode = superblock.FirstInode(lineage)
	if err := sb.Sign(key); err != nil {
		return nil, nil, err
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, err
	}
	return raw, &sb, nil
}

// pickLineage draws an inode-space partition no ref in this volume is
// already using.
//
// Drawn at random rather than counted up, because a counter would have to
// live somewhere both branches can see and be incremented under a lock
// neither holds. Random plus a collision check needs no coordination, and
// it avoids the trap a name-derived value would set: a branch deleted and
// re-created would get its predecessor's slice back, and start handing
// out numbers that generations reachable from a tag are still using.
//
// The check reads every branch head and every tag, which is every
// generation this volume can still name. It is not exhaustive — a retired
// generation nobody names could hold a lineage this misses — but such a
// generation cannot be branched from or merged, so it cannot collide with
// anything either.
func pickLineage(ctx context.Context, inner pelicanobj.Store, rstore *refs.Store) (uint32, error) {
	taken := map[uint32]bool{0: true} // 0 is the original lineage
	branches, err := listRefNames(ctx, inner, refs.RefDirKey)
	if err != nil {
		return 0, err
	}
	for _, b := range branches {
		f, err := rstore.Fetch(ctx, b)
		if err != nil {
			// An unreadable ref cannot be branched from, but it can still
			// be holding a lineage. Failing closed: a lineage collision is
			// silent, and this is the only place that can prevent one.
			return 0, fmt.Errorf("cannot check branch %s for its inode lineage: %w", b, err)
		}
		taken[lineageOf(f.Superblock)] = true
	}
	tags, err := listRefNames(ctx, inner, refs.TagDirKey)
	if err != nil {
		return 0, err
	}
	for _, t := range tags {
		sb, _, err := rstore.FetchTag(ctx, t)
		if err != nil {
			return 0, fmt.Errorf("cannot check tag %s for its inode lineage: %w", t, err)
		}
		taken[lineageOf(sb)] = true
	}
	// 24 bits, so a draw collides with a hundred taken lineages about once
	// in 170,000 tries; the loop is here for correctness, not for luck.
	for range 1000 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		l := binary.BigEndian.Uint32(b[:]) & 0xffffff
		if l != 0 && !taken[l] {
			return l, nil
		}
	}
	return 0, errors.New("could not find an unused inode lineage after 1000 draws")
}

// lineageOf is the lineage a generation allocates from: its fork record's,
// or the original.
func lineageOf(sb *superblock.Superblock) uint32 {
	if sb.Fork != nil {
		return sb.Fork.Lineage
	}
	return 0
}
