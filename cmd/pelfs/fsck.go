package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// cmdFsck checks one published generation: pack list, catalog and shard
// reachability, structural invariants, and chunk presence (chunk CONTENT
// only with --deep).
//
// # Exit status, which is the contract scripts actually depend on
//
//	0  nothing found, OR warnings only and no --strict
//	1  the generation is damaged; or warnings only under --strict;
//	   or the check could not be run at all
//	2  usage error (a bad flag, -h) — pelfs-wide, see exitErr
//
// A warning is not damage (internal/fsck, Severity), so a warning alone
// must not fail a run. Everything that already runs fsck reads its status
// as "0 fine, nonzero broken" — scripts/e2e-test.sh, scripts/
// unprivileged-test.sh, scripts/crash-recovery-docker.sh, scripts/
// bench-untar-nfs-docker.sh, and the hostile harness's phases D and E,
// which report a nonzero as "fsck REJECTED the generation this run
// published". A "clean but noteworthy" exit of its own would turn every
// one of those red the first time a graft source was legitimately
// republished, and the operator who learns that fsck cries wolf stops
// running fsck. So the noteworthy case reports itself in the OUTPUT, at
// status 0, and an operator who wants a warning to fail their cron job
// says --strict.
//
// --strict maps warnings onto 1 rather than onto a code of their own:
// 2 is already the pelfs-wide usage status, so a distinct code here would
// have to be 3+, inventing a contract nobody asked for and making a
// typo'd flag indistinguishable from a real finding. --strict means "a
// warning is an error", and the error status is 1.
func cmdFsck(args []string) int {
	var branch, tag, pubkeyHex, grafts string
	var deep, strict bool
	var workers int
	var fset *flag.FlagSet
	o, pos, err := parseArgs("fsck", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fset = fs
		fs.StringVar(&branch, "branch", "main", "branch to check")
		fs.StringVar(&tag, "tag", "", "check a tag instead of a branch head")
		fs.StringVar(&pubkeyHex, "volume-pubkey", "", "hex Ed25519 volume key to trust (default: pin on first use)")
		fs.BoolVar(&deep, "deep", false, "fetch and decode every chunk instead of only checking that it is present")
		fs.IntVar(&workers, "workers", 0, "concurrent fetchers for --deep (default 8)")
		fs.BoolVar(&strict, "strict", false, "fail (exit 1) on warnings too, not only on damage")
		fs.StringVar(&grafts, "grafts", "head", "how much of a graft's SOURCE to check: "+
			"none (touch no third party), head (stat every source object), "+
			"deep (re-read and re-hash every external block)")
	})
	if err != nil {
		return exitErr(err)
	}
	depth, err := fsck.ParseGraftDepth(grafts)
	if err != nil {
		return exitErr(err)
	}
	// --deep MEANS THE BYTES, in whichever layer holds them. A volume
	// that is 95% graft would otherwise answer `--deep` with "every chunk
	// fetched and verified" while having read none of the bytes anyone
	// actually stores there. Saying --grafts explicitly wins, because
	// re-reading a 10 TB tree over somebody else's network is a decision
	// worth being able to decline while still verifying the packs.
	if deep && !flagWasSet(fset, "grafts") {
		depth = fsck.GraftDeep
	}
	prefix := pos[0]
	ctx := context.Background()

	inner, rstore, stateDir, err := volumeStore(ctx, o, prefix, pubkeyHex)
	if err != nil {
		return exitErr(err)
	}
	// The superblock is the integrity root: fsck checks what it signs, so
	// it must be verified before anything below it means anything.
	var sb *superblock.Superblock
	if tag != "" {
		if sb, _, err = rstore.FetchTag(ctx, tag); err != nil {
			return exitErr(err)
		}
	} else {
		f, err := rstore.Fetch(ctx, branch)
		if err != nil {
			return exitErr(err)
		}
		sb = f.Superblock
	}

	var dek []byte
	if o.encryptKeyPath != "" {
		kek, err := superblock.LoadRSAPrivateKeyFile(o.encryptKeyPath, keyPassphrase())
		if err != nil {
			return exitErr(fmt.Errorf("load --encrypt-key: %w", err))
		}
		for _, ke := range sb.KeyTable {
			if ke.Kind != superblock.KeyKindDEK {
				continue
			}
			if dek, err = superblock.UnwrapKey(kek, ke.Wrapped); err != nil {
				return exitErr(fmt.Errorf("unwrap key %d: %w", ke.ID, err))
			}
		}
	}

	rep, cerr := fsck.Check(ctx, fsck.Options{
		Inner:    inner,
		SB:       sb,
		DEK:      dek,
		CacheDir: filepath.Join(stateDir, "gencache"),
		Deep:     deep,
		Workers:  workers,
		// The same reader's veto a mount applies (genfs.Options.
		// GraftOpener): fsck is a reader too, and a check that fetched
		// from a source the mount would refuse would be checking
		// something nobody will ever read. Quiet, because the report
		// names every graft and its source itself.
		GraftOpener: graftOpenerQuiet(o),
		GraftDepth:  depth,
	})
	if rep != nil {
		printFsckReport(os.Stdout, sb.Generation, deep, rep)
	}
	if cerr != nil {
		return exitErr(cerr)
	}
	if rep.Damaged() {
		ui.Error("generation {generation} is damaged: {problems}",
			"generation", sb.Generation, "problems", ui.Count(rep.Errors(), "problem"))
		// Never let the damage bury the warnings: a reader who acts on
		// the error line alone must still be told the rest is there.
		if n := rep.Warnings(); n > 0 {
			ui.Warn("and {warnings} above are not damage, but are worth reading",
				"warnings", ui.Count(n, "warning"))
		}
		return fsckExit(rep, strict)
	}
	fmt.Println(fsckSummary(rep, strict))
	if rep.Warnings() > 0 && strict {
		ui.Error("--strict: {warnings} on a generation that is otherwise consistent",
			"warnings", ui.Count(rep.Warnings(), "warning"))
	}
	return fsckExit(rep, strict)
}

// fsckExit is the exit status of a completed check. See cmdFsck's comment
// for why a warning is not, by itself, a failure.
func fsckExit(rep *fsck.Report, strict bool) int {
	switch {
	case rep.Damaged():
		return 1
	case strict && rep.Warnings() > 0:
		return 1
	default:
		return 0
	}
}

// fsckSummary is the last line of an undamaged run.
//
// It keeps the literal words "generation is consistent" in every case,
// because that phrase IS the contract for the greps that check it
// (scripts/e2e-test.sh, scripts/unprivileged-test.sh, the hostile
// harness) and because on a warning-only volume it is simply true — the
// warnings are not damage. What it must not do is stop there and let a
// reader take "consistent" for "nothing to see", so the count of
// warnings is in the same sentence, and every one of them is listed
// above with the word "warning" in front of it.
func fsckSummary(rep *fsck.Report, strict bool) string {
	n := rep.Warnings()
	switch {
	case n == 0:
		return "generation is consistent"
	case strict:
		return fmt.Sprintf("generation is consistent, but %s: failing on --strict",
			ui.Count(n, "warning"))
	default:
		return fmt.Sprintf("generation is consistent, with %s to read above (not damage)",
			ui.Count(n, "warning"))
	}
}

// printFsckReport writes the counts and then every finding, each line led
// by its severity so that a line lifted out of the report by a grep still
// says whether it is damage.
func printFsckReport(w io.Writer, gen uint64, deep bool, rep *fsck.Report) {
	fmt.Fprintf(w, "generation %d\n", gen)
	fmt.Fprintf(w, "  objects: %d packs, %d catalogs, %d inode shards\n", rep.Packs, rep.Catalogs, rep.Shards)
	fmt.Fprintf(w, "  tree:    %d dirs, %d files (%d inline), %d symlinks, %d logical bytes\n",
		rep.Dirs, rep.Files, rep.InlineFiles, rep.Symlinks, rep.Bytes)
	if deep {
		fmt.Fprintf(w, "  data:    %d chunks referenced, %d fetched and verified\n", rep.Chunks, rep.ChunksVerified)
	} else {
		fmt.Fprintf(w, "  data:    %d chunks referenced, presence only (--deep verifies content)\n", rep.Chunks)
	}
	if rep.Grafts > 0 {
		fmt.Fprintf(w, "  grafts:  %s serving %s from %s\n",
			ui.Count(rep.Grafts, "root"), ui.Count(rep.GraftChunks, "external chunk"),
			ui.Count(rep.GraftObjects, "source object"))
		fmt.Fprintf(w, "  source:  %s\n", graftClaim(rep))
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(w, "  %s: %s: %s: %s\n", p.Severity, p.Kind, p.Path, p.Detail)
	}
}

// flagWasSet reports whether the user typed a flag, as opposed to
// inheriting its default. Go's flag package only answers this after Parse
// and only through Visit, which walks the flags that were SET.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	if fs == nil {
		return false
	}
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// graftClaim is the sentence that keeps the two graft depths from looking
// like the same check.
//
// It exists because "checked" is the word both would otherwise print, and
// the gap between them is four orders of magnitude: one stats a hundred
// thousand small objects and reads no data at all, the other re-reads and
// re-hashes ten terabytes over somebody else's network. A report that
// said "grafts: OK" for either would be inviting a reader to believe the
// expensive claim after paying for the cheap one, so each mode states
// exactly what it did and, for the cheap one, what it cannot see.
func graftClaim(rep *fsck.Report) string {
	switch rep.GraftDepth {
	case fsck.GraftNone:
		return "not checked — no source was contacted (--grafts=head stats each source object)"
	case fsck.GraftDeep:
		return fmt.Sprintf("%s re-read from the source and re-hashed (%d bytes), %s stat'd",
			ui.Count(rep.GraftBlocksVerified, "external block"),
			rep.GraftBytesVerified, ui.Count(rep.GraftObjectsChecked, "source object"))
	default:
		return fmt.Sprintf("%s stat'd by HEAD — size and mtime, no source bytes read; "+
			"a same-length edit is invisible to this mode (--grafts=deep re-hashes every block)",
			ui.Count(rep.GraftObjectsChecked, "source object"))
	}
}
