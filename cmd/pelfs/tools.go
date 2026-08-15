package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/bbockelm/pelfs/internal/offline"
)

// toolSession prepares an offline session: metadata comes from --state-dir
// when it already holds a meta.db, otherwise the newest snapshot is restored
// into a temp dir.
func toolSession(ctx context.Context, o *cmdOpts, prefix string, needWrite bool) (*session, error) {
	s, err := newSession(ctx, o, prefix, needWrite)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.metaPath); err != nil {
		s.cleanupTemp()
		return nil, errors.New("no volume metadata available: the prefix has no snapshot yet and --state-dir holds no meta.db")
	}
	return s, nil
}

// cmdRepack reclaims federation space held by dead entries inside sealed
// packs: live entries of sparse packs are rewritten into new packs and the
// old packs deleted whole. Runs under the volume lease (write session).
func cmdRepack(args []string) int {
	o, pos, err := parseArgs("repack", args, 1, 1, nil)
	if err != nil {
		return exitErr(err)
	}
	// The pack store's write side is normally gated on --writeback; a
	// repack session writes packs by definition.
	o.writeback = true
	o.noPack = false
	ctx := context.Background()
	s, err := toolSession(ctx, o, pos[0], true)
	if err != nil {
		return exitErr(err)
	}
	defer s.cleanupTemp()

	before := s.packs.Garbage()
	fmt.Fprintf(os.Stderr, "pelfs: %d bytes of dead pack data before repack\n", before)
	if err := s.packs.RepackAll(ctx); err != nil {
		return exitErr(err)
	}
	fmt.Printf("repack reclaimed %d bytes (%d remaining)\n", before-s.packs.Garbage(), s.packs.Garbage())
	return 0
}

func cmdGC(args []string) int {
	o, pos, err := parseArgs("gc", args, 1, 1, func(fs *flag.FlagSet, o *cmdOpts) {
		fs.BoolVar(&o.gcDelete, "delete", false, "delete leaked objects (default: report only)")
	})
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	s, err := toolSession(ctx, o, pos[0], o.gcDelete)
	if err != nil {
		return exitErr(err)
	}
	defer s.cleanupTemp()

	fmt.Fprintln(os.Stderr, "pelfs: scanning for leaked block objects (blocks newer than 1h are skipped; do not trust results while a mount is active elsewhere)")
	rep, err := offline.GC(ctx, offline.Options{
		MetaPath: s.metaPath,
		Blob:     s.data,
		Delete:   o.gcDelete,
	})
	if err != nil {
		return exitErr(err)
	}
	fmt.Printf("slices in metadata: %d\nobjects scanned:    %d\n  valid:            %d\n  skipped (new):    %d\n  leaked:           %d (%d bytes)\n",
		rep.UsedSlices, rep.Scanned, rep.Valid, rep.Skipped, rep.Leaked, rep.LeakedBytes)
	if o.gcDelete {
		fmt.Printf("  deleted:          %d\n", rep.Deleted)
	} else if rep.Leaked > 0 {
		fmt.Println("re-run with --delete to remove leaked objects")
	}
	return 0
}

func cmdFsck(args []string) int {
	o, pos, err := parseArgs("fsck", args, 1, 1, nil)
	if err != nil {
		return exitErr(err)
	}
	ctx := context.Background()
	s, err := toolSession(ctx, o, pos[0], false)
	if err != nil {
		return exitErr(err)
	}
	defer s.cleanupTemp()

	rep, err := offline.Fsck(ctx, offline.Options{MetaPath: s.metaPath, Blob: s.data})
	if err != nil {
		return exitErr(err)
	}
	fmt.Printf("slices: %d\nblocks: %d\nmissing: %d\n", rep.Slices, rep.Blocks, rep.Missing)
	for _, k := range rep.MissingKeys {
		fmt.Printf("  missing: %s\n", k)
	}
	if rep.Missing > 0 {
		fmt.Fprintln(os.Stderr, "pelfs: volume is damaged: some referenced blocks are gone from the federation")
		return 1
	}
	fmt.Println("volume is consistent")
	return 0
}
