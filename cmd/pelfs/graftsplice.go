package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The half of `pelfs graft` that is about THIS volume rather than about
// the source: what is at the graft path, what happens to it, and the
// removal that has no walk at all.
//
// The splice itself is internal/publish/graftsplice.go; this is the
// command's side of it — the preflight before the walk, the report a
// person reads, and `--remove`.

// graftPlan is the preflight's answer, plus the generation it was made
// against so that a branch which moved during the walk can be noticed.
type graftPlan struct {
	*publish.GraftPlan
	generation uint64
}

// openGraftBase opens the generation a splice is built on.
//
// The GraftOpener is the same reader's veto a mount applies, and it is
// needed here for a reason that is easy to miss: a volume that ALREADY
// serves a graft cannot be read at all without one (genfs.openGrafts is
// fatal by design), and reading it is exactly what adding a second graft
// requires.
func openGraftBase(ctx context.Context, o *cmdOpts, inner pelicanobj.Store, stateDir string,
	sb *superblock.Superblock) (*genfs.FS, error) {

	fs, err := genfs.Open(ctx, genfs.Options{
		Inner:       inner,
		SB:          sb,
		CacheDir:    filepath.Join(stateDir, "gencache"),
		GraftOpener: graftOpenerQuiet(o),
	})
	if err != nil {
		return nil, fmt.Errorf("read generation %d to splice into: %w", sb.Generation, err)
	}
	return fs, nil
}

// graftPreflight decides what would happen at the path, before the walk.
func graftPreflight(ctx context.Context, o *cmdOpts, inner pelicanobj.Store, stateDir string,
	sb *superblock.Superblock, mount, source string, replace, refresh, remove bool) (*graftPlan, error) {

	base, err := openGraftBase(ctx, o, inner, stateDir, sb)
	if err != nil {
		return nil, err
	}
	defer base.Close() //nolint:errcheck
	p, err := publish.GraftPreflight(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: sb, Mount: mount, Source: source,
		Replace: replace, Refresh: refresh, Remove: remove,
	})
	if err != nil {
		return nil, err
	}
	return &graftPlan{GraftPlan: p, generation: sb.Generation}, nil
}

// reportGraftPlan says what is about to happen to the path, BEFORE the
// hours of reading start.
//
// Every line here is a thing that could have been done silently. The one
// that matters most is the replacement of a populated directory: it cannot
// happen without --replace, and when it does happen it is announced with a
// count, because the person running it is the only one who can still stop
// it.
func reportGraftPlan(p *graftPlan, mount, source string, remove bool) {
	switch p.Placement {
	case publish.GraftPlaceRemoved:
		ui.Info("removing the graft at {path} (from {source}); the volume will stop depending on it, "+
			"and the {n} entries it served leave the namespace",
			"path", mount, "source", p.Prior.Source, "n", p.Prior.Files)
	case publish.GraftPlaceRefresh:
		ui.Info("{path} already serves this source; this is a refresh, and only what CHANGED "+
			"at {source} will be read", "path", mount, "source", source)
	case publish.GraftPlaceReplacedGraft:
		// Said loudly, because it is a change of who this volume depends
		// on, and nothing about the path itself will look different
		// afterwards.
		ui.Warn("{path} already serves a graft from {old}; this REPLACES it with {new}. "+
			"Nothing local is lost (a graft's bytes were never in this volume), but every reader "+
			"of this volume will start fetching a different third party",
			"path", mount, "old", p.Prior.Source, "new", source)
	case publish.GraftPlaceReplacedDir:
		ui.Warn("--replace: {path} holds {n} entries and they will NOT be in the next generation. "+
			"The generation that holds them stays readable until it ages out of the retention "+
			"window, and `pelfs graft --remove` will not bring them back",
			"path", mount, "n", p.DisplacedEntries)
	case publish.GraftPlaceReplacedFile:
		ui.Warn("--replace: the {kind} at {path} will not be in the next generation",
			"kind", graftTypeWord(p.DisplacedType), "path", mount)
	case publish.GraftPlaceEmptyDir:
		ui.Info("grafting into the empty directory already at {path}", "path", mount)
	case publish.GraftPlaceNew:
		if len(p.SyntheticDirs) > 0 {
			// A mistyped path is otherwise discovered as a set of empty
			// directories somebody has to find and delete.
			ui.Info("{path} does not exist yet; these directories will be created for it: {dirs}",
				"path", mount, "dirs", p.SyntheticDirs)
		}
	}
}

// graftPublishArgs is what the removal path needs; the add path has its
// own locals and does not go through here.
type graftPublishArgs struct {
	o        *cmdOpts
	inner    pelicanobj.Store
	refs     *refs.Store
	stateDir string
	prefix   string
	branch   string
	head     *refs.Fetched
	key      []byte
	mount    string
}

// graftRemove publishes a generation with the graft at mount taken out.
//
// It reads NOTHING: the tree is the previous generation's with one subtree
// dropped, and the superblock's graft list is stated without that entry.
// So there is no walk to interrupt and no checkpoint to keep — which is
// why it is the answer the nesting refusals offer.
//
// The directories the original graft had to CREATE on its way to the mount
// path are left behind, empty. Removing them would mean guessing which of
// them the volume's owner also wanted, and a graft does not record that.
func graftRemove(ctx context.Context, a graftPublishArgs) int {
	prior := graftEntryAt(a.head.Superblock.Grafts, a.mount)
	if prior == nil {
		// The preflight already refused this; reaching here would be a
		// bug, and saying so beats a nil dereference.
		return exitErr(fmt.Errorf("internal: no graft at %s to remove", a.mount))
	}
	lease, err := maintenanceLease(ctx, a.o, a.prefix, a.branch, "graft-remove-"+newSessionID())
	if err != nil {
		return exitErr(err)
	}
	defer releaseLease(ctx, lease)

	base, err := openGraftBase(ctx, a.o, a.inner, a.stateDir, a.head.Superblock)
	if err != nil {
		return exitErr(err)
	}
	defer base.Close() //nolint:errcheck
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: a.head.Superblock, Mount: a.mount, Remove: true,
	})
	if err != nil {
		return exitErr(err)
	}
	// A non-nil EMPTY slice is what removes the last graft; nil would
	// carry the parent's list forward (publish.Options.Grafts).
	grafts := []superblock.GraftEntry{}
	for _, g := range a.head.Superblock.Grafts {
		if g.Path != a.mount {
			grafts = append(grafts, g)
		}
	}
	res, err := publish.Publish(ctx, publish.Options{
		Source: splice, Inner: a.inner, SpoolDir: a.stateDir, Branch: a.branch,
		SigningKey: a.key, Prev: a.head.Superblock, PrevRaw: a.head.Raw,
		Grafts: grafts,
	})
	if err != nil {
		return exitErr(err)
	}
	ui.Info("removed the graft at {path} (was {source}): generation {gen} does not serve it and "+
		"does not name that source",
		"path", a.mount, "source", prior.Source, "gen", res.Superblock.Generation)
	if len(grafts) > 0 {
		ui.Info("{n} graft(s) remain; `pelfs graft --list` names them", "n", len(grafts))
	}
	ui.Info("the generation that DID serve it stays readable until it ages out of the retention "+
		"window, so this is recoverable by re-grafting {source} at {path} rather than by undoing it",
		"source", prior.Source, "path", a.mount)
	return 0
}

// graftEntryAt finds the graft at a path.
func graftEntryAt(list []superblock.GraftEntry, path string) *superblock.GraftEntry {
	for i := range list {
		if list[i].Path == path {
			return &list[i]
		}
	}
	return nil
}

// graftListWith states the whole graft list with e in it, replacing any
// entry at the same path. Options.Grafts REPLACES rather than merges, so
// carrying the parent's forward is what keeps a second graft from deleting
// the first.
func graftListWith(prev []superblock.GraftEntry, e superblock.GraftEntry) []superblock.GraftEntry {
	out := make([]superblock.GraftEntry, 0, len(prev)+1)
	replaced := false
	for _, g := range prev {
		if g.Path == e.Path {
			out, replaced = append(out, e), true
			continue
		}
		out = append(out, g)
	}
	if !replaced {
		out = append(out, e)
	}
	return out
}

// warnAboutLeftoverOverlay says, BEFORE the walk, that publishing will
// strand an unsealed overlay sitting in this state directory.
//
// It is not a graft problem and it is not new — any out-of-band publish
// (`pelfs repack`, `pelfs merge`, a second writer) has always done this:
// an overlay records the generation it shadows, so a head that moves
// underneath it makes it unsealable and `pelfs mount --rw` refuses with
// overlay.ErrGeneration. What IS new is how easy it is to hit, because
// grafting into a POPULATED volume means the state directory has usually
// just had a writable mount in it.
//
// So it is said out loud, up front, where it costs a person nothing to
// act on it — rather than discovered at the next mount, after the hours
// the walk takes. Refusing outright would be worse: the overlay may hold
// nothing anyone wants, and a graft is a legitimate thing to do to a
// volume.
func warnAboutLeftoverOverlay(stateDir string) {
	dir := filepath.Join(stateDir, "overlay")
	if _, err := os.Stat(filepath.Join(dir, "overlay.db")); err != nil {
		return
	}
	ui.Warn("there is an unsealed write overlay at {dir}. Publishing a graft advances the branch, "+
		"and an overlay can only be sealed onto the generation it was recorded over — so after this "+
		"runs, `pelfs mount --rw` on this state directory will refuse it and ask you to move it "+
		"aside. If it holds writes you want, mount and unmount to seal them BEFORE grafting; if it "+
		"does not, move or delete {dir} now",
		"dir", dir)
}

// graftTypeWord names a catalog type for a message.
func graftTypeWord(t uint8) string {
	switch t {
	case catalog.TypeDir:
		return "directory"
	case catalog.TypeFile:
		return "file"
	case catalog.TypeSymlink:
		return "symlink"
	default:
		return "entry"
	}
}
