package main

import (
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// A rename is unpublished work, and the durability panel has to say so.
//
// It did not. The panel is fed from genSession.pressure(), which reported
// staged BYTES and dirty INODES — and a rename writes neither. Renaming a
// file in the browser wrote a whiteout for the old name and an edge for
// the new one (overlay.Rename), left StagedBytes and DirtyNodes at zero,
// and the page told the user there was nothing to publish while an
// unpublished change sat in the overlay.
//
// The seal never had the hole: checkpoint and sealAtExit have always
// tested DirtyEdges too, which is why this was a reporting bug and not a
// lost-data one — the rename was published, just never when the user asked
// and never with the user knowing it was pending. Two meters and a
// predicate that disagree are one meter too few.
//
// The fixture publishes first on purpose. A file created in THIS session
// is dirty in every meter at once, so renaming it would pass whatever the
// panel counted; only a rename of something the base generation already
// holds isolates the namespace as the sole change.
func TestARenameIsReportedAsUnpublishedWork(t *testing.T) {
	ctx := context.Background()
	f := newBrowseFixture(t, true, false)
	f.bs.setReady(f.g, ctx)

	writeFile(t, f.g.ov, "before.txt", "published content")
	if _, err := f.g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint the fixture: %v", err)
	}
	if st := f.state(); st.Unpublished {
		t.Fatalf("the session reports unpublished work right after a checkpoint: "+
			"%d staged file(s), %d dirty node(s), %d dirty edge(s)",
			st.StagedFiles, st.DirtyNodes, st.DirtyEdges)
	}

	if _, err := f.g.ov.Lookup(ctx, overlay.RootInode, "before.txt"); err != nil {
		t.Fatalf("lookup before.txt: %v", err)
	}
	if err := f.g.ov.Rename(ctx, overlay.RootInode, "before.txt",
		overlay.RootInode, "after.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	st := f.state()
	if st.DirtyEdges == 0 {
		t.Errorf("after a rename the session reports %d dirty edge(s); the whiteout and the "+
			"new name are both unpublished", st.DirtyEdges)
	}
	if !st.Unpublished {
		t.Errorf("after a rename the session reports nothing to publish "+
			"(%d staged file(s), %d staged byte(s), %d dirty node(s), %d dirty edge(s)) — "+
			"the page cannot prompt for a change it is never told about",
			st.StagedFiles, st.StagedBytes, st.DirtyNodes, st.DirtyEdges)
	}
	// And the counters that were already right must stay right: a rename
	// really does move no bytes, and a panel that started reporting one
	// would be lying in the other direction.
	if st.StagedBytes != 0 || st.StagedFiles != 0 {
		t.Errorf("a rename reported %d staged byte(s) across %d file(s); it moves neither",
			st.StagedBytes, st.StagedFiles)
	}

	// The seal's own predicate agreed all along, and this is what pins the
	// two together: publishing after the rename must write a generation.
	before := f.g.gfs.Generation()
	if _, err := f.g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint the rename: %v", err)
	}
	if after := f.g.gfs.Generation(); after == before {
		t.Errorf("publishing after a rename left the mount on generation %d; "+
			"the panel said there was work and the seal found none", after)
	}
	if st := f.state(); st.Unpublished {
		t.Errorf("the rename is published and the session still reports %d dirty edge(s)",
			st.DirtyEdges)
	}
}
