package retention

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The sweep reads the window the VOLUME RECORDS.
//
// T_grace is a per-volume parameter (`pelfs init --grace`, carried forward
// by every seal), and the sweep is where that parameter either means
// something or does not. It used to be floored at the format default: a
// volume that recorded twelve hours was swept at seventy-two, so the knob
// could widen the window and never narrow it, and the documentation that
// called it configurable was describing a field nothing read.
//
// The direction that matters is NARROWING, because that is the one a floor
// silently ignored — and because it is the one an operator asks for: a
// volume nobody pins for more than an hour should not carry three days of
// garbage.

// headWithGrace publishes a head that RECORDS a window (publishHead states
// no Params at all, which is the "says nothing" case this contrasts with).
func headWithGrace(t *testing.T, rs *refs.Store, priv ed25519.PrivateKey, grace time.Duration, packs ...string) {
	t.Helper()
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      0,
		CreatedUnixNano: 1,
		Params:          superblock.Params{TGraceSeconds: int64(grace / time.Second)},
	}
	for _, p := range packs {
		sb.PackList = append(sb.PackList, superblock.PackEntry{Name: p, Size: 1})
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(context.Background(), "main", raw, ""); err != nil {
		t.Fatalf("flip: %v", err)
	}
}

// INVARIANT: a volume that records a SHORTER window than the default is
// swept at the window it records.
func TestTheSweepUsesTheWindowTheVolumeRecords(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	// Three hours old: past a recorded two-hour window, comfortably inside
	// the format's 72-hour default. The whole test lives in that gap.
	garbage := packName(now.Add(-3*time.Hour), "bbbb")
	live := packName(now.Add(-3*time.Hour), "aaaa")

	t.Run("recorded 2h collects it", func(t *testing.T) {
		inner, _ := newInner(t)
		_, priv, _ := ed25519.GenerateKey(nil)
		rs, err := refs.New(inner, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		putPack(t, inner, live, 100)
		putPack(t, inner, garbage, 100)
		headWithGrace(t, rs, priv, 2*time.Hour, live)

		rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if rep.Grace != 2*time.Hour {
			t.Fatalf("the sweep applied a %v window; the head records 2h, and a sweep that floors it at "+
				"the format default is a sweep the --grace parameter cannot narrow", rep.Grace)
		}
		if rep.Deleted != 1 {
			t.Fatalf("deleted %d packs, want 1: the 3h-old unreferenced pack is past the 2h window this "+
				"volume recorded", rep.Deleted)
		}
		if alive(t, inner, packstore.PackDirKey+"/"+garbage) {
			t.Error("the unreferenced pack survived a window it is older than")
		}
		if !alive(t, inner, packstore.PackDirKey+"/"+live) {
			t.Error("a pack the head names was deleted")
		}
	})

	// The control, and it is what keeps the case above from being vacuous:
	// the same objects at the same ages, on a volume that records nothing,
	// are KEPT. If the sweep were ignoring the recorded window in either
	// direction, exactly one of these two subtests would fail.
	t.Run("no recorded window keeps it", func(t *testing.T) {
		inner, _ := newInner(t)
		_, priv, _ := ed25519.GenerateKey(nil)
		rs, err := refs.New(inner, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		putPack(t, inner, live, 100)
		putPack(t, inner, garbage, 100)
		publishHead(t, rs, priv, 0, nil, "", []string{live}, nil)

		rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if rep.Grace != DefaultGrace {
			t.Fatalf("a head that records no window was swept at %v, want the format default %v",
				rep.Grace, DefaultGrace)
		}
		if rep.Deleted != 0 {
			t.Fatalf("deleted %d packs, want 0: nothing here is older than the default window", rep.Deleted)
		}
	})

	// And the reader-side flag keeps its meaning: it may only WIDEN. A
	// reader who knows they are holding a generation longer than the volume
	// promises says so here, and the sweep obeys them over the document.
	t.Run("--grace still widens past the recorded window", func(t *testing.T) {
		inner, _ := newInner(t)
		_, priv, _ := ed25519.GenerateKey(nil)
		rs, err := refs.New(inner, t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		putPack(t, inner, live, 100)
		putPack(t, inner, garbage, 100)
		headWithGrace(t, rs, priv, 2*time.Hour, live)

		rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now, Grace: 100 * time.Hour})
		if err != nil {
			t.Fatalf("GC: %v", err)
		}
		if rep.Grace != 100*time.Hour {
			t.Fatalf("the sweep applied %v with --grace 100h against a recorded 2h", rep.Grace)
		}
		if rep.Deleted != 0 {
			t.Fatalf("deleted %d packs under --grace 100h; a reader asking for a wider window was "+
				"overruled by the document, which is the one direction this option must not lose",
				rep.Deleted)
		}
	})
}

// INVARIANT: on a volume whose roots record DIFFERENT windows, each root's
// ledger rows are judged against the window its own document records, and
// the object-age guard runs at the widest.
//
// This is what narrowing a volume's window means in practice: it takes
// effect as the documents written under the old one leave the root set, and
// until then the older promise is kept. The alternative — one window per
// sweep, taken from whichever root was absorbed first — would make the
// answer for an object depend on listing order.
func TestAWiderRootKeepsItsOwnPromise(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	live := packName(now.Add(-100*time.Hour), "aaaa")
	garbage := packName(now.Add(-3*time.Hour), "bbbb")
	putPack(t, inner, live, 100)
	putPack(t, inner, garbage, 100)

	// The head records two hours; a TAG on a generation written before the
	// window was narrowed records the old seventy-two.
	headWithGrace(t, rs, priv, 2*time.Hour, live)
	old := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      0,
		CreatedUnixNano: 1,
		Params:          superblock.Params{TGraceSeconds: int64(72 * time.Hour / time.Second)},
		PackList:        []superblock.PackEntry{{Name: live, Size: 1}},
	}
	if err := old.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := old.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Tag(ctx, "wide", raw); err != nil {
		t.Fatalf("tag: %v", err)
	}

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: now})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Grace != 72*time.Hour {
		t.Fatalf("the sweep applied %v; one root still records 72h, and the age guard has to run at the "+
			"widest window any root promises or that root's readers lose objects early", rep.Grace)
	}
	if rep.Deleted != 0 {
		t.Fatalf("deleted %d packs: the 3h-old pack is inside the 72h window the tag still records", rep.Deleted)
	}
}
