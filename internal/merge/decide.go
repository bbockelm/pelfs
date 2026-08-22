package merge

import (
	"context"
	"fmt"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// The rules, in one place.
//
// The planner and the executor both run them, and that sharing is the
// whole point of the file: two implementations of these rules would drift,
// and the way they would drift is one of them silently taking a side the
// other called a conflict. Everything about a merge that could go wrong
// QUIETLY is here.

// Outcome is what a merge does with one name.
type Outcome int

const (
	// TakeOurs and TakeTheirs name the side the merged tree gets the entry
	// from.
	TakeOurs Outcome = iota
	TakeTheirs
	// Same means both sides agree, so either will do.
	Same
	// Drop means the merged tree does not have this name: one side deleted
	// it and the other did not touch it.
	Drop
	// Conflicted means a human has to decide.
	Conflicted
	// Descend means the answer is inside a directory rather than about it.
	Descend
)

// Policy is what to do with a path neither tree can resolve.
type Policy int

const (
	// Refuse reports conflicts and merges nothing. The default, because a
	// merge is not a thing to half-do: a user who wanted both copies can
	// ask, and one who did not would rather be told.
	Refuse Policy = iota
	// KeepBoth writes both versions — ours under its own name, theirs
	// under a suffixed one — so a conflicted merge completes and loses
	// nothing. Dropbox's answer, and it is the right shape for a
	// FILESYSTEM: there is no place to put conflict markers in a byte
	// stream that anything would still be able to read, so the two
	// versions have to be two files.
	//
	// The cost is clutter, and it is real: nothing cleans these up, and a
	// tool that walks the tree will see them. That is why it is opt-in.
	KeepBoth
)

// ConflictName is where theirs' copy goes when a conflict is kept rather
// than reported.
//
// The suffix goes BEFORE the extension, so that `report.tar.gz` stays a
// `.gz` to everything that dispatches on one. Dropbox does the same, for
// the same reason: a conflicted copy nothing can open is a conflicted copy
// nobody can resolve.
//
// It names the branch rather than a timestamp. A timestamp says when the
// clash was noticed, which nobody needs; the branch says whose version it
// is, which is the question a user actually has.
func ConflictName(name, branch string) string {
	stem, ext := name, ""
	// The LAST dot, not the first: `archive.tar.gz` should become
	// `archive.tar (from dev).gz`, keeping the extension a reader
	// dispatches on rather than inventing `archive (from dev).tar.gz`,
	// which would be tidier and would move a name the tree may reference.
	if i := strings.LastIndex(name, "."); i > 0 {
		stem, ext = name[:i], name[i:]
	}
	return stem + " (from " + branch + ")" + ext
}

// decide resolves one name against the three trees.
func decide(ctx context.Context, t *trees, b entry, inBase bool, ours entry, inOurs bool,
	theirs entry, inTheirs bool) (Outcome, Kind, string) {

	switch {
	case inOurs && inTheirs:
		if ours.Node.Type != theirs.Node.Type {
			return Conflicted, TypeChange, fmt.Sprintf("ours is type %d, theirs is type %d",
				ours.Node.Type, theirs.Node.Type)
		}
		if ours.Node.Type == catalog.TypeDir {
			// Directories merge as the union of their entries, which is why
			// two branches that touched different areas conflict nowhere.
			return Descend, "", ""
		}
		same, err := sameContent(ctx, t.ours, ours, t.theirs, theirs)
		if err == nil && same {
			return Same, "", ""
		}
		if !inBase {
			return Conflicted, AddAdd, "both sides created it with different content"
		}
		ourChanged := !sameEntry(ctx, t.base, b, t.ours, ours)
		theirChanged := !sameEntry(ctx, t.base, b, t.theirs, theirs)
		switch {
		case ourChanged && theirChanged:
			return Conflicted, BothModified, "both sides changed it since the base"
		case theirChanged:
			return TakeTheirs, "", ""
		case ourChanged:
			return TakeOurs, "", ""
		}
		// Neither differs from the base yet they differ from each other,
		// which cannot happen if the comparison is sound. Reported rather
		// than silently taking a side.
		return Conflicted, BothModified, "the two sides differ but neither differs from the base (base may be wrong)"

	case inOurs:
		// A DIRECTORY IS ALWAYS DESCENDED, including one the other side
		// deleted. Its inodes have to reach the collision pass, and "was it
		// modified" cannot be answered by comparing the directories:
		// sameContent calls two of them equal whenever their metadata
		// matches, because directories are compared by their ENTRIES.
		// Deciding a deletion from that would discard a subtree this side
		// had changed inside, so the descent decides per file and reports
		// against the file that actually changed.
		if ours.Node.Type == catalog.TypeDir {
			return Descend, "", ""
		}
		if !inBase {
			return TakeOurs, "", "" // added here
		}
		if !sameEntry(ctx, t.base, b, t.ours, ours) {
			return Conflicted, ModifyDelete, "ours modified it, theirs deleted it"
		}
		return Drop, "", "" // unmodified here, deleted there

	case inTheirs:
		if theirs.Node.Type == catalog.TypeDir {
			return Descend, "", ""
		}
		if !inBase {
			return TakeTheirs, "", ""
		}
		if !sameEntry(ctx, t.base, b, t.theirs, theirs) {
			return Conflicted, ModifyDelete, "theirs modified it, ours deleted it"
		}
		return Drop, "", ""
	}
	// Only the base has it: both sides deleted it.
	return Drop, "", ""
}
