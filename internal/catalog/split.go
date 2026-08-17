// Catalog split policy (docs/design-packfs.md, "Path catalogs" /
// splitting). Pure in-memory: publish computes directory weights
// (W = 200·entries + inline_bytes (+ xattr bytes)) into a DirNode tree and
// runs Split before writing any SQLite; nothing here touches the database.
package catalog

// Measured thresholds from the design doc: split at SMax, merge a nested
// catalog back into its parent only below SMin (8:1 hysteresis prevents
// thrashing). TransitionWeight is the structural cost a peeled child leaves
// behind in its parent — one transition row, priced like any other entry.
const (
	SMax             int64 = 8 << 20
	SMin             int64 = 1 << 20
	TransitionWeight int64 = 200
)

// DirNode is one directory in the caller-built weight tree. OwnWeight is
// the directory's own structural cost — 200 bytes per entry it contains
// plus its entries' inline (and xattr) bytes — excluding child directories'
// subtrees, which hang off Children.
type DirNode struct {
	OwnWeight int64
	Children  []*DirNode
	// Weight is what Split left this directory weighing: its own rows plus
	// the child subtrees still attached after any peels — exactly the
	// number its PARENT counted for it. Split fills it in.
	//
	// It is output rather than bookkeeping because a publisher that
	// records a catalog root's weight can, next generation, stand in for
	// that whole subtree with one number and never walk it: the parent's
	// peel decisions are a function of its children's weights and nothing
	// else.
	Weight int64
}

// Split chooses catalog roots for the tree at root: bottom-up post-order, a
// directory whose accumulated weight exceeds smax peels its largest
// attached child subtree (the peel becomes a nested-catalog root and costs
// the parent one TransitionWeight row), repeating until the directory fits.
// Peeling stops early when no attached child outweighs its own transition
// row — peeling such a child cannot help. A flat directory whose own rows
// alone exceed smax cannot split (catalog roots are directories) and stays
// one oversized catalog — the allowed pathology.
//
// smin plays no role here: it governs merging existing small catalogs back
// into parents between generations (see ShouldMerge), not the initial peel.
// It rides in the signature so call sites carry both thresholds together.
//
// The result is deterministic: peeled roots in discovery order (post-order
// over the tree; within a directory largest child first, ties to the lowest
// child index), with the tree root — always a catalog root — last.
func Split(root *DirNode, smax, smin int64) []*DirNode {
	_ = smin
	var roots []*DirNode
	var walk func(d *DirNode) int64
	walk = func(d *DirNode) int64 {
		w := d.OwnWeight
		weights := make([]int64, len(d.Children))
		attached := make([]int, 0, len(d.Children))
		for i, c := range d.Children {
			weights[i] = walk(c)
			w += weights[i]
			attached = append(attached, i)
		}
		for w > smax && len(attached) > 0 {
			best := 0
			for pos, i := range attached[1:] {
				if weights[i] > weights[attached[best]] {
					best = pos + 1
				}
			}
			i := attached[best]
			if weights[i] <= TransitionWeight {
				break
			}
			w += TransitionWeight - weights[i]
			roots = append(roots, d.Children[i])
			attached = append(attached[:best], attached[best+1:]...)
		}
		d.Weight = w
		return w
	}
	walk(root)
	return append(roots, root)
}

// ShouldMerge reports whether a nested catalog of childWeight should be
// merged back into its parent of parentWeight: the child is under the smin
// hysteresis floor and the parent, absorbing the child and shedding the
// transition row, stays within smax.
func ShouldMerge(childWeight, parentWeight, smax, smin int64) bool {
	return childWeight < smin && parentWeight+childWeight-TransitionWeight <= smax
}
