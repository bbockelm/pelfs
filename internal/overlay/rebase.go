package overlay

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// Rebase is the other half of the checkpoint. Once a snapshot has been
// sealed and published, the new generation CONTAINS that snapshot's
// merged view — so every overlay row whose last modification the snapshot
// captured is redundant, and dropping it makes the inode clean again:
// resolvable from the base, and eligible for the effectively infinite
// entry/attr TTLs immutable content earns (docs/design-packfs.md, on the
// catalog-native mount). Without it a long session monotonically loses
// caching, because every inode it ever touched keeps paying the short
// dirty TTL long after its content was published.
//
// The caller's contract, in order, and none of it optional:
//
//  1. snap := fs.Snapshot(ctx, dir); seq := snap.Seq()
//  2. seal snap (NOT the live overlay) and publish it successfully
//  3. swap the base *genfs.FS in place to the sealed generation
//     (genfs.Swap, which also re-descends kernel-held residency)
//  4. fs.Rebase(ctx, seq, Options{BaseRoot: <sealed>, BaseGeneration: ...})
//  5. push kernel notifications for the reported inodes and start
//     serving them the clean TTLs
//
// Step 3 before step 4 is what makes step 4 safe, and Rebase refuses to
// run until it sees it: the sealed root catalog it is handed must be the
// one the LIVE base serves. What the overlay cannot verify is that the
// sealed generation is a seal of THIS snapshot rather than of some other
// tree with the same root — that is the caller's to get right. What it
// does verify is that every edge the snapshot recorded resolves, in the
// new base, to the same inode; a mismatch there is refused outright, and
// an inode the new base cannot resolve is simply left dirty.

// RebaseReport is what the caller turns into kernel notifications and TTL
// policy: Clean inodes may be served as immutable base content again.
type RebaseReport struct {
	// Clean lists the inodes that lost all overlay state, ascending.
	Clean []uint64
	// Unresolved lists inodes the sealed base could not resolve, which
	// were therefore left dirty (never a correctness loss, only a cost).
	Unresolved []uint64
	// Dirty is how many inodes remain dirty afterwards.
	Dirty int
	// Edges is the number of oedge rows dropped, whiteouts included.
	Edges int
	// BaseGeneration is the generation the overlay now sits over.
	BaseGeneration uint64
}

// Rebase drops the overlay state a sealed snapshot published. sealedSeq
// is that snapshot's Seq; sealed carries the published generation's
// identity, exactly as Open takes the base's (NextInode is ignored — the
// overlay's own allocator is authoritative and must never rewind).
// rebaseBatch is how many inodes one batch drops before the lock is
// released. Big enough that per-transaction overhead stays small, short
// enough that a filesystem operation arriving mid-rebase waits for a
// batch rather than for the whole set.
const rebaseBatch = 512

// rebaseBatchLocked drops the overlay rows of one batch of cleaned
// inodes. The caller holds the lock and keeps holding it.
//
// Membership is re-checked here rather than trusted from the set computed
// before the first batch: the lock is released between batches, so an
// inode can be written in the meantime, and dropping its rows then would
// lose that write. modSeq is what says so, and it is the same test the
// set was built with.
func (fs *FS) rebaseBatchLocked(batch []uint64, sealedSeq uint64, clean map[uint64]struct{},
	rep *RebaseReport) error {
	var drop []uint64
	if err := fs.withTx(func(tx querier) error {
		for _, ino := range batch {
			if fs.modSeqOfLocked(ino) > sealedSeq {
				// Written since the batching began. It is dirty again, and
				// belongs to the next generation rather than this one.
				delete(clean, ino)
				continue
			}
			staged, err := hasContent(tx, ino)
			if err != nil {
				return err
			}
			if staged {
				drop = append(drop, ino)
			}
			for _, q := range []string{
				`DELETE FROM onode WHERE inode = ?`,
				`DELETE FROM ocontent WHERE inode = ?`,
				`DELETE FROM oxattr WHERE inode = ?`,
				`DELETE FROM osymlink WHERE inode = ?`,
			} {
				if _, err := tx.Exec(q, int64(ino)); err != nil {
					return err
				}
			}
			// Edges belong to their parent: every namespace mutation
			// stamps the parent, so a clean parent means its whole
			// directory — whiteouts included — is what was published. A
			// published deletion needs no whiteout: the name is gone from
			// the new base, so the merged view resolves it to nothing on
			// its own.
			res, err := tx.Exec(`DELETE FROM oedge WHERE parent = ?`, int64(ino))
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err == nil {
				rep.Edges += int(n)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// The content goes NOW, with the lock still held, rather than on a
	// list replayed after the whole rebase. That list was safe only while
	// one lock hold covered the entire rebase: with the lock released
	// between batches, an inode whose rows were just dropped can be
	// written again — staging a fresh file under the same number — and a
	// deferred unlink would then delete the new one. A test caught exactly
	// that.
	//
	// The cost is what it was before it was deferred, minus the scale: one
	// unlink per staged inode in THIS batch, so tens of milliseconds
	// rather than the seconds a whole source tree took.
	for _, ino := range drop {
		if deferred := fs.content.Drop(ino); deferred != nil {
			deferred()
		}
	}
	return nil
}

func (fs *FS) Rebase(ctx context.Context, sealedSeq uint64, sealed Options) (*RebaseReport, error) {
	if sealed.BaseRoot == ([32]byte{}) {
		return nil, errors.New("overlay: Rebase requires the sealed generation's BaseRoot")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if live := fs.base.RootCatalog(); live != sealed.BaseRoot {
		return nil, fmt.Errorf("%w: Rebase names sealed root %x but the served base is %x "+
			"(swap the base generation before rebasing onto it)",
			ErrGeneration, sealed.BaseRoot[:8], live[:8])
	}
	if sealedSeq < fs.rebasedSeq {
		return nil, fmt.Errorf("overlay: sequence %d was already rebased away (at %d)", sealedSeq, fs.rebasedSeq)
	}
	edges, ok := fs.snapEdges[sealedSeq]
	if !ok {
		return nil, fmt.Errorf("overlay: no snapshot was taken at sequence %d", sealedSeq)
	}

	// Re-establish base residency at the snapshot's namespace before
	// anything is dropped. This is both a repair and a check: genfs
	// serves an inode only after a descent, and the swap re-descended
	// only inodes whose BASE edge survived — anything the overlay had
	// moved must be re-resolved here, or a stat after the rebase would
	// hit an inode the new generation has never been asked for.
	unresolved, err := fs.replaySnapshotNamespaceLocked(ctx, edges)
	if err != nil {
		return nil, err
	}

	dirty, err := dirtyInodes(fs.q)
	if err != nil {
		return nil, err
	}
	// A directory whose edges are dropped must have every one of its
	// names answerable by the new base, so an unresolved child pins its
	// parent dirty as well.
	blocked := make(map[uint64]struct{}, 2*len(unresolved))
	for ino := range unresolved {
		blocked[ino] = struct{}{}
		blocked[edges[ino].parent] = struct{}{}
	}
	clean := make(map[uint64]struct{}, len(dirty))
	for ino := range dirty {
		if _, no := blocked[ino]; no {
			continue
		}
		if fs.modSeqOfLocked(ino) <= sealedSeq {
			clean[ino] = struct{}{}
		}
	}
	cleaned := sortedInodes(clean)

	rep := &RebaseReport{BaseGeneration: sealed.BaseGeneration, Unresolved: sortedInodes(unresolved)}

	// The base generation is recorded BEFORE any row is dropped, and in
	// its own transaction, which is what lets everything after it be
	// interruptible. A crash in between leaves an overlay over the new
	// base carrying rows that shadow content that base already has:
	// redundant, identical, and harmless. The other order is not safe —
	// rows dropped while the overlay still claims the OLD base would be
	// content missing from the merged view after a reopen.
	if err := fs.withTx(func(tx querier) error {
		if err := metaSet(tx, metaBaseRoot, hex.EncodeToString(sealed.BaseRoot[:])); err != nil {
			return err
		}
		return metaSet(tx, metaBaseGeneration, strconv.FormatUint(sealed.BaseGeneration, 10))
	}); err != nil {
		return nil, err
	}

	// Dropping rows for tens of thousands of inodes is the bulk of a
	// rebase, and it used to hold the mount's lock for all of it — 7 to
	// 11 seconds on a source tree, which is long enough for an NFS client
	// to declare the server dead. It is done in batches now, with the
	// lock released between them, because none of it is load-bearing:
	// rebasing is what hands inodes back as CLEAN, and an inode that does
	// not get there simply keeps paying the short dirty TTL.
	//
	// What the release makes possible is a writer dirtying an inode this
	// loop was about to clean, so each batch re-checks under the lock
	// rather than trusting the set computed before the first one. Dropping
	// rows for an inode written since the snapshot would be losing that
	// write.
	for start := 0; start < len(cleaned); start += rebaseBatch {
		end := min(start+rebaseBatch, len(cleaned))
		if err := fs.rebaseBatchLocked(cleaned[start:end], sealedSeq, clean, rep); err != nil {
			return nil, err
		}
		if end < len(cleaned) {
			// The only point of the batching: hand the lock to whoever is
			// waiting. Go's mutex passes it directly to a waiter that has
			// been queued for a millisecond, which is exactly the filesystem
			// operation this exists to let through.
			fs.mu.Unlock()
			fs.mu.Lock()
		}
	}

	err = fs.withTx(func(tx querier) error {
		// The snapshot's namespace IS the new base's namespace, so it is
		// also the provenance a reopened overlay must replay: an inode
		// the overlay moved lives in the new base at its MERGED path, and
		// the original base edge recorded when it detached names a path
		// that generation no longer has. Rewriting it is not optional —
		// a stale chain is an ErrStale after reopen.
		//
		// A cleaned inode that no overlay edge still names needs no row at
		// all: a plain merged descent now finds it exactly where the base
		// has it, the same standing every untouched base inode has. One
		// that IS still named by a surviving edge keeps its row, because
		// that edge answers the lookup WITHOUT descending the base, so
		// nothing else would ever make it resident.
		for _, ino := range sortedEdgeKeys(edges) {
			if ino == RootInode {
				continue
			}
			if _, gone := clean[ino]; gone {
				var one int64
				err := tx.QueryRow(`SELECT 1 FROM oedge WHERE inode = ? LIMIT 1`, int64(ino)).Scan(&one)
				if errors.Is(err, sql.ErrNoRows) {
					if _, err := tx.Exec(`DELETE FROM obase WHERE inode = ?`, int64(ino)); err != nil {
						return err
					}
					continue
				}
				if err != nil {
					return err
				}
			}
			if _, no := unresolved[ino]; no {
				continue
			}
			e := edges[ino]
			if _, err := tx.Exec(`INSERT OR REPLACE INTO obase (inode, parent, name) VALUES (?, ?, ?)`,
				int64(ino), int64(e.parent), []byte(e.name)); err != nil {
				return err
			}
		}
		if err := metaSet(tx, metaBaseRoot, hex.EncodeToString(sealed.BaseRoot[:])); err != nil {
			return err
		}
		return metaSet(tx, metaBaseGeneration, strconv.FormatUint(sealed.BaseGeneration, 10))
	})
	if err != nil {
		return nil, err
	}
	// Re-derive the dirty set from the rebased tables rather than editing
	// it: agreement with a fresh reopen is then structural, not a claim.
	fs.dirtySet = nil
	if err := fs.loadDirtyLocked(); err != nil {
		return nil, err
	}
	for _, ino := range cleaned {
		if _, still := fs.dirtySet[ino]; still {
			// Named by an edge under a parent that stayed dirty: its own
			// state is published and gone, but the kernel still sees a
			// dirty inode, so it does not go clean in this report.
			fs.modSeq[ino] = sealedSeq
			continue
		}
		delete(fs.modSeq, ino)
		// And its cached base descent step, for the same reason and by
		// the same rule as the obase row the transaction above just
		// deleted for this exact set.
		//
		// prov is a CACHE of "the base resolves parent/name to this
		// inode" (overlay.go), filled by every descent and — until now —
		// deleted by nothing, so it grew for the life of a session at
		// ~66 B per inode ever named: 6.6 GB at a hundred million.
		//
		// An inode that has gone CLEAN is one the new base serves at its
		// own path, with no overlay row and no overlay edge left to name
		// it. That is precisely the standing of an inode this session
		// never touched, and the seal path already draws that conclusion
		// for the PERSISTED copy of the same fact: the obase chain is
		// dropped here for this set, on the stated grounds that "a plain
		// merged descent now finds it exactly where the base has it".
		// Dropping the in-memory cache of that same descent step is the
		// same decision, so it can cost only what a cache miss costs — a
		// lookup that runs again.
		//
		// The two sets that must NOT be swept are excluded by the branch
		// above rather than by a rule of their own: an inode still named
		// by a surviving overlay edge is still dirty, and its edge answers
		// lookups WITHOUT descending the base, so nothing else would ever
		// make it resident. Everything the snapshot's namespace named and
		// the base could not resolve stayed dirty too (blocked), and keeps
		// the provenance replaySnapshotNamespaceLocked just re-pinned.
		delete(fs.prov, ino)
		rep.Clean = append(rep.Clean, ino)
	}
	rep.Dirty = len(fs.dirtySet)
	fs.rebasedSeq = sealedSeq
	for seq := range fs.snapEdges {
		if seq <= sealedSeq {
			delete(fs.snapEdges, seq)
		}
	}
	return rep, nil
}

// replaySnapshotNamespaceLocked descends every snapshot edge in the new
// base, parent first, and re-pins provenance from it. An edge that
// resolves to a DIFFERENT inode means the base is not the tree that was
// sealed, which is refused; an edge the base cannot serve leaves its
// inode (and its descendants) out of the rebase.
func (fs *FS) replaySnapshotNamespaceLocked(ctx context.Context, edges map[uint64]provEdge) (map[uint64]struct{}, error) {
	state := make(map[uint64]int8, len(edges)) // 1 resolved, -1 not
	bad := make(map[uint64]struct{})
	var resolve func(ino uint64) (bool, error)
	resolve = func(ino uint64) (bool, error) {
		if ino == RootInode {
			return true, nil
		}
		if s, seen := state[ino]; seen {
			return s > 0, nil
		}
		e, named := edges[ino]
		if !named {
			// Not moved by the overlay: it sits at its base path, where
			// the swap already re-descended it.
			return true, nil
		}
		state[ino] = -1 // also breaks a cycle a rename loop could have left
		bad[ino] = struct{}{}
		ok, err := resolve(e.parent)
		if err != nil || !ok {
			return false, err
		}
		n, err := fs.base.Lookup(ctx, e.parent, e.name)
		switch {
		case errors.Is(err, ErrStale), errors.Is(err, ErrNotExist):
			return false, nil
		case err != nil:
			return false, fmt.Errorf("overlay: rebase: resolve %d/%q in the sealed base: %w", e.parent, e.name, err)
		case n.Inode != ino:
			return false, fmt.Errorf("%w: sealed base resolves %d/%q to inode %d, the snapshot to %d "+
				"(the published generation is not a seal of this snapshot)",
				ErrGeneration, e.parent, e.name, n.Inode, ino)
		}
		fs.prov[ino] = e
		state[ino] = 1
		delete(bad, ino)
		return true, nil
	}
	for _, ino := range sortedEdgeKeys(edges) {
		if _, err := resolve(ino); err != nil {
			return nil, err
		}
	}
	return bad, nil
}

// dirtyInodes is the table-derived dirty set: the definition IsDirty
// reopens with (accessors.go), plus symlink rows for completeness.
func dirtyInodes(q querier) (map[uint64]struct{}, error) {
	set := make(map[uint64]struct{})
	for _, sel := range []string{
		`SELECT inode FROM onode`,
		`SELECT inode FROM ocontent`,
		`SELECT inode FROM oxattr`,
		`SELECT inode FROM osymlink`,
		`SELECT inode FROM oedge WHERE inode != 0`,
		`SELECT parent FROM oedge`,
	} {
		rows, err := q.Query(sel)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ino uint64
			if err := rows.Scan(&ino); err != nil {
				rows.Close() //nolint:errcheck
				return nil, err
			}
			set[ino] = struct{}{}
		}
		if err := closeRows(rows); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func sortedEdgeKeys(edges map[uint64]provEdge) []uint64 {
	out := make([]uint64, 0, len(edges))
	for ino := range edges {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
