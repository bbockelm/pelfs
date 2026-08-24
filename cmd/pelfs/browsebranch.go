package main

// THE BRANCH PILL AS A CONTROL: `GET /api/v1/branches` and
// `POST /api/v1/branch`.
//
// The request was "I feel like I should be able to click on the 'branch'
// pill and get a drop-down to show other branches", and a drop-down whose
// entries cannot be chosen is a worse pill than the label it replaced. So
// both routes ship together: listing without switching would give the page
// a control that errors on every click.
//
// # What a switch IS, and why it is not a second open path
//
// A generation swap already exists and is already the thing a live session
// does to follow a generation it did not open on: genfs.Swap "replaces the
// served generation in place", re-resolving resident inodes and leaving
// readers in flight to complete against the catalogs they already hold.
// The checkpoint path has used it since it existed. A branch is a NAME
// POINTING AT A GENERATION (cmd/pelfs/branch.go), so switching branches is
// that same swap pointed at a generation reached by another name.
//
// THE BINDING FOLLOWS FOR FREE, and that is the reason to do it this way
// rather than by rebuilding a session. `b.binding` wraps the *overlay.FS*
// or the *genfs.FS* by pointer, and genfs.Swap mutates that object; a
// read-only session therefore needs no new binding, no new WebDAV handler
// and no window in which /dav/ answers 503. A stale binding after a switch
// is the worst outcome this route could have, and the shape of the fix is
// that there is nothing to keep in sync.
//
// # The overlay is the part that cannot be swapped, so it is the part
// that gates the switch
//
// An overlay is recorded OVER ONE BASE GENERATION and its rows describe a
// tree that only makes sense against that base (internal/overlay: "the
// unsealed overlay was recorded over an older generation … its contents
// are intact but cannot be sealed onto the current head"). There is no
// meaning to be had from replaying volume A's staged writes onto volume
// branch B, and inventing one would be inventing a merge.
//
// overlay.Rebase is NOT that tool and must not be reached for here, even
// though an empty overlay would survive it: its contract is "the sealed
// generation CONTAINS this snapshot", which is true of a checkpoint of
// this branch and false of another branch's head. Using it because the
// degenerate case happens to work would leave the next reader believing it
// supports this.
//
// So the rule is the simple one, and it is a REFUSAL rather than a
// discard: a session with staged work answers 409 and says "publish or
// discard first". Nothing is thrown away to make a switch possible, which
// is the one outcome that would be unforgivable — a user clicks a pill and
// loses an afternoon's uploads.
//
// With nothing staged, the overlay carries no information, and it is
// closed, retired to the trash (the same retireDir a seal uses) and
// reopened over the new base. That is a fresh empty overlay for a fresh
// base, which is exactly what the session would have had if it had been
// started on this branch.
//
// # The lease moves before anything else does
//
// The advisory lease is PER BRANCH (internal/lease). A writable session
// switching from main to dev must hold dev's lease, and the acquisition
// comes FIRST — before the swap, before the overlay is touched — because
// it is the step most likely to be refused (another writer has dev) and
// the only one whose failure must leave the session exactly as it was.
// The old branch's lease is released last, after the switch has succeeded:
// releasing first would open a window in which this session holds neither.
//
// # Read-only sessions switch
//
// The contract offered a 403 for "a read-only session that refuses to
// switch". THIS SERVER DOES NOT REFUSE, and the decision is recorded here
// because the route's client is written to handle both. A read-only
// session has no overlay to strand, no lease to move and nothing to
// publish, so a switch is a swap and nothing else — the cheapest and
// safest form of the operation. Refusing it would disable the drop-down
// in exactly the session where reading across branches is the most
// natural thing to be doing.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// branchInfo is one row of the drop-down.
type branchInfo struct {
	Name string `json:"name"`
	// Generation and Head are omitted when this client could not read the
	// branch — a ref signed by a key this volume does not trust, or one
	// that lost a race with a writer. The row is still LISTED, because a
	// branch that exists and cannot be read is a fact the user needs more
	// than a shorter list; Error says which.
	Generation uint64 `json:"generation,omitempty"`
	Head       string `json:"head,omitempty"`
	// Staged is work this session would strand by switching away. It can
	// only ever be true of the branch the session is ON: an overlay
	// belongs to one base generation, so no other row can have any.
	Staged bool   `json:"staged"`
	Error  string `json:"error,omitempty"`
}

type branchList struct {
	Current  string       `json:"current"`
	Branches []branchInfo `json:"branches"`
}

// stagedForSwitch answers the only question a switch has to ask of the
// overlay, and it exists because genSession.pressure() folds three
// different answers into one.
//
// pressure() returns (-1, -1) for "read-only", for "mid-seal" and for
// "unreadable" alike, which is right for a durability panel (all three
// mean "do not believe a zero") and wrong here: a READ-ONLY session has
// nothing to strand and must be allowed to switch, while a session whose
// overlay is inside a seal must not be. Reading -1 as "refuse" made a
// read-only browse session — the one where switching is safest — the one
// session that could not.
//
//	staged  there is unpublished work a switch would strand
//	busy    the overlay cannot be read right now (a seal holds it, or the
//	        session is going away), so the answer is not "no"
func stagedForSwitch(g *genSession) (staged, busy bool) {
	g.ovMu.RLock()
	ov, spent := g.ov, g.spent
	g.ovMu.RUnlock()
	if ov == nil {
		// No overlay at all: a read-only session. `spent` means the
		// overlay was sealed and retired, which happens on the way out.
		return false, spent
	}
	st, err := ov.Stats()
	if err != nil {
		return false, true
	}
	return st.DirtyNodes != 0 || st.DirtyEdges != 0, false
}

// serveBranches lists the volume's branches with enough for the page to
// show which is current and which has work.
//
// One refs.Fetch per branch, which is one round trip per branch and is
// deliberate rather than overlooked: the generation and head come from the
// VERIFIED ref (the pinned key, the rollback check), and a listing that
// reported a generation it had not verified would be a listing that could
// be lied to by the origin. Volumes have branches in the single digits;
// this is a drop-down, not a hot path.
func (b *browseServer) serveBranches(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	g := b.g
	b.mu.Unlock()
	if g == nil {
		writeBrowseJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the volume is still opening; the branch list is not available yet"})
		return
	}
	ctx := r.Context()
	names, err := g.refs.ListBranches(ctx)
	if err != nil {
		writeBrowseJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	cur := g.currentBranch()
	staged, _ := stagedForSwitch(g)
	out := branchList{Current: cur, Branches: make([]branchInfo, 0, len(names)+1)}
	found := false
	for _, n := range names {
		row := branchInfo{Name: n}
		if n == cur {
			found = true
			row.Staged = staged
		}
		if f, ferr := g.refs.Fetch(ctx, n); ferr != nil {
			row.Error = ferr.Error()
		} else {
			row.Generation = f.Superblock.Generation
			row.Head = headName(f.Raw)
		}
		out.Branches = append(out.Branches, row)
	}
	if !found {
		// The branch this session is ON is always in the list, even when
		// the listing did not turn it up — a ref deleted under a live
		// session, or a listing the origin truncated. `current` must name
		// a row or the picker has no value to render.
		out.Branches = append(out.Branches, branchInfo{
			Name: cur, Generation: g.gfs.Generation(), Staged: staged,
			Error: "this session is on it, but it is not in the volume's ref listing",
		})
	}
	writeBrowseJSON(w, http.StatusOK, out)
}

// headName is the generation's identity as a page shows it: the first eight
// bytes of the same BLAKE3 digest the format uses to chain generations
// (superblock.Hash, which is what the next generation's PrevHash holds). It
// is an identifier for a human to compare, not a credential.
func headName(raw []byte) string {
	h := superblock.Hash(raw)
	return hex.EncodeToString(h[:8])
}

// serveSwitchBranch accepts a switch, or explains why it will not.
//
// 202 and a job, never a synchronous 200: reopening a volume at another
// generation is not instant (genfs.Swap re-resolves every resident inode
// and fetches the incoming root catalog), and a request held open across it
// would give the page a spinner with nothing in it. The job is the SAME
// slot a publish takes, which is what makes the two mutually exclusive —
// they both hold g.mu for their whole duration, so a queue here would only
// be a longer wait wearing a different name.
func (b *browseServer) serveSwitchBranch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if err := refs.ValidateName(name); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	b.mu.Lock()
	g, ctx := b.g, b.ctx
	if g == nil {
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the volume is still opening; it cannot switch branches yet"})
		return
	}
	if b.job != nil && b.job.State == "running" {
		id := b.job.ID
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusConflict, map[string]string{
			"error":  "a publish is running; switching would strand it",
			"reason": "wait for the publish to finish, then switch",
			"job":    id})
		return
	}
	// The staged check is here AND again under g.mu inside the switch. Here
	// so the answer is a 409 the page can render rather than a job that
	// fails; there because a write can land between the two, and the one
	// that runs with the seal lock held is the one that decides.
	staged, busy := stagedForSwitch(g)
	if busy {
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusConflict, map[string]string{
			"error":  "the overlay is busy, so this session cannot say whether a switch would strand work",
			"reason": "try again in a moment"})
		return
	}
	if staged {
		b.mu.Unlock()
		writeBrowseJSON(w, http.StatusConflict, map[string]string{
			"error": "this session has work staged on " + g.currentBranch() + " that is not published yet",
			"reason": "publish or discard first — switching branches cannot carry it across, " +
				"and pelfs will not throw it away to make the switch possible"})
		return
	}
	job := &publishJob{ID: newJobID(), State: "running", Reason: "branch", Started: b.nowTime()}
	b.job = job
	b.publishWG.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.publishWG.Done()
		// The SESSION context, not the request's: a request context is
		// cancelled the moment the 202 is written, which would abort the
		// swap it just accepted.
		if ctx == nil {
			ctx = context.Background()
		}
		summary, err := b.switchBranch(ctx, g, name)
		b.finishJob(job, summary, err)
	}()
	b.nudge()
	writeBrowseJSON(w, http.StatusAccepted, map[string]any{
		"job": job.ID, "watch": "/events", "branch": name,
	})
}

// switchBranch is the whole operation, in the order failures must be able
// to leave things alone.
func (b *browseServer) switchBranch(ctx context.Context, g *genSession, name string) (string, error) {
	// The target, through the ordinary trust path — the pinned volume key
	// and the rollback check — and BEFORE g.mu, because it is a network
	// read and holding the seal lock across one would block the whole
	// session on the federation.
	f, err := g.refs.Fetch(ctx, name)
	if err != nil {
		return "", fmt.Errorf("branch %s: %w", name, err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	from := g.currentBranch()
	if from == name {
		return fmt.Sprintf("already on %s at generation %d", name, g.gfs.Generation()), nil
	}
	if g.spent {
		return "", errors.New("this session is shutting down")
	}
	// The staged check that decides, with the seal lock held so nothing can
	// stage between it and the swap.
	if g.ov != nil {
		st, serr := g.ov.Stats()
		if serr != nil {
			return "", fmt.Errorf("read the overlay before switching: %w", serr)
		}
		if st.DirtyNodes != 0 || st.DirtyEdges != 0 {
			return "", fmt.Errorf("work was staged on %s while the switch was starting; "+
				"publish or discard it first", from)
		}
	}

	// ---- 1. The lease, first, because its refusal is the one that must
	// change nothing. Acquired on the new branch BEFORE the old one is
	// released, so this session never holds neither.
	var taken *lease.Lease
	if g.lease != nil && g.leaseFor != nil {
		taken, err = g.leaseFor(ctx, name)
		if err != nil {
			return "", fmt.Errorf("cannot write branch %s: %w", name, err)
		}
	}
	abandon := func() {
		if taken != nil {
			taken.Release(context.WithoutCancel(ctx)) //nolint:errcheck
		}
	}

	// ---- 2. The swap. Nothing has been destroyed yet, so a refusal here
	// (a generation this session cannot read, a different volume) leaves
	// the session serving exactly what it was serving.
	if _, err := g.gfs.Swap(ctx, f.Superblock); err != nil {
		abandon()
		return "", fmt.Errorf("switch to %s: %w", name, err)
	}

	// ---- 3. The overlay: a new empty one over the new base. The old one
	// is provably empty (checked above, under this lock), so retiring it
	// discards nothing — and it is RETIRED rather than deleted, by the
	// same rename a seal uses, so a mistake in that reasoning would leave
	// the evidence in the trash rather than gone.
	if g.ov != nil {
		old := g.ov
		g.ovMu.Lock()
		g.ov = nil
		g.ovMu.Unlock()
		if cerr := old.Close(); cerr != nil {
			ui.Warn("closing the overlay before the branch switch: {error}", "error", cerr)
		}
		if rerr := g.retireDir(g.overlayDir); rerr != nil {
			ui.Warn("the spent overlay at {dir} could not be retired: {error}",
				"dir", g.overlayDir, "error", rerr)
		}
		ov, oerr := overlay.Open(g.overlayDir, g.gfs, overlay.Options{
			NextInode:      g.gfs.NextInode(),
			BaseRoot:       g.gfs.RootCatalog(),
			BaseGeneration: g.gfs.Generation(),
			Memtable:       g.content,
		})
		if oerr != nil {
			// The base has moved and there is no overlay to write onto. The
			// session can still READ (the binding below is rebuilt over the
			// base), and it says so rather than pretending: nothing was
			// staged, so nothing is lost, and a restart puts it right.
			abandon()
			b.rebind(g)
			return "", fmt.Errorf("switched the base to %s but could not open an overlay on it "+
				"(%w); this session is read-only until it is restarted — nothing was staged, "+
				"so nothing is lost", name, oerr)
		}
		g.ovMu.Lock()
		g.ov = ov
		g.ovMu.Unlock()
	}

	// ---- 4. The session is now on the new branch. Everything that names
	// the branch moves together, under this lock.
	released := g.lease
	g.sb, g.prevRaw = f.Superblock, f.Raw
	if taken != nil {
		g.lease = taken
	}
	g.setBranch(name)
	g.stats.Update(func(sum *stats.Summary) {
		sum.Branch = name
		sum.Generation = f.Superblock.Generation
		if taken != nil {
			sum.LeaseKey = taken.Key()
		}
	})

	// ---- 5. Rebind, so the WebDAV handler, the JSON data plane and the
	// durability panel are all looking at what the session is looking at.
	b.rebind(g)

	// ---- 6. And only now the old branch's lease goes.
	if taken != nil && released != nil {
		if rerr := released.Release(context.WithoutCancel(ctx)); rerr != nil {
			ui.Warn("switched to {branch}, but the lease on {old} could not be released "+
				"({error}); it expires on its own", "branch", name, "old", from, "error", rerr)
		}
	}
	ui.Info("switched from branch {from} to {to} at generation {generation}",
		"from", from, "to", name, "generation", f.Superblock.Generation)
	return fmt.Sprintf("on %s at generation %d", name, f.Superblock.Generation), nil
}

// rebind rebuilds the surfaces that hold a filesystem, which is setReady's
// job and is therefore setReady.
//
// A READ-ONLY session does not strictly need it — its binding wraps
// *genfs.FS by pointer and genfs.Swap mutates that object in place, so the
// WebDAV handler and the JSON data plane are already serving the new
// generation the instant the swap returns. It is called anyway, for both
// kinds of session, because "which sessions need a rebind" is a fact about
// two other packages' internals and a switch that skipped it for one of
// them would be a stale binding waiting for the day that stops being true.
func (b *browseServer) rebind(g *genSession) {
	b.mu.Lock()
	ctx := b.ctx
	b.mu.Unlock()
	b.setReady(g, ctx)
}

// registerBranchRoutes puts both on the page's own surface: the session
// header is required, an Authorization header is refused, and a WebDAV
// client can reach neither. Switching branches under a bookmark's
// credential is not a thing this design offers — the two principals rule
// (see routes) is what says so.
func (b *browseServer) registerBranchRoutes(r *httpguard.Router) {
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/branches", b.serveBranches)
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/branch", b.serveSwitchBranch)
}
