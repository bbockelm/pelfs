//go:build hostile

package hostile

// The EXECUTOR: it applies a hostile plan to a REAL pelfs mount and to a
// reference tree on tmpfs, and demands they stay identical.
//
// CONTAINMENT IS MANDATORY AND LAYERED. This code generates adversarial
// filesystem operations at concurrency; escaped, it destroys a working
// directory. Six independent layers stand between it and anything real,
// and each one is sufficient on its own:
//
//   1. BUILD TAG. This file only compiles under `hostile`, so no ordinary
//      `go build`, `go vet` or `go test ./...` can even link it. It is a
//      _test.go file as well, so product code cannot import it at all.
//   2. ENV GATE. It skips unless PELFS_HOSTILE_CONTAINED=1, which only
//      scripts/hostile-docker.sh sets, and only inside the container.
//   3. IMAGE SENTINEL. It refuses unless /etc/pelfs-hostile-container
//      exists — a file that exists only in the image the launcher builds.
//      Being in *a* container is not enough; it must be THE container.
//   4. NO WRITABLE HOST PATH EXISTS. The container mounts the staged
//      binaries read-only and nothing else. Every writable byte is on a
//      tmpfs that dies with the container, so even total escape from
//      every check below can only damage the container's own scratch.
//   5. os.Root. Every path operation the harness performs goes through an
//      os.Root handle rooted at the sandbox, so a symlink aimed at
//      /etc/passwd or a path full of ".." cannot be followed out — and
//      the vocabulary deliberately generates both, which is how we know
//      the confinement is load-bearing rather than decorative.
//   6. NEGATIVE ASSERTION. requireContainment proves escape is impossible
//      rather than assuming it: it creates a symlink to the host root and
//      to "../../.." and requires os.Root to refuse both. A build of Go
//      whose os.Root stopped confining would fail here, not silently
//      write to /.
//
// Run: scripts/hostile-docker.sh

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------- layer 1-3+6

// requireContainment is the gate. It returns the sandbox directory, inside
// which everything else happens.
func requireContainment(tb testing.TB) string {
	tb.Helper()
	if os.Getenv("PELFS_HOSTILE_CONTAINED") != "1" {
		tb.Skip("the hostile exerciser runs ONLY inside its containment launcher: scripts/hostile-docker.sh")
	}
	// Layer 3: THE container, not merely a container. The launcher bakes
	// this file into the image it builds; a stray `docker run debian` would
	// not have it, and neither does any host.
	const sentinel = "/etc/pelfs-hostile-container"
	if _, err := os.Stat(sentinel); err != nil {
		tb.Fatalf("containment: %s is absent, so this is not the purpose-built container: %v", sentinel, err)
	}
	// A host that has a home directory tree is not a container we built.
	// Cheap, and it is the exact mistake worth being loud about.
	for _, forbidden := range []string{"/Users", "/home/runner/work"} {
		if _, err := os.Stat(forbidden); err == nil {
			tb.Fatalf("containment: %s is visible; this is not the sealed container", forbidden)
		}
	}
	sandbox := os.Getenv("PELFS_HOSTILE_SANDBOX")
	if sandbox == "" {
		tb.Fatal("containment: PELFS_HOSTILE_SANDBOX is unset")
	}
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		tb.Fatalf("sandbox: %v", err)
	}
	// Layer 4, asserted: the sandbox must be on a tmpfs. If a future edit
	// to the launcher ever bind-mounted a host directory here, this is
	// what would notice.
	var st syscall.Statfs_t
	if err := syscall.Statfs(sandbox, &st); err != nil {
		tb.Fatalf("statfs %s: %v", sandbox, err)
	}
	const tmpfsMagic = 0x01021994
	if st.Type != tmpfsMagic {
		tb.Fatalf("containment: sandbox %s is on filesystem type 0x%x, not tmpfs (0x%x); "+
			"the launcher must give this container nothing writable but tmpfs",
			sandbox, st.Type, tmpfsMagic)
	}
	proveOsRootConfines(tb, sandbox)
	return sandbox
}

// proveOsRootConfines is layer 6. Containment by os.Root is the claim that
// lets this harness create symlinks pointing at /etc/passwd on purpose, so
// the claim is TESTED, here, before a single hostile op runs.
func proveOsRootConfines(tb testing.TB, sandbox string) {
	tb.Helper()
	dir := path.Join(sandbox, "containment-proof")
	if err := os.RemoveAll(dir); err != nil {
		tb.Fatalf("proof: clear: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("proof: mkdir: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		tb.Fatalf("proof: OpenRoot: %v", err)
	}
	defer root.Close() //nolint:errcheck

	// Creating a hostile link is allowed (os.Root does not validate a link
	// target), and must be: the vocabulary generates these.
	for name, target := range map[string]string{
		"abs":     "/etc/passwd",
		"climb":   "../../../../../../etc/passwd",
		"absroot": "/",
	} {
		if err := root.Symlink(target, name); err != nil {
			tb.Fatalf("proof: could not create the link %s -> %s that the vocabulary needs: %v", name, target, err)
		}
		// FOLLOWING it must fail. This is the whole guarantee.
		if f, err := root.Open(name); err == nil {
			f.Close() //nolint:errcheck
			tb.Fatalf("CONTAINMENT BROKEN: os.Root followed %s -> %s out of the sandbox", name, target)
		}
		if err := root.WriteFile(name+"/x", []byte("no"), 0o600); err == nil {
			tb.Fatalf("CONTAINMENT BROKEN: os.Root wrote THROUGH %s -> %s", name, target)
		}
		// Readlink must still report it verbatim: the harness has to be
		// able to compare link targets without following them.
		if got, err := root.Readlink(name); err != nil || got != target {
			tb.Fatalf("proof: readlink %s = %q, %v; want %q", name, got, err, target)
		}
	}
	// And a plain ".." path, which is a different code path from a symlink.
	if _, err := root.Stat("../../../etc/passwd"); err == nil {
		tb.Fatal("CONTAINMENT BROKEN: os.Root resolved a .. path out of the sandbox")
	}
	if err := os.RemoveAll(dir); err != nil {
		tb.Fatalf("proof: cleanup: %v", err)
	}
	tb.Log("containment proven: os.Root refuses absolute targets, climbing targets and .. paths")
}

// ---------------------------------------------------------------- the two trees

// tree is one side of the comparison — either the pelfs mount or the tmpfs
// reference — reached only through an os.Root.
type tree struct {
	label string
	dir   string
	root  *os.Root
	// setTimes records the mtime an OpUtimes asked for, per path. Only
	// these paths have their mtime compared: comparing it everywhere would
	// flag the microseconds between creating a file on one tree and the
	// other, which is noise, not a bug.
	setTimes map[string]int64
}

func openTree(tb testing.TB, label, dir string) *tree {
	tb.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		tb.Fatalf("open %s tree at %s: %v", label, dir, err)
	}
	return &tree{label: label, dir: dir, root: root, setTimes: map[string]int64{}}
}

func (t *tree) close() {
	if t.root != nil {
		t.root.Close() //nolint:errcheck
		t.root = nil
	}
}

// reopen is needed after a kill -9: the old handle names a dead mount.
func (t *tree) reopen(tb testing.TB) {
	tb.Helper()
	t.close()
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		tb.Fatalf("reopen %s tree at %s: %v", t.label, t.dir, err)
	}
	t.root = root
}

// bodyOf is the bytes one write puts down. The generation itself is in
// plan.go — pure, untagged, and unit-tested against the volume's real
// codec in the ordinary lane — because the claim the fill kinds make
// (that a fill=text body is something zstd shrinks and a fill=NN body is
// not) is the whole reason they exist, and a claim only checkable inside
// a container is a claim nobody checks.
func bodyOf(op Op, off, n int64) []byte { return Body(op.FillKind, op.Fill, off, n) }

// apply performs one op. The error it returns is COMPARED between the two
// trees, never acted on: a divergence in whether an operation succeeded is
// precisely the bug class this exists to find (the reported symlink bug is
// exactly "the reference tree unlinked it and the mount said ENOENT").
func (t *tree) apply(op Op) error {
	r := t.root
	switch op.Kind {
	case OpCreate:
		f, err := r.OpenFile(op.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if op.Len > 0 {
			if _, err := f.Write(bodyOf(op, 0, op.Len)); err != nil {
				f.Close() //nolint:errcheck
				return err
			}
		}
		return f.Close()
	case OpMkdir:
		mode := os.FileMode(op.Mode)
		if mode == 0 {
			mode = 0o755
		}
		return r.Mkdir(op.Path, mode)
	case OpSymlink:
		return r.Symlink(op.Path2, op.Path)
	case OpUnlink:
		// Remove refuses a directory here on purpose: unlink and rmdir are
		// different operations and a filesystem must distinguish them.
		fi, err := r.Lstat(op.Path)
		if err == nil && fi.IsDir() {
			return &os.PathError{Op: "unlink", Path: op.Path, Err: syscall.EISDIR}
		}
		return r.Remove(op.Path)
	case OpRmdir:
		fi, err := r.Lstat(op.Path)
		if err == nil && !fi.IsDir() {
			return &os.PathError{Op: "rmdir", Path: op.Path, Err: syscall.ENOTDIR}
		}
		return r.Remove(op.Path)
	case OpRename:
		return r.Rename(op.Path, op.Path2)
	case OpLink:
		return r.Link(op.Path, op.Path2)
	case OpPwrite:
		f, err := r.OpenFile(op.Path, os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, werr := f.WriteAt(bodyOf(op, op.Off, op.Len), op.Off)
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		return cerr
	case OpTruncate:
		f, err := r.OpenFile(op.Path, os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		terr := f.Truncate(op.Size)
		cerr := f.Close()
		if terr != nil {
			return terr
		}
		return cerr
	case OpChmod:
		return r.Chmod(op.Path, os.FileMode(op.Mode))
	case OpChown:
		return r.Lchown(op.Path, op.UID, op.GID)
	case OpUtimes:
		ts := time.Unix(op.MTime, 0)
		if err := r.Chtimes(op.Path, ts, ts); err != nil {
			return err
		}
		t.setTimes[op.Path] = op.MTime
		return nil
	case OpRmrf:
		return t.rmrf(op.Path)
	case OpReaddirMutate:
		return t.readdirMutate(op.Path, op.Count)
	}
	return fmt.Errorf("executor does not implement %s", op.Kind)
}

// rmrf is rm -rf, deliberately: SORTED order, and ENOENT on an unlink
// treated as "someone else got there first" and skipped. Both details are
// load-bearing. Sorted order is what put the shared symlink target ahead
// of the links naming it; ENOENT-tolerance is what turned a REMOVE that
// refused to unlink into a silent survivor instead of an error. A cleverer
// recursive delete would not have found the bug, so this one is not
// clever.
func (t *tree) rmrf(p string) error {
	fi, err := t.root.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // rm -rf is happy about an absent operand
		}
		return err
	}
	if fi.IsDir() {
		names, err := t.readdirnames(p)
		if err != nil {
			return err
		}
		for _, name := range SortedNames(names) {
			if err := t.rmrf(path.Join(p, name)); err != nil {
				return err
			}
		}
	}
	if err := t.root.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // exactly what rm(1) does, and why the bug was silent
		}
		// "directory not empty" after a full sorted sweep is the reported
		// bug's signature, and on its own it is not a diagnosis: the
		// question is always WHICH entries survived, because that is what
		// says whether the sweep SKIPPED them (a readdir that handed back
		// an incomplete listing) or tried and failed to remove them.
		// Re-list and say so, or this finding costs someone an afternoon.
		if errors.Is(err, syscall.ENOTEMPTY) {
			if left, lerr := t.readdirnames(p); lerr == nil {
				return fmt.Errorf("%w -- after a full sorted rm -rf sweep, %d entries survive in "+
					"%s: %s (the sweep removed everything the listing named, so the listing it "+
					"was given was incomplete)",
					err, len(left), p, summarize(SortedNames(left)))
			}
		}
		return err
	}
	return nil
}

func (t *tree) readdirnames(p string) ([]string, error) {
	f, err := t.root.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return f.Readdirnames(-1)
}

// readdirMutate enumerates a directory in PAGES while mutating it between
// them: the only shape in which a positional readdir cookie can be caught
// shifting entries a client has not been shown yet. The mutations are
// derived from the sorted listing, so both trees do the same thing.
//
// What it asserts about the enumeration itself is only what POSIX
// guarantees — an entry added or removed during a scan may or may not be
// seen — so: no duplicates, no entry that never existed, and it
// terminates. Whether the two trees AGREE is decided afterwards, by the
// ordinary comparison over the final listing.
func (t *tree) readdirMutate(dir string, disturb int) error {
	before, err := t.readdirnames(dir)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, n := range before {
		known[n] = true
	}
	victims := SortedNames(before)
	if disturb > len(victims) {
		disturb = len(victims)
	}

	f, err := t.root.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	seen := map[string]bool{}
	removedOK := map[string]bool{}
	pages, mutated := 0, 0
	for {
		page, err := f.Readdirnames(64)
		for _, n := range page {
			if seen[n] {
				return fmt.Errorf("readdir over %s returned %q twice in one scan", dir, n)
			}
			seen[n] = true
			if !known[n] && !strings.HasPrefix(n, "added-") {
				return fmt.Errorf("readdir over %s returned %q, which never existed", dir, n)
			}
		}
		if err == io.EOF || len(page) == 0 {
			break
		}
		if err != nil {
			return fmt.Errorf("readdir page %d over %s: %w", pages, dir, err)
		}
		pages++
		if pages > 100000 {
			return fmt.Errorf("readdir over %s did not terminate", dir)
		}
		// Mutate between pages: remove one victim and add one entry.
		if mutated < disturb {
			v := victims[mutated]
			if err := t.root.Remove(path.Join(dir, v)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("mid-enumeration unlink of %s: %w", v, err)
			}
			add := fmt.Sprintf("added-%05d", mutated)
			if err := t.root.WriteFile(path.Join(dir, add), nil, 0o644); err != nil {
				return fmt.Errorf("mid-enumeration create of %s: %w", add, err)
			}
			known[add] = true
			mutated++
			removedOK[v] = true
		}
	}

	// COMPLETENESS, checked here rather than left for a later rm -rf to
	// trip over. POSIX lets a scan miss an entry added or removed DURING
	// it, so the scan itself is not held to a set -- but afterwards the
	// directory has an exact one: everything that was there, minus what
	// this function removed, plus what it added. A fresh listing that does
	// not match it has lost entries that nothing touched, and that is a
	// bug at its source rather than three ops downstream.
	after, err := t.readdirnames(dir)
	if err != nil {
		return fmt.Errorf("post-enumeration listing of %s: %w", dir, err)
	}
	want := map[string]bool{}
	for n := range known {
		if !removedOK[n] {
			want[n] = true
		}
	}
	got := map[string]bool{}
	for _, n := range after {
		got[n] = true
	}
	var lost, extra []string
	for n := range want {
		if !got[n] {
			lost = append(lost, n)
		}
	}
	for n := range got {
		if !want[n] {
			extra = append(extra, n)
		}
	}
	if len(lost) > 0 || len(extra) > 0 {
		return fmt.Errorf("after enumerating %s with %d mutations, the directory should hold %d "+
			"entries and holds %d: %d lost %s, %d unexpected %s",
			dir, mutated, len(want), len(after),
			len(lost), summarize(SortedNames(lost)), len(extra), summarize(SortedNames(extra)))
	}
	return nil
}

// ---------------------------------------------------------------- comparison

// node is everything about one path that both trees must agree on.
type node struct {
	kind    byte // 'f', 'd', 'l'
	size    int64
	perm    os.FileMode
	nlink   uint64
	uid     uint32
	gid     uint32
	target  string // symlinks
	entries []string
}

func (t *tree) statNode(p string) (node, error) {
	fi, err := t.root.Lstat(p)
	if err != nil {
		return node{}, err
	}
	n := node{size: fi.Size(), perm: fi.Mode().Perm()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		n.nlink, n.uid, n.gid = uint64(st.Nlink), st.Uid, st.Gid
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		n.kind = 'l'
		n.target, err = t.root.Readlink(p)
		if err != nil {
			return node{}, err
		}
		n.size = 0 // a symlink's st_size is its target length on some fs
	case fi.IsDir():
		n.kind = 'd'
		n.size = 0 // a directory's size is an implementation detail
		n.nlink = 0
		names, err := t.readdirnames(p)
		if err != nil {
			return node{}, err
		}
		n.entries = SortedNames(names)
	default:
		n.kind = 'f'
	}
	return n, nil
}

// compareTrees walks both sides and demands identical structure, metadata
// and bytes. `mode` is exact for a live or sealed comparison; after a
// SIGKILL it is subset, where the mount is allowed to be MISSING content
// (a crashed session may lose unsealed writes) but is never allowed to
// hold content that is present and WRONG — silently short or zero-filled
// is the failure a user cannot detect.
type compareMode int

const (
	compareExact compareMode = iota
	compareSubsetAfterCrash
)

type comparison struct {
	tb          testing.TB
	mnt, ref    *tree
	mode        compareMode
	permPaths   map[string]bool
	attributed  []string
	attributeTo string
	problems    []string
	files       int
	missing     []string
	unreadable  int
}

// failf records a disagreement -- unless the path is one an already-reported
// permission divergence explains, in which case it is ATTRIBUTED to that
// finding instead. Attribution is per-path and shows up in the run's
// summary line, so it can be read and disbelieved; it is not a silence.
func (c *comparison) failf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if c.attributeTo != "" {
		c.attributed = append(c.attributed, msg)
		return
	}
	c.problems = append(c.problems, msg)
}

// attributeTo is set for the duration of one node's comparison when that
// node is downstream of a reported permission divergence.
func (c *comparison) explainedBy(p string) string {
	for pp := range c.permPaths {
		if p == pp || strings.HasPrefix(p, pp+"/") {
			return pp
		}
	}
	return ""
}

type compareResult struct {
	files      int
	unreadable int
	missing    []string
	problems   []string
	attributed []string
}

func compareTrees(tb testing.TB, mnt, ref *tree, mode compareMode, permPaths map[string]bool) compareResult {
	c := &comparison{tb: tb, mnt: mnt, ref: ref, mode: mode, permPaths: permPaths}
	c.walk(".")
	return compareResult{
		files: c.files, unreadable: c.unreadable, missing: c.missing,
		problems: c.problems, attributed: c.attributed,
	}
}

func (c *comparison) walk(p string) {
	if len(c.problems) > 40 {
		return // enough; the first ones are the diagnosis
	}
	// If this node is downstream of a permission divergence already
	// reported for this run, its differences are that finding's
	// consequence. Scoped to this node and restored on the way out.
	prev := c.attributeTo
	c.attributeTo = c.explainedBy(p)
	defer func() { c.attributeTo = prev }()

	rn, rerr := c.ref.statNode(p)
	mn, merr := c.mnt.statNode(p)

	if rerr != nil {
		if merr == nil {
			c.failf("%s: present in the mount, absent from the reference (%v)", p, rerr)
		}
		return
	}
	if merr != nil {
		if c.mode == compareSubsetAfterCrash && errors.Is(merr, os.ErrNotExist) {
			c.missing = append(c.missing, p)
			return
		}
		c.failf("%s: absent from the mount (%v), present in the reference as %c", p, merr, rn.kind)
		return
	}
	if mn.kind != rn.kind {
		c.failf("%s: mount says type %c, reference says %c", p, mn.kind, rn.kind)
		return
	}
	if mn.perm != rn.perm {
		c.failf("%s: mode %04o in the mount, %04o in the reference", p, mn.perm, rn.perm)
	}
	if mn.uid != rn.uid || mn.gid != rn.gid {
		c.failf("%s: owner %d:%d in the mount, %d:%d in the reference", p, mn.uid, mn.gid, rn.uid, rn.gid)
	}
	// mtime, but only where an op set it explicitly: see tree.setTimes.
	if want, ok := c.ref.setTimes[p]; ok {
		if got := c.mtime(c.mnt, p); got != want {
			c.failf("%s: utimes set mtime=%d, the mount reports %d", p, want, got)
		}
	}

	switch mn.kind {
	case 'l':
		if mn.target != rn.target {
			c.failf("%s: link target %q in the mount, %q in the reference", p, mn.target, rn.target)
		}
	case 'f':
		if mn.nlink != rn.nlink {
			c.failf("%s: nlink %d in the mount, %d in the reference", p, mn.nlink, rn.nlink)
		}
		if mn.size != rn.size {
			c.failf("%s: %d bytes in the mount, %d in the reference", p, mn.size, rn.size)
			return
		}
		c.files++
		c.compareBytes(p, rn.size)
	case 'd':
		if strings.Join(mn.entries, "\x00") != strings.Join(rn.entries, "\x00") {
			c.failf("%s: entries differ\n    mount:     %s\n    reference: %s",
				p, summarize(mn.entries), summarize(rn.entries))
			// Still descend into the intersection: the first differing
			// directory is rarely the whole story.
		}
		for _, name := range rn.entries {
			c.walk(path.Join(p, name))
		}
	}
}

func (c *comparison) mtime(t *tree, p string) int64 {
	fi, err := t.root.Lstat(p)
	if err != nil {
		return -1
	}
	return fi.ModTime().Unix()
}

// compareBytes reads both files in chunks and reports the FIRST differing
// offset, because "differs" is not a diagnosis and an offset is: a hole
// that came back as data, or data that came back as a hole, names itself.
func (c *comparison) compareBytes(p string, size int64) {
	mf, merr := c.mnt.root.Open(p)
	rf, rerr := c.ref.root.Open(p)
	defer func() {
		if mf != nil {
			mf.Close() //nolint:errcheck
		}
		if rf != nil {
			rf.Close() //nolint:errcheck
		}
	}()
	// The vocabulary sets modes that forbid its own reads (chmod 0400 on a
	// file then chown'd away), so "cannot open" is an expected answer -- but
	// only when it is the answer on BOTH sides. Refused on both: metadata
	// was already compared above and the content is simply out of reach.
	// Refused on ONE: that is a permission divergence, and the direction
	// matters, so say which side let us in.
	if merr != nil || rerr != nil {
		bothPerm := errors.Is(merr, os.ErrPermission) && errors.Is(rerr, os.ErrPermission)
		switch {
		case bothPerm:
			c.unreadable++
		case merr != nil && rerr == nil:
			c.failf("%s: readable in the reference, refused by the mount (%v)", p, merr)
		case rerr != nil && merr == nil:
			c.failf("%s: refused by the reference (%v) but READABLE in the mount "+
				"-- the frontend is not enforcing the mode bits (known-open finding)", p, rerr)
		default:
			c.failf("%s: unreadable on both sides for different reasons: mount %v, reference %v", p, merr, rerr)
		}
		return
	}

	const chunk = 128 << 10
	mb, rb := make([]byte, chunk), make([]byte, chunk)
	var off int64
	for off < size {
		mn, merr := io.ReadFull(mf, mb[:min64(chunk, size-off)])
		rn, rerr := io.ReadFull(rf, rb[:min64(chunk, size-off)])
		if merr != nil && merr != io.EOF && merr != io.ErrUnexpectedEOF {
			c.failf("%s: read at %d in the mount: %v", p, off, merr)
			return
		}
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			c.failf("%s: read at %d in the reference: %v", p, off, rerr)
			return
		}
		if mn != rn {
			c.failf("%s: short read at %d: %d bytes from the mount, %d from the reference", p, off, mn, rn)
			return
		}
		if !bytes.Equal(mb[:mn], rb[:rn]) {
			for i := 0; i < mn; i++ {
				if mb[i] != rb[i] {
					c.failf("%s: byte %d is 0x%02x in the mount, 0x%02x in the reference%s",
						p, off+int64(i), mb[i], rb[i], holeHint(mb[i], rb[i]))
					return
				}
			}
		}
		if mn == 0 {
			break
		}
		off += int64(mn)
	}
}

// holeHint labels the two failures that actually happen, so the message
// says what went wrong rather than only that something did.
func holeHint(got, want byte) string {
	switch {
	case got == 0 && want != 0:
		return " (a hole where there should be data: a lost extent)"
	case got != 0 && want == 0:
		return " (data where there should be a hole: an extent naming bytes past a truncate)"
	}
	return ""
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func summarize(names []string) string {
	if len(names) <= 12 {
		return "[" + strings.Join(names, " ") + "]"
	}
	return fmt.Sprintf("[%s ... %s] (%d entries)",
		strings.Join(names[:6], " "), strings.Join(names[len(names)-3:], " "), len(names))
}

// ---------------------------------------------------------------- the mount

// rig owns the processes: a fakeorigin on loopback and a pelfs mount.
type rig struct {
	tb        testing.TB
	sandbox   string
	pelfs     string
	forigin   string
	prefix    string
	port      int
	originC   *exec.Cmd
	mountC    *exec.Cmd
	mountDone chan error
	mountLog  string
	mnt       string
	// keyArgs is `--encrypt-key PATH` when this run is against an
	// ENCRYPTED volume, and empty otherwise. It goes in front of every
	// pelfs invocation the rig makes, because the key is needed by all of
	// them: init wraps it, a mount unwraps it, and fsck cannot read a
	// chunk without it.
	keyArgs []string
}

func newRig(tb testing.TB, sandbox, name string, port int) *rig {
	tb.Helper()
	r := &rig{
		tb:      tb,
		sandbox: sandbox,
		pelfs:   envOr("PELFS_HOSTILE_PELFS", "/stage/pelfs"),
		forigin: envOr("PELFS_HOSTILE_FAKEORIGIN", "/stage/fakeorigin"),
		port:    port,
	}
	if encryptedRun() {
		r.keyArgs = []string{"--encrypt-key", volumeKeyFile(tb, sandbox)}
	}
	for _, bin := range []string{r.pelfs, r.forigin} {
		if _, err := os.Stat(bin); err != nil {
			tb.Fatalf("staged binary %s is missing: %v", bin, err)
		}
	}
	base := path.Join(sandbox, name)
	if err := os.MkdirAll(path.Join(base, "origin"), 0o755); err != nil {
		tb.Fatalf("mkdir origin: %v", err)
	}
	r.prefix = fmt.Sprintf("http://127.0.0.1:%d/vol", port)

	r.originC = exec.Command(r.forigin, "-listen", fmt.Sprintf("127.0.0.1:%d", port),
		"-root", path.Join(base, "origin"))
	olog, err := os.Create(path.Join(base, "origin.log"))
	if err != nil {
		tb.Fatalf("origin log: %v", err)
	}
	r.originC.Stdout, r.originC.Stderr = olog, olog
	if err := r.originC.Start(); err != nil {
		tb.Fatalf("start fakeorigin: %v", err)
	}
	tb.Cleanup(func() {
		if r.originC.Process != nil {
			r.originC.Process.Kill() //nolint:errcheck
			r.originC.Wait()         //nolint:errcheck
		}
		olog.Close() //nolint:errcheck
	})
	// Readiness: the volume-create below would fail confusingly otherwise.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close() //nolint:errcheck
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	tb.Fatalf("fakeorigin did not listen on %d:\n%s", port, indent(readAll(path.Join(base, "origin.log"))))
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ------------------------------------------------------- encrypted volumes

// encryptedRun reports whether this container was launched with
// scripts/hostile-docker.sh --encrypt.
//
// WHY THE VARIANT EXISTS. Everything above this line is about the
// filesystem; encryption is about what the filesystem's bytes turn into
// on the way to an object, and the two interact in one specific place
// that has already produced a released bug. A chunk is COMPRESSED AND
// THEN ENCRYPTED, so the entry in the pack is never the length of the
// plaintext on an encrypted volume — a nonce and a GCM tag are always
// added, whatever the compressor decided. That makes the encrypted leg
// the strongest form of the same question the fill kinds ask: a catalog
// row that copies its numbers from the plaintext in hand is wrong for
// EVERY chunk here, not only for the compressible ones.
//
// It is a switch rather than the default because the default gate is
// budgeted in seconds and this doubles the packer's work per byte.
func encryptedRun() bool { return os.Getenv("PELFS_HOSTILE_ENCRYPT") == "1" }

// volumeKeyFile mints the RSA key that wraps the volume's data keys, once
// per container, on the sandbox tmpfs. It is generated here rather than
// staged from the host for the same reason the corpus travels as data:
// the container must not need anything of the developer's, and a key that
// dies with the container cannot be reused against anything real.
func volumeKeyFile(tb testing.TB, sandbox string) string {
	tb.Helper()
	p := path.Join(sandbox, "volume-key.pem")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate the volume key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		tb.Fatalf("write the volume key: %v", err)
	}
	tb.Logf("ENCRYPTED RUN: volume keys are wrapped by a throwaway RSA key at %s. "+
		"Every chunk is compressed and then sealed, so no entry in any pack is the length "+
		"of its plaintext.", p)
	return p
}

// run executes a pelfs subcommand to completion and returns its output.
// The subcommand comes first and the key flag after it, which is the
// order pelfs's per-command flag sets require.
func (r *rig) run(args ...string) (string, error) {
	if len(r.keyArgs) > 0 && len(args) > 0 {
		args = append(append(append([]string{}, args[0]), r.keyArgs...), args[1:]...)
	}
	cmd := exec.Command(r.pelfs, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// runWithoutKey is run with the volume key deliberately withheld: on an
// encrypted volume it must FAIL, and that failure is the proof the leg is
// testing what it says it is.
func (r *rig) runWithoutKey(args ...string) (string, error) {
	cmd := exec.Command(r.pelfs, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// mustRun fails the test with the command's own output, which is the only
// thing that ever explains a pelfs failure.
func (r *rig) mustRun(what string, args ...string) string {
	r.tb.Helper()
	out, err := r.run(args...)
	if err != nil {
		r.tb.Fatalf("%s failed: %v\n  pelfs %s\n%s", what, err, strings.Join(args, " "), indent(out))
	}
	return out
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// startMount brings up a writable mount in the background and waits for
// the kernel to actually have it. Readiness is st_dev differing from the
// parent directory's, which is true for FUSE and for the loopback NFS
// client alike — a file appearing is not available on a fresh volume,
// whose root is legitimately empty.
func (r *rig) startMount(backend, stateDir, mnt string, snapshot time.Duration, logName string) {
	r.tb.Helper()
	args := []string{"mount-gen"}
	if backend != "" {
		args = append(args, "--backend", backend)
	}
	args = append(args, "--rw", "--no-lease",
		"--snapshot-interval", snapshot.String(),
		"--state-dir", stateDir, r.prefix, mnt)
	r.startMountArgs(args, mnt, logName)
}

// startReadOnlyMount is the cold-remount form: a FRESH state dir, no --rw.
// A fresh state dir can mount and read but cannot seal (the volume signing
// key lives in the state dir), which is exactly why a cold check is
// read-only.
func (r *rig) startReadOnlyMount(backend, stateDir, mnt, logName string) {
	r.tb.Helper()
	args := []string{"mount-gen"}
	if backend != "" {
		args = append(args, "--backend", backend)
	}
	args = append(args, "--state-dir", stateDir, r.prefix, mnt)
	r.startMountArgs(args, mnt, logName)
}

func (r *rig) startMountArgs(args []string, mnt, logName string) {
	r.tb.Helper()
	if err := r.tryStartMountArgs(args, mnt, logName); err != nil {
		r.tb.Fatal(err.Error())
	}
}

// tryStartMountArgs is startMountArgs for a caller that has something to
// say about a mount REFUSING TO START, rather than only about what a
// running mount serves. A mount that will not come up is a finding in its
// own right -- it is the whole volume, not one file -- and phase C2 found
// one, so it must be reportable through the campaign's own channel
// instead of killing the run from inside the rig.
func (r *rig) tryStartMountArgs(args []string, mnt, logName string) error {
	r.tb.Helper()
	if len(r.keyArgs) > 0 {
		args = append(append(append([]string{}, args[0]), r.keyArgs...), args[1:]...)
	}
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		r.tb.Fatalf("mkdir mountpoint: %v", err)
	}
	logPath := path.Join(r.sandbox, logName)
	lf, err := os.Create(logPath)
	if err != nil {
		r.tb.Fatalf("mount log: %v", err)
	}
	cmd := exec.Command(r.pelfs, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		r.tb.Fatalf("start mount: %v", err)
	}
	// One reaper per process, owned here: the readiness loop below and
	// stopAndSeal both need to know whether it has exited, and two callers
	// of cmd.Wait() is a race that shows up as a stuck test.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	r.mountC, r.mountDone, r.mountLog, r.mnt = cmd, done, logPath, mnt

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if isMountpoint(mnt) {
			r.tb.Logf("mounted: pelfs %s", strings.Join(args, " "))
			return nil
		}
		select {
		case err := <-done:
			// A dead process will never mount; report with its own words.
			r.mountC, r.mountDone = nil, nil
			return fmt.Errorf("the mount process exited (%v) before it mounted:\n  pelfs %s\n%s",
				err, strings.Join(args, " "), indent(readAll(logPath)))
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the mount did not come up within 90s:\n  pelfs %s\n%s",
		strings.Join(args, " "), indent(readAll(logPath)))
}

// tryStartMount is startMount for the same caller.
func (r *rig) tryStartMount(backend, stateDir, mnt string, snapshot time.Duration, logName string) error {
	r.tb.Helper()
	args := []string{"mount-gen"}
	if backend != "" {
		args = append(args, "--backend", backend)
	}
	args = append(args, "--rw", "--no-lease",
		"--snapshot-interval", snapshot.String(),
		"--state-dir", stateDir, r.prefix, mnt)
	return r.tryStartMountArgs(args, mnt, logName)
}

// isMountpoint compares st_dev against the parent's, which is what
// mountpoint(1) does and works for every backend.
func isMountpoint(p string) bool {
	var here, up syscall.Stat_t
	if err := syscall.Lstat(p, &here); err != nil {
		return false
	}
	if err := syscall.Lstat(path.Dir(p), &up); err != nil {
		return false
	}
	return here.Dev != up.Dev
}

func readAll(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	return string(b)
}

// stopAndSeal is the ordinary end of a session: SIGTERM, which pelfs
// handles by unmounting and sealing the overlay into the next generation.
func (r *rig) stopAndSeal() string {
	r.tb.Helper()
	if r.mountC == nil {
		return ""
	}
	if err := r.mountC.Process.Signal(syscall.SIGTERM); err != nil {
		r.tb.Fatalf("SIGTERM the mount: %v", err)
	}
	select {
	case <-r.mountDone:
	case <-time.After(5 * time.Minute):
		// A stuck seal is a real failure mode and the log names the phase
		// it is stuck in, so print it rather than letting the job cap kill
		// the runner with no evidence.
		r.tb.Fatalf("the mount did not exit within 5m of SIGTERM:\n%s", indent(readAll(r.mountLog)))
	}
	log := readAll(r.mountLog)
	r.mountC, r.mountDone = nil, nil
	r.forceUnmount()
	return log
}

// kill9 is the crash: SIGKILL with no chance to flush, then the forced
// detach a dead FUSE server leaves behind.
func (r *rig) kill9() {
	r.tb.Helper()
	if r.mountC == nil {
		return
	}
	if err := r.mountC.Process.Kill(); err != nil {
		r.tb.Fatalf("SIGKILL the mount: %v", err)
	}
	select {
	case <-r.mountDone:
	case <-time.After(30 * time.Second):
		r.tb.Fatalf("the mount survived SIGKILL for 30s, which is not possible unless it is a zombie")
	}
	r.mountC, r.mountDone = nil, nil
	r.forceUnmount()
}

// forceUnmount detaches whatever is still attached. Every step is
// best-effort: "not mounted" is the desired outcome, not an error.
func (r *rig) forceUnmount() {
	if r.mnt == "" || !isMountpoint(r.mnt) {
		return
	}
	for _, argv := range [][]string{
		{"fusermount3", "-u", r.mnt},
		{"fusermount3", "-uz", r.mnt},
		{"umount", r.mnt},
		{"umount", "-f", r.mnt},
		{"umount", "-l", r.mnt},
	} {
		exec.Command(argv[0], argv[1:]...).Run() //nolint:errcheck
		if !isMountpoint(r.mnt) {
			return
		}
	}
	r.tb.Logf("warning: %s is still attached after every detach attempt", r.mnt)
}

// ---------------------------------------------------------------- the campaign

type campaign struct {
	tb            testing.TB
	rig           *rig
	backend       string
	mnt           *tree
	ref           *tree
	plan          Plan
	applied       int
	diverge       int
	notComparable int
	permDiverge   int
	// expectDiverge is set for a corpus entry marked `expect: known-open`
	// on this backend: divergences are the POINT, so they are reported and
	// counted rather than failed, and their ABSENCE is what fails.
	expectDiverge bool
	observed      int
	// permPaths are the paths a PERMISSION DIVERGENCE has already been
	// reported for. Their later content and metadata differences are a
	// CONSEQUENCE of that one finding, not new findings, so they are
	// attributed to it rather than counted again.
	//
	// This is what keeps the gate honest AND usable. Without it, one open
	// permission finding turns every comparison touching that file red,
	// and the run stops being able to report anything else -- verified at
	// scale: a 5,482-op run produced five permission divergences and the
	// whole NFS leg went red on their downstream byte mismatches, hiding
	// whatever else those 5,482 ops did. Attribution is per-path and
	// reported, so nothing is swallowed silently.
	permPaths map[string]bool
}

func (c *campaign) markPermPath(p string) {
	if c.permPaths == nil {
		c.permPaths = map[string]bool{}
	}
	c.permPaths[p] = true
}

// note reports something that is a failure normally and an expected
// observation for a known-open entry. Everything that would call Errorf on
// a divergence goes through here, so the two modes cannot drift.
func (c *campaign) note(format string, args ...any) {
	c.tb.Helper()
	if c.expectDiverge {
		c.observed++
		c.tb.Logf("EXPECTED (known-open finding, %s backend): "+format, append([]any{c.backend}, args...)...)
		return
	}
	c.tb.Errorf(format, args...)
}

// applyAll runs the plan against both trees, comparing as it goes.
func (c *campaign) applyAll(ops []Op) {
	tb := c.tb
	for i, op := range ops {
		switch op.Kind {
		case OpSettle:
			time.Sleep(time.Duration(op.Wait) * time.Millisecond)
			continue
		case OpCompare:
			c.compare(fmt.Sprintf("mid-run checkpoint after op %d (%s)", i, op.Note), compareExact)
			continue
		}
		refErr := c.ref.apply(op)
		mntErr := c.mnt.apply(op)
		c.applied++

		// When the ORACLE refuses an operation on permission grounds, the
		// two answers mean different things and must be split:
		//
		//   - the mount ALSO refused: nothing to compare. The reference
		//     tree is the definition of correct and it declined to define
		//     anything, so the op is recorded as not-comparable. (This is
		//     real and deliberate: the container drops capabilities, and
		//     the vocabulary sets modes that forbid its own later writes.)
		//   - the mount PERMITTED it: that is a permission divergence, and
		//     the interesting direction. The frontend allowed something
		//     the kernel refused on an identical tree.
		if errors.Is(refErr, os.ErrPermission) {
			if mntErr != nil {
				c.notComparable++
				if c.notComparable <= 3 {
					c.tb.Logf("op %d (%s) is not comparable: both sides refused it on permission "+
						"grounds (reference: %v)", i, op.Kind, refErr)
				}
				continue
			}
			c.permDiverge++
			// Marked so the compare that follows attributes the file's
			// contents to THIS report instead of repeating it as a fresh
			// difference; the report itself is a failure now.
			c.markPermPath(op.Path)
			// A FAILURE, not a note in the log. It was a bare Logf while the
			// mode-bits finding was open, because every run of the corpus
			// entry that pinned it would otherwise have been red. The
			// frontend enforces the model now (internal/vfsbilly/perm.go),
			// so a mount that permits what the kernel refuses is a
			// regression again -- and this is the line that makes the
			// corpus entry GUARD the fix rather than merely replay it,
			// since the bytes it would otherwise catch are attributed above.
			c.note("PERMISSION DIVERGENCE at op %d on the %s backend\n"+
				"    op:        %s\n"+
				"    reference: %s\n"+
				"    mount:     PERMITTED IT\n"+
				"    The frontend allowed an operation the kernel refused on an identical\n"+
				"    tree. The NFS frontend's permission model is internal/vfsbilly/perm.go;\n"+
				"    the FUSE one is the kernel's, via `default_permissions`.",
				i, c.backend, op, errStr(refErr))
			continue
		}

		refOK, mntOK := refErr == nil, mntErr == nil
		if refOK != mntOK {
			c.diverge++
			// THE headline failure mode, and the one that would have caught
			// the reported symlink bug: an operation the reference performed
			// and the mount refused, or vice versa.
			c.note("DIVERGENCE at op %d on the %s backend\n"+
				"    op:        %s\n"+
				"    reference: %s\n"+
				"    mount:     %s\n"+
				"    (replay this exact sequence with: scripts/hostile-docker.sh --plan FILE)",
				i, c.backend, op, errStr(refErr), errStr(mntErr))
			if !c.expectDiverge && c.diverge > 8 {
				tb.Fatalf("too many divergences to be worth continuing; the first ones are the diagnosis")
			}
			// Re-sync so later ops are still meaningful: whichever side
			// succeeded is now ahead, and continuing from a divergence
			// produces cascades that hide the next real finding. The
			// comparison at the next checkpoint is the honest signal.
		}
	}
}

func errStr(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func (c *campaign) compare(what string, mode compareMode) {
	c.tb.Helper()
	res := compareTrees(c.tb, c.mnt, c.ref, mode, c.permPaths)
	if len(res.attributed) > 0 {
		// Reported, always: the whole point is that this is visible and
		// checkable, not swallowed.
		c.tb.Logf("%s: %d difference(s) attributed to the KNOWN-OPEN permission finding "+
			"already reported above (%s backend)\n%s",
			what, len(res.attributed), c.backend, indent(strings.Join(res.attributed, "\n")))
	}
	if len(res.problems) > 0 {
		c.note("%s: the mount and the reference disagree (%s backend)\n%s",
			what, c.backend, indent(strings.Join(res.problems, "\n")))
		return
	}
	extra := ""
	if res.unreadable > 0 {
		extra = fmt.Sprintf(", %d unreadable on both sides (a mode the vocabulary set)", res.unreadable)
	}
	if len(res.attributed) > 0 {
		extra += fmt.Sprintf(", %d attributed to the known-open finding", len(res.attributed))
	}
	if len(res.missing) > 0 {
		// Only reachable in the post-crash mode, where loss is allowed but
		// must be NAMED.
		c.tb.Logf("%s: %d paths lost to the crash (allowed; every survivor was byte-exact%s): %s",
			what, len(res.missing), extra, summarize(res.missing))
		return
	}
	c.tb.Logf("%s: %d files byte-and-metadata-exact%s", what, res.files, extra)
}

// ---------------------------------------------------------------- entry points

// snapshotInterval is how often a writable mount checkpoints during phase
// A. The default of 1s is already aggressive next to the product default
// of 5 minutes, and it is what makes phase A's comparisons land on a live
// view that is part overlay and part freshly-sealed generation.
//
// It is tunable because the seam is a RACE, and a race is studied by
// changing its timing. The intermittent readdir finding filed under
// hostile-agent in docs/TODO.md was chased with this: if a checkpoint
// landing inside a large directory's enumeration is what loses entries,
// then shortening the interval must raise the hit rate, and that is a
// question worth being able to ask rather than argue about.
func snapshotInterval(tb testing.TB) time.Duration {
	v := os.Getenv("PELFS_HOSTILE_SNAPSHOT")
	if v == "" {
		return time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		tb.Fatalf("PELFS_HOSTILE_SNAPSHOT=%q: %v", v, err)
	}
	return d
}

func planFromEnv(tb testing.TB) Plan {
	tb.Helper()
	if p := os.Getenv("PELFS_HOSTILE_PLAN_FILE"); p != "" {
		plan, err := ParsePlan(readAll(p))
		if err != nil {
			tb.Fatalf("parse %s: %v", p, err)
		}
		tb.Logf("replaying plan file %s (%d ops)", p, len(plan.Ops))
		return plan
	}
	opt := DefaultOptions()
	if v := os.Getenv("PELFS_HOSTILE_OPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			tb.Fatalf("PELFS_HOSTILE_OPS=%q: %v", v, err)
		}
		opt.Ops = n
		// Keep the checkpoint cadence proportional on a long manual run.
		opt.CompareEvery = max(60, n/8)
		opt.SettleEvery = max(80, n/6)
	}
	if v := os.Getenv("PELFS_HOSTILE_BIGDIR"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			tb.Fatalf("PELFS_HOSTILE_BIGDIR=%q: %v", v, err)
		}
		opt.BigDirEntries = n
	}
	// The one file per plan big enough for the chunker to cut in two, and
	// the cheapest budget lever here: 0 removes it. It is a knob rather
	// than a constant because it is the only body in the vocabulary whose
	// cost is measured in megabytes, and it gets written, sealed, cold-
	// read and compared at every checkpoint.
	if v := os.Getenv("PELFS_HOSTILE_LARGEFILE"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			tb.Fatalf("PELFS_HOSTILE_LARGEFILE=%q: %v", v, err)
		}
		opt.LargeFileBytes = n
	}
	seed := uint64(time.Now().UnixNano())
	if v := os.Getenv("PELFS_HOSTILE_SEED"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			tb.Fatalf("PELFS_HOSTILE_SEED=%q: %v", v, err)
		}
		seed = n
	}
	plan := Generate(seed, opt)
	// THE SEED, printed unconditionally and early. A finding that cannot
	// be replayed is an anecdote.
	tb.Logf("SEED=%d ops=%d bigdir=%d  (replay: PELFS_HOSTILE_SEED=%d PELFS_HOSTILE_OPS=%d)",
		seed, len(plan.Ops), opt.BigDirEntries, seed, opt.Ops)
	return plan
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestHostileFUSE and TestHostileNFS are separate top-level tests rather
// than subtests of one, so `-run` can select a leg and a failure names the
// backend in the test name — the first question about any finding here is
// "which frontend", because the frontends fail differently by design (raw
// FUSE resolves no paths; the NFS server resolves them all).
func TestHostileFUSE(t *testing.T) { runCampaign(t, "fuse", 19310) }
func TestHostileNFS(t *testing.T)  { runCampaign(t, "nfs", 19311) }

// checkTheCheckpointsGeneration holds the generation A CHECKPOINT
// published to the same standard as the one the seal publishes, and it is
// the only thing in this harness that looks at one.
//
// THE HOLE IT CLOSES, because it is worth stating exactly. Phase C cold-
// mounts the FINAL generation, and the final seal re-renders every file
// it can from the memtable's own location map — so a catalog row that a
// checkpoint got wrong and the next seal happened to get right is
// invisible to every other check here, at every phase. That is not a
// hypothetical: it is precisely what the release-week rechunk CLen/Alg
// bug does. The wrong rows land in the checkpoint's generation, the
// SIGTERM seal replaces them with correct ones, and a cold mount of the
// end state reads clean. Measured on a build that HAS the bug (c26428f):
// unreadable in the checkpoint's generation, byte-exact in the final one.
//
// A checkpoint's generation is signed, published and mountable, and other
// clients read it, so "wrong for one interval and then repaired" is a
// released bug and not a transient. fsck --deep is the cheap way to say
// so: it reads every chunk of every file, and a row whose CLen disagrees
// with the entry the pack holds is exactly what it reports.
//
// It runs while the mount is still up on purpose. The branch head at this
// instant is the LAST CHECKPOINT's generation, which is the thing under
// test; once the mount exits, that generation is no longer the head.
func checkTheCheckpointsGeneration(t *testing.T, r *rig, base, phase string) {
	t.Helper()
	out, err := r.run("fsck", "--deep", "--state-dir", path.Join(base, "state-checkpoint-fsck"), r.prefix)
	switch {
	case err != nil:
		t.Errorf("%s: fsck --deep REJECTS the generation a mid-run CHECKPOINT published, which is "+
			"signed, mountable and read by other clients. The seal that follows may well repair "+
			"it, and every other check here reads only what the seal produced -- so this is a "+
			"generation nothing else in this harness would have looked at: %v\n%s",
			phase, err, indent(out))
	case !strings.Contains(out, "generation is consistent"):
		t.Errorf("%s: fsck --deep exited 0 on the checkpoint's generation without reporting "+
			"consistency:\n%s", phase, indent(out))
	default:
		t.Logf("%s: the generation the last mid-run checkpoint published is consistent under fsck --deep", phase)
	}
}

func runCampaign(t *testing.T, backend string, port int) {
	sandbox := requireContainment(t)
	if backend == "nfs" && !haveNFSClient() {
		t.Fatal("the NFS leg needs a kernel NFS client (mount.nfs, from nfs-common); " +
			"the launcher's image installs it, so its absence means the wrong image is running")
	}

	base := path.Join(sandbox, "run-"+backend)
	if err := os.RemoveAll(base); err != nil {
		t.Fatalf("clear %s: %v", base, err)
	}
	r := newRig(t, sandbox, "run-"+backend, port)
	stateDir := path.Join(base, "state")
	refDir := path.Join(base, "ref")
	mntDir := path.Join(base, "mnt")
	for _, d := range []string{stateDir, refDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	out := r.mustRun("volume create", "init", "--state-dir", stateDir, r.prefix)
	if !strings.Contains(out, "created volume") {
		t.Fatalf("init did not create a volume:\n%s", indent(out))
	}

	plan := planFromEnv(t)

	// ---- phase A: the live view, under mid-run checkpoints -------------
	// --snapshot-interval 1s: checkpoints publish generations DURING the
	// run, so every comparison below is against a live view that is part
	// overlay and part freshly-sealed generation. That seam is where a
	// checkpoint that drops something shows up.
	r.startMount(backend, stateDir, mntDir, snapshotInterval(t), "mount-"+backend+".log")
	c := &campaign{
		tb:      t,
		rig:     r,
		backend: backend,
		mnt:     openTree(t, "mount", mntDir),
		ref:     openTree(t, "reference", refDir),
		plan:    plan,
	}
	defer c.mnt.close()
	defer c.ref.close()

	start := time.Now()
	c.applyAll(plan.Ops)
	elapsed := time.Since(start)
	t.Logf("phase A: %d ops applied in %s (%d not comparable, %d permission divergences)",
		c.applied, elapsed.Round(time.Millisecond), c.notComparable, c.permDiverge)
	// A run where a large share of the vocabulary was unusable is not a
	// pass worth having: it means the container's capability set changed
	// and whole shapes stopped being exercised.
	if c.notComparable*4 > c.applied {
		t.Errorf("%d of %d ops were not comparable: the container is missing capabilities "+
			"the vocabulary needs, so this run exercised much less than it claims",
			c.notComparable, c.applied)
	}
	c.compare("phase A: the live view at the end of the run", compareExact)
	checkTheCheckpointsGeneration(t, r, base, "phase A")

	// ---- phase B: seal ------------------------------------------------
	c.mnt.close()
	log := r.stopAndSeal()
	if !strings.Contains(log, "sealed generation") && !strings.Contains(log, "nothing changed") {
		t.Fatalf("the session did not seal:\n%s", indent(log))
	}
	// --snapshot-interval is 1s, so a run that lasted several seconds MUST
	// have crossed the checkpoint seam; a two-op replay legitimately does
	// not, and asserting on it would make every minimized corpus entry
	// fail for the wrong reason.
	n := strings.Count(log, "checkpoint: sealed generation")
	switch {
	case n > 0:
		t.Logf("phase B: sealed, after %d mid-run checkpoints", n)
	case elapsed > 4*time.Second:
		t.Errorf("phase A ran for %s under --snapshot-interval 1s and published no mid-run "+
			"checkpoint; the seam this phase exists to test was never crossed:\n%s",
			elapsed.Round(time.Millisecond), indent(log))
	default:
		t.Logf("phase B: sealed; the run was too short (%s) to cross a 1s checkpoint",
			elapsed.Round(time.Millisecond))
	}

	// ---- phase C: cold remount, full compare --------------------------
	// A state dir that has never existed, so nothing is answered from a
	// local overlay or cache: this reads the published generation and
	// nothing else. It is where the sparse-train bug lived — the live
	// mount served those files correctly all along.
	coldState := path.Join(base, "state-cold")
	coldMnt := path.Join(base, "cold")
	r.startReadOnlyMount(backend, coldState, coldMnt, "cold-"+backend+".log")
	c.mnt = openTree(t, "cold mount", coldMnt)
	c.compare("phase C: the SEALED generation, cold", compareExact)
	c.mnt.close()
	r.stopAndSeal()

	inheritPhase(t, r, c, backend, base, stateDir, mntDir, plan)

	// ---- phase D: fsck --deep, then gc --------------------------------
	fsckState := path.Join(base, "state-fsck")
	fout, ferr := r.run("fsck", "--deep", "--state-dir", fsckState, r.prefix)
	if ferr != nil {
		t.Errorf("fsck --deep rejected the generation this run published: %v\n%s", ferr, indent(fout))
	} else if !strings.Contains(fout, "generation is consistent") {
		t.Errorf("fsck --deep exited 0 without reporting consistency:\n%s", indent(fout))
	} else {
		t.Log("phase D: fsck --deep says the generation is consistent")
	}
	// The encrypted leg has to prove it IS encrypted, or a --encrypt that
	// quietly stopped reaching the volume would buy a green run that
	// tested the plaintext path twice. fsck --deep reads every chunk, so
	// without the key it must fail; if it passes, the bytes were never
	// sealed.
	if encryptedRun() {
		nout, nerr := r.runWithoutKey("fsck", "--deep", "--state-dir", path.Join(base, "state-nokey"), r.prefix)
		if nerr == nil {
			t.Errorf("this run was launched with --encrypt, but fsck --deep read the whole "+
				"generation WITHOUT the key. The volume is not encrypted and this leg tested "+
				"the plaintext path:\n%s", indent(nout))
		} else {
			t.Log("phase D: the generation is genuinely encrypted -- fsck --deep cannot read it without the key")
		}
	}
	gcState := path.Join(base, "state-gc")
	gout, gerr := r.run("gc", "--state-dir", gcState, r.prefix)
	if gerr != nil {
		t.Errorf("gc failed against the generation this run published: %v\n%s", gerr, indent(gout))
	} else {
		t.Logf("phase D: gc clean\n%s", indent(gout))
	}

	// ---- phase E: kill -9 mid-train, remount, recover -----------------
	// Last, so the exact comparisons above are not weakened by a crash's
	// legitimate losses. Recovery is allowed to LOSE content -- a mount is
	// tied to a job and a crashed job usually discards its state -- but it
	// is never allowed to lose it quietly, and never allowed to leave a
	// file present and wrong.
	crashPhase(t, r, c, backend, base, stateDir, refDir, mntDir, plan.Seed)
}

// inheritPhase is a SECOND WRITABLE SESSION over the generation the first
// one published, and what it exists for is the one thing every other
// phase here structurally cannot reach.
//
// Phase A is a single session on a fresh volume. Its mid-run checkpoints
// do publish generations, but the memtable that wrote them is still the
// same object and still holds its own chunk locations — so when a later
// write in the SAME session disturbs one of those files, the seal renders
// it from locations it recorded itself. A file inherited from a
// generation THIS session did not write is a different code path
// entirely: the memtable adopts it by reference from the base's catalog
// rows and, when a write straddles one of its chunks, re-chunks a span it
// has to read back out of the base.
//
// That is where the release-week rechunk CLen/Alg bug is observable, and
// it is why a plain checkpoint-then-overwrite does not show it: measured
// on the pre-fix build (c26428f), the same op shape inside one session
// produces a clean generation, and across two sessions it produces a file
// that cannot be read. So this phase is not extra coverage of the same
// thing, it is the only coverage of the other thing.
//
// Every op it applies goes to BOTH trees like any other, so the oracle is
// unchanged; the ops are derived from the plan and the reference tree, so
// a replay is deterministic.
func inheritPhase(t *testing.T, r *rig, c *campaign, backend, base, stateDir, mntDir string, plan Plan) {
	ops := inheritedRewrites(plan, c.ref)
	if len(ops) == 0 {
		t.Log("phase C2: no inherited compressible file large enough to rewrite; skipped")
		return
	}
	if err := r.tryStartMount(backend, stateDir, mntDir, snapshotInterval(t), "inherit-"+backend+".log"); err != nil {
		// A SECOND WRITABLE SESSION ON ITS OWN STATE DIRECTORY IS AN
		// ORDINARY THING TO DO, and a refusal to start is worse than any
		// divergence: it is the whole volume, not one file.
		//
		// THIS IS A FILED OPEN FINDING and it is why the report below is
		// not an Errorf. `memtable: re-adopt inode N: genfs: stale inode
		// (no residency)` is reproduced deterministically by
		// testdata/corpus/second-session-refuses-after-adopt.plan, which
		// is marked `known-open all` and therefore FAILS if it ever stops
		// reproducing -- so this allowance cannot outlive the bug it
		// allows for. What it buys is a random lane that keeps reporting
		// everything ELSE: any plan containing checkpoint-then-partial-
		// overwrite reaches this, which is most of them now, and a gate
		// that is red two runs in three is a gate somebody switches off.
		// The same reasoning and the same shape as the permission
		// attribution above (see campaign.permPaths).
		//
		// WHEN IT IS FIXED: the corpus entry goes red, its marker comes
		// off, and isReadoptRefusal goes with it.
		//
		// A corpus entry that PINS this takes the c.note path, because
		// that is what counts an observation and therefore what makes the
		// entry fail if the finding ever stops reproducing. The bare
		// allowance is only for the random lane.
		if isReadoptRefusal(err) && !c.expectDiverge {
			logReadoptFinding(t, c.backend, "phase C2", err)
			return
		}
		c.note("phase C2: a second writable session REFUSED TO START on the state directory "+
			"the first one sealed cleanly (%s backend). Mounting a volume again from the same "+
			"machine is the ordinary case, and this is the whole volume rather than one file:\n%s",
			c.backend, indent(err.Error()))
		return
	}
	c.mnt = openTree(t, "second-session mount", mntDir)
	c.applyAll(ops)
	c.compare("phase C2: a second session's live view over inherited files", compareExact)
	checkTheCheckpointsGeneration(t, r, base, "phase C2")
	c.mnt.close()
	log := r.stopAndSeal()
	if !strings.Contains(log, "sealed generation") && !strings.Contains(log, "nothing changed") {
		t.Errorf("phase C2: the second session did not seal:\n%s", indent(log))
	}
	coldMnt := path.Join(base, "cold2")
	r.startReadOnlyMount(backend, path.Join(base, "state-cold2"), coldMnt, "cold2-"+backend+".log")
	c.mnt = openTree(t, "cold mount after the second session", coldMnt)
	c.compare("phase C2: the generation a second session sealed, cold", compareExact)
	c.mnt.close()
	r.stopAndSeal()
	t.Logf("phase C2: %d rewrite(s) of inherited compressible files, sealed and read back cold", len(ops)-1)
}

// isTheReadoptFinding recognises the ONE open finding that stops a
// writable mount from starting, reports it as the expected observation it
// currently is, and says so. Everything else that stops a mount is a
// failure.
//
// It exists in exactly one place so that removing it when the bug is
// fixed is one deletion, and it cannot quietly outlive the bug: the
// corpus entry that pins the same sequence is marked `known-open all` and
// FAILS the moment the divergence stops reproducing.
func isReadoptRefusal(err error) bool {
	return err != nil && strings.Contains(err.Error(), "re-adopt inode")
}

func logReadoptFinding(tb testing.TB, backend, phase string, err error) {
	tb.Logf("%s: EXPECTED (known-open finding, %s backend): a writable mount refused to start on "+
		"a state directory whose journal holds an adopted handle, because the base has moved on "+
		"since. Pinned by testdata/corpus/second-session-refuses-after-adopt.plan:\n%s",
		phase, backend, indent(err.Error()))
}

// inheritedRewrites picks files the plan wrote with COMPRESSIBLE bodies
// and returns partial overwrites of them, strictly inside the file.
//
// Compressible is the filter that matters and it is not decoration: for
// an incompressible body a row that copies the plaintext's numbers is
// accidentally correct, so rewriting one proves nothing. The span is
// unaligned at both ends so that the chunk holding it straddles the
// rewrite, which is what makes the seal re-chunk rather than replace.
func inheritedRewrites(plan Plan, ref *tree) []Op {
	compressible := map[string]bool{}
	for _, op := range plan.Ops {
		if op.Kind != OpCreate && op.Kind != OpPwrite {
			continue
		}
		if op.FillKind != FillRandom && op.Len > 0 {
			compressible[op.Path] = true
		}
	}
	var paths []string
	for p := range compressible {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var ops []Op
	for _, p := range paths {
		if len(ops) >= 6 {
			break
		}
		fi, err := ref.root.Lstat(p)
		// Gone, renamed, or turned into something else by the plan: the
		// vocabulary does that on purpose and it is not this phase's
		// business to work around it.
		if err != nil || !fi.Mode().IsRegular() || fi.Size() < 8192 {
			continue
		}
		size := fi.Size()
		kind, variant := FillText, byte(0x70+len(ops))
		if len(ops)%3 == 2 {
			kind, variant = FillZero, 0
		}
		ops = append(ops, Op{Kind: OpPwrite, Path: p,
			Off: 1 + size/7, Len: size / 3, FillKind: kind, Fill: variant,
			Note: "second session: partial overwrite of a file INHERITED from a generation it did not write"})
	}
	if len(ops) == 0 {
		return nil
	}
	return append(ops, Op{Kind: OpCompare, Note: "inherited rewrites"})
}

func crashPhase(t *testing.T, r *rig, c *campaign, backend, base, stateDir, refDir, mntDir string, seed uint64) {
	if backend == "nfs" {
		// A SIGKILLed loopback NFS server leaves the kernel client wedged
		// on a socket nobody will answer, and the umount dance that frees
		// it can block for the retrans timeout. The crash contract is
		// backend-independent (it is the memtable's, not the frontend's),
		// so it is tested once, on FUSE, rather than flakily on both.
		t.Log("phase E: skipped on the NFS backend by design (a killed loopback server " +
			"wedges the kernel client; the recovery contract is the memtable's and is covered on FUSE)")
		return
	}
	// A fresh sub-plan, seeded off the campaign seed so it replays too.
	opt := DefaultOptions()
	opt.Ops = 120
	opt.CompareEvery = 0
	opt.SettleEvery = 0
	sub := Generate(seed^0xc7a54, opt)

	// --snapshot-interval 0: nothing this session writes gets published,
	// so everything it wrote is unsealed when it dies. That is the state
	// recovery exists for.
	// --snapshot-interval 0 and the SAME state dir as phase A, so this is
	// also a reopen: it meets the known-open re-adopt finding whenever the
	// plan contained an adoption. See isTheReadoptFinding.
	if err := r.tryStartMount(backend, stateDir, mntDir, 0, "crash-"+backend+".log"); err != nil {
		if isReadoptRefusal(err) {
			logReadoptFinding(t, backend, "phase E", err)
			t.Log("phase E: skipped, because the mount it needs cannot start until that finding is fixed")
			return
		}
		t.Fatal(err.Error())
	}
	c.mnt = openTree(t, "crashing mount", mntDir)

	// Kill at a point the plan chose, not at a boundary: mid-train.
	killAt := len(sub.Ops) / 2
	c.applyAll(sub.Ops[:killAt])
	t.Logf("phase E: SIGKILL after %d of %d crash-phase ops", killAt, len(sub.Ops))
	c.mnt.close()
	r.kill9()

	// Remount the SAME state dir. The recovery must announce itself.
	r.startMount(backend, stateDir, mntDir, 0, "recover-"+backend+".log")
	c.mnt = openTree(t, "recovered mount", mntDir)
	c.compare("phase E: after remount, every survivor byte-exact", compareSubsetAfterCrash)
	c.mnt.close()
	log := r.stopAndSeal()
	if !strings.Contains(log, "sealed generation") && !strings.Contains(log, "nothing changed") {
		t.Errorf("the recovered session did not seal:\n%s", indent(log))
	}
	recovered := strings.Contains(readAll(path.Join(r.sandbox, "recover-"+backend+".log")), "recover")
	t.Logf("phase E: remount reported recovery: %v", recovered)

	// And fsck the generation the recovered session sealed: a crash must
	// not be able to publish an inconsistent generation.
	fout, ferr := r.run("fsck", "--deep", "--state-dir", path.Join(base, "state-fsck2"), r.prefix)
	if ferr != nil || !strings.Contains(fout, "generation is consistent") {
		t.Errorf("fsck --deep after crash recovery: %v\n%s", ferr, indent(fout))
	} else {
		t.Log("phase E: fsck --deep passes on the generation a recovered session sealed")
	}
}

func haveNFSClient() bool {
	_, err := exec.LookPath("mount.nfs")
	return err == nil
}

// TestReplayTheRegressionCorpus runs every committed corpus entry against
// both backends. This is the fuzz discipline: a sequence that ever found a
// bug is replayed forever, so the bug cannot come back quietly. It is also
// the cheap lane -- fixed sequences, no generation, seconds each -- which
// is what makes it affordable in CI alongside a short random run.
func TestReplayTheRegressionCorpus(t *testing.T) {
	sandbox := requireContainment(t)
	entries, err := os.ReadDir("testdata/corpus")
	if err != nil {
		t.Fatalf("the corpus is the point of this package; it must exist: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".plan") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no corpus entries")
	}

	backends := []string{"fuse"}
	if haveNFSClient() {
		backends = append(backends, "nfs")
	}
	port := 19320
	for _, backend := range backends {
		for _, name := range names {
			backend, name := backend, name
			t.Run(backend+"/"+strings.TrimSuffix(name, ".plan"), func(t *testing.T) {
				plan, err := ParsePlan(readAll(path.Join("testdata/corpus", name)))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				replayOne(t, sandbox, backend, name, plan, port)
			})
			port++
		}
	}
}

// planWantsACheckpoint reports whether an entry's settles are load-
// bearing: a settle long enough to cross the mount's checkpoint interval
// is there for one reason, and the entry is entitled to have it happen.
func planWantsACheckpoint(p Plan) bool {
	for _, op := range p.Ops {
		if op.Kind == OpSettle && op.Wait >= 1000 {
			return true
		}
	}
	return false
}

// replayOne is the corpus lane's campaign: apply, seal, cold-compare,
// fsck. Deliberately the same lifecycle as a random run, because both bugs
// in the corpus are only visible at a different stage (one at the live
// unlink, one at the seal), and a replay that skipped either would replay
// nothing.
func replayOne(t *testing.T, sandbox, backend, name string, plan Plan, port int) {
	tag := fmt.Sprintf("corpus-%s-%s", backend, strings.TrimSuffix(name, ".plan"))
	base := path.Join(sandbox, tag)
	if err := os.RemoveAll(base); err != nil {
		t.Fatalf("clear: %v", err)
	}
	r := newRig(t, sandbox, tag, port)
	stateDir, refDir, mntDir := path.Join(base, "state"), path.Join(base, "ref"), path.Join(base, "mnt")
	for _, d := range []string{stateDir, refDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	r.mustRun("volume create", "init", "--state-dir", stateDir, r.prefix)

	known := plan.IsKnownOpen(backend)
	if known {
		t.Logf("this entry pins a KNOWN-OPEN finding on the %s backend: the divergence below "+
			"is expected, and its ABSENCE would fail this test. See the entry's own header.", backend)
	}

	r.startMount(backend, stateDir, mntDir, snapshotInterval(t), tag+".log")
	c := &campaign{
		tb: t, rig: r, backend: backend, plan: plan, expectDiverge: known,
		mnt: openTree(t, "mount", mntDir),
		ref: openTree(t, "reference", refDir),
	}
	defer c.ref.close()
	c.applyAll(plan.Ops)
	c.compare("corpus "+name+": live view", compareExact)
	// Before the seal, while the branch head is still the last
	// CHECKPOINT's generation. For the rechunk entry this is the only
	// place its bug is observable at all -- see
	// checkTheCheckpointsGeneration.
	if planWantsACheckpoint(plan) {
		checkTheCheckpointsGeneration(t, r, base, "corpus "+name)
	}
	c.mnt.close()

	log := r.stopAndSeal()
	if !strings.Contains(log, "sealed generation") && !strings.Contains(log, "nothing changed") {
		t.Fatalf("corpus %s: the session did not seal -- which for the sparse-train entry "+
			"IS the bug it exists to detect:\n%s", name, indent(log))
	}
	// An entry whose `settle` ops exist to put a checkpoint between two
	// operations is testing nothing if no checkpoint landed, and it would
	// PASS while testing nothing. Say how many there were, and refuse to
	// call it a replay if an entry that asked for one got none.
	checkpoints := strings.Count(log, "checkpoint: sealed generation")
	t.Logf("corpus %s: %d mid-run checkpoint(s) before the seal", name, checkpoints)
	if checkpoints == 0 && planWantsACheckpoint(plan) {
		t.Errorf("corpus %s: the entry contains `settle` ops, which are there to put a "+
			"CHECKPOINT between two operations, and none landed. Whatever the entry pins, "+
			"this replay did not reach it:\n%s", name, indent(log))
	}

	coldMnt := path.Join(base, "cold")
	r.startReadOnlyMount(backend, path.Join(base, "state-cold"), coldMnt, tag+"-cold.log")
	c.mnt = openTree(t, "cold mount", coldMnt)
	c.compare("corpus "+name+": sealed generation, cold", compareExact)
	c.mnt.close()
	r.stopAndSeal()

	// The corpus gets the second-session phase too, and for the rechunk
	// entry it is not optional: a partial overwrite of a file INHERITED
	// from a generation the writing session did not produce is the only
	// arrangement in which that entry's bug is observable at all. See
	// inheritPhase.
	inheritPhase(t, r, c, backend, base, stateDir, mntDir, plan)

	fout, ferr := r.run("fsck", "--deep", "--state-dir", path.Join(base, "state-fsck"), r.prefix)
	if ferr != nil || !strings.Contains(fout, "generation is consistent") {
		t.Errorf("corpus %s: fsck --deep: %v\n%s", name, ferr, indent(fout))
	}

	switch {
	case !known:
	case plan.Flaky:
		// A RACE. Both outcomes are true observations and neither is a
		// regression, so neither is asserted -- but the result is always
		// stated, so the entry is never silent.
		if c.observed > 0 {
			t.Logf("corpus %s: the flaky-open finding DID reproduce on %s this run (%d observation(s)). "+
				"See the entry's header for the amplifier that raises the rate on demand.",
				name, backend, c.observed)
		} else {
			t.Logf("corpus %s: the flaky-open finding did not fire on %s this run. That is expected "+
				"some fraction of the time and is NOT evidence it is fixed -- reproduce with the "+
				"amplifier in the entry's header before concluding anything.", name, backend)
		}
	case c.observed == 0:
		// The other half of the known-open contract, and the reason the
		// marker is safe: if a DETERMINISTIC finding stops reproducing,
		// this fails. An entry for an open bug that quietly starts passing
		// has stopped testing anything, and nobody would notice.
		t.Errorf("corpus %s: marked `expect: known-open %s` but the divergence did NOT reproduce.\n"+
			"If this finding has been fixed, remove the marker from the entry -- from then on it "+
			"guards the fix instead of recording the bug.", name, backend)
	}
}
