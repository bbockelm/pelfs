//go:build opfuzz

package overlay_test

// The op-sequence fuzzer: random filesystem operation sequences decoded
// from fuzz input, applied to BOTH the overlay and an in-memory reference
// model, with full-tree divergence checks — the fsx/syzkaller shape that
// has historically shaken real bugs out of filesystems.
//
// CONTAINMENT IS MANDATORY: this fuzzer generates arbitrary filesystem
// operation sequences, so it must never be able to reach a real tree.
// This file:
//   - only builds under the `opfuzz` tag (never part of normal test runs),
//   - refuses to execute unless PELFS_OPFUZZ_CONTAINED=1, which only
//     scripts/opfuzz-docker.sh sets — inside a network-less, cap-dropped,
//     read-only container with a tmpfs scratch,
//   - does every path operation the harness controls through os.Root
//     handles rooted at the scratch directory, so even a harness bug
//     cannot traverse out via symlinks or "..".
//
// Run: scripts/opfuzz-docker.sh [fuzztime]

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

func requireContainment(tb testing.TB) (*os.Root, string) {
	tb.Helper()
	if os.Getenv("PELFS_OPFUZZ_CONTAINED") != "1" {
		tb.Skip("op-sequence fuzzing runs ONLY inside the containment launcher: scripts/opfuzz-docker.sh")
	}
	scratch := os.Getenv("PELFS_OPFUZZ_SCRATCH")
	if scratch == "" {
		scratch = tb.TempDir()
	}
	root, err := os.OpenRoot(scratch)
	if err != nil {
		tb.Fatalf("open scratch root: %v", err)
	}
	tb.Cleanup(func() { _ = root.Close() })
	return root, scratch
}

// scratchDir allocates a fresh directory THROUGH the os.Root handle —
// symlink/.. traversal out of the scratch is impossible by construction.
func scratchDir(tb testing.TB, root *os.Root, scratch, name string) string {
	tb.Helper()
	if err := root.Mkdir(name, 0700); err != nil {
		tb.Fatalf("scratch mkdir %s: %v", name, err)
	}
	return filepath.Join(scratch, name)
}

// mnode is the reference model's inode.
type mnode struct {
	typ      uint8 // catalog type constants via overlay/genfs Node.Type
	content  []byte
	target   string
	children map[string]uint64
	nlink    int
}

type model struct {
	nodes map[uint64]*mnode
	next  uint64
}

const (
	tFile = 1
	tDir  = 2
	tLink = 3
)

func (m *model) dir(ino uint64) (*mnode, bool) {
	n, ok := m.nodes[ino]
	return n, ok && n.typ == tDir
}

func (m *model) lookup(parent uint64, name string) (uint64, *mnode, error) {
	d, ok := m.dir(parent)
	if !ok {
		return 0, nil, errors.New("bad parent")
	}
	ino, ok := d.children[name]
	if !ok {
		return 0, nil, overlay.ErrNotExist
	}
	return ino, m.nodes[ino], nil
}

func (m *model) create(parent uint64, name string, typ uint8, target string) error {
	d, ok := m.dir(parent)
	if !ok {
		return errors.New("bad parent")
	}
	if _, exists := d.children[name]; exists {
		return errors.New("exists")
	}
	m.next++
	n := &mnode{typ: typ, target: target, nlink: 1}
	if typ == tDir {
		n.children = map[string]uint64{}
		n.nlink = 2
	}
	m.nodes[m.next] = n
	d.children[name] = m.next
	return nil
}

func (m *model) unlink(parent uint64, name string, wantDir bool) error {
	d, ok := m.dir(parent)
	if !ok {
		return errors.New("bad parent")
	}
	ino, ok := d.children[name]
	if !ok {
		return overlay.ErrNotExist
	}
	n := m.nodes[ino]
	if wantDir != (n.typ == tDir) {
		return errors.New("type mismatch")
	}
	if n.typ == tDir && len(n.children) > 0 {
		return errors.New("not empty")
	}
	delete(d.children, name)
	n.nlink--
	if n.typ == tDir || n.nlink <= 0 {
		delete(m.nodes, ino)
	}
	return nil
}

func (m *model) rename(sp uint64, sn string, dp uint64, dn string) error {
	// Same-name no-op comes FIRST: a self-rename that falls through to
	// the replace branch unlinks the source and then binds a name to the
	// inode it just removed, corrupting the model the overlay is being
	// compared against.
	if sp == dp && sn == dn {
		if _, _, err := m.lookup(sp, sn); err != nil {
			return err
		}
		return nil
	}
	sd, ok := m.dir(sp)
	if !ok {
		return errors.New("bad src parent")
	}
	dd, ok := m.dir(dp)
	if !ok {
		return errors.New("bad dst parent")
	}
	ino, ok := sd.children[sn]
	if !ok {
		return overlay.ErrNotExist
	}
	moving := m.nodes[ino]
	_ = moving
	// NOTE: no directory-loop guard — the overlay leaves EINVAL for a
	// rename of a directory into its own subtree to the binding, and the
	// model mirrors the implementation under test, not idealized POSIX.
	if tgt, exists := dd.children[dn]; exists {
		if tgt == ino {
			return nil // hardlinks to the same inode: POSIX no-op
		}
		tn := m.nodes[tgt]
		if tn.typ == tDir {
			if moving.typ != tDir {
				return errors.New("is dir")
			}
			if len(tn.children) > 0 {
				return errors.New("not empty")
			}
			delete(m.nodes, tgt)
		} else {
			if moving.typ == tDir {
				return errors.New("not dir")
			}
			tn.nlink--
			if tn.nlink <= 0 {
				delete(m.nodes, tgt)
			}
		}
	}
	delete(sd.children, sn)
	dd.children[dn] = ino
	return nil
}

func (m *model) link(ino, parent uint64, name string) error {
	n, ok := m.nodes[ino]
	if !ok || n.typ != tFile {
		return errors.New("bad target")
	}
	d, ok := m.dir(parent)
	if !ok {
		return errors.New("bad parent")
	}
	if _, exists := d.children[name]; exists {
		return errors.New("exists")
	}
	d.children[name] = ino
	n.nlink++
	return nil
}

func (m *model) write(ino uint64, off int, data []byte) error {
	n, ok := m.nodes[ino]
	if !ok || n.typ != tFile {
		return errors.New("bad file")
	}
	if need := off + len(data); need > len(n.content) {
		n.content = append(n.content, make([]byte, need-len(n.content))...)
	}
	copy(n.content[off:], data)
	return nil
}

func (m *model) truncate(ino uint64, size int) error {
	n, ok := m.nodes[ino]
	if !ok || n.typ != tFile {
		return errors.New("bad file")
	}
	if size <= len(n.content) {
		n.content = n.content[:size]
	} else {
		n.content = append(n.content, make([]byte, size-len(n.content))...)
	}
	return nil
}

var namePool = []string{"a", "b", "c.txt", "d.bin", "sub", "deep", "x", "y"}

// interp decodes one op per chunk of the fuzz input and applies it to
// both sides, tracking the model-ino <-> overlay-ino correspondence.
type interp struct {
	t     *testing.T
	ov    *overlay.FS
	m     *model
	toOv  map[uint64]uint64 // model ino -> overlay ino
	dirs  []uint64          // model inos currently believed to be dirs
	files []uint64
}

func (ip *interp) refresh() {
	ip.dirs = ip.dirs[:0]
	ip.files = ip.files[:0]
	inos := make([]uint64, 0, len(ip.m.nodes))
	for ino := range ip.m.nodes {
		inos = append(inos, ino)
	}
	sort.Slice(inos, func(i, j int) bool { return inos[i] < inos[j] })
	for _, ino := range inos {
		if ip.m.nodes[ino].typ == tDir {
			ip.dirs = append(ip.dirs, ino)
		} else if ip.m.nodes[ino].typ == tFile {
			ip.files = append(ip.files, ino)
		}
	}
}

func (ip *interp) pick(list []uint64, b byte) uint64 {
	if len(list) == 0 {
		return 1
	}
	return list[int(b)%len(list)]
}

func (ip *interp) step(op []byte) {
	if len(op) < 4 {
		return
	}
	ip.refresh()
	ctx := context.Background()
	kind := op[0] % 9
	parent := ip.pick(ip.dirs, op[1])
	name := namePool[int(op[2])%len(namePool)]
	ovParent := ip.toOv[parent]

	both := func(merr error, oerr error, what string) bool {
		if (merr == nil) != (oerr == nil) {
			ip.t.Fatalf("%s divergence: model=%v overlay=%v (parent %d %q)", what, merr, oerr, parent, name)
		}
		return merr == nil
	}

	switch kind {
	case 0: // create file
		n, oerr := ip.ov.Create(ctx, ovParent, name, 0644, 1000, 1000)
		if both(ip.m.create(parent, name, tFile, ""), oerr, "create") {
			ip.toOv[ip.m.next] = n.Inode
		}
	case 1: // mkdir
		n, oerr := ip.ov.Mkdir(ctx, ovParent, name, 0755, 1000, 1000)
		if both(ip.m.create(parent, name, tDir, ""), oerr, "mkdir") {
			ip.toOv[ip.m.next] = n.Inode
		}
	case 2: // symlink
		n, oerr := ip.ov.Symlink(ctx, ovParent, name, "target-"+name, 1000, 1000)
		if both(ip.m.create(parent, name, tLink, "target-"+name), oerr, "symlink") {
			ip.toOv[ip.m.next] = n.Inode
		}
	case 3: // unlink
		both(ip.m.unlink(parent, name, false), ip.ov.Unlink(ctx, ovParent, name), "unlink")
	case 4: // rmdir
		both(ip.m.unlink(parent, name, true), ip.ov.Rmdir(ctx, ovParent, name), "rmdir")
	case 5: // rename
		dp := ip.pick(ip.dirs, op[3])
		dn := namePool[int(op[3]>>3)%len(namePool)]
		both(ip.m.rename(parent, name, dp, dn),
			ip.ov.Rename(ctx, ovParent, name, ip.toOv[dp], dn), "rename")
	case 6: // link
		target := ip.pick(ip.files, op[3])
		_, oerr := ip.ov.Link(ctx, ip.toOv[target], ovParent, name)
		both(ip.m.link(target, parent, name), oerr, "link")
	case 7: // write
		target := ip.pick(ip.files, op[1])
		off := int(op[2]) * 37
		data := bytes.Repeat([]byte{op[3]}, int(op[3])%977+1)
		_, oerr := ip.ov.Write(ctx, ip.toOv[target], int64(off), data)
		both(ip.m.write(target, off, data), oerr, "write")
	case 8: // truncate
		target := ip.pick(ip.files, op[1])
		size := int64(op[2]) * 41
		sz := size
		_, oerr := ip.ov.SetAttr(ctx, ip.toOv[target], overlay.SetAttrIn{Size: &sz})
		both(ip.m.truncate(target, int(size)), oerr, "truncate")
	}
}

// compare walks both trees and demands identical structure and content.
func (ip *interp) compare(mIno, oIno uint64) {
	ctx := context.Background()
	mn := ip.m.nodes[mIno]
	on, err := ip.ov.GetAttr(ctx, oIno)
	if err != nil {
		ip.t.Fatalf("overlay GetAttr %d: %v (model has %d)", oIno, err, mIno)
	}
	switch mn.typ {
	case tFile:
		if int64(len(mn.content)) != on.Length {
			ip.t.Fatalf("length mismatch ino %d: model %d overlay %d", mIno, len(mn.content), on.Length)
		}
		buf := make([]byte, len(mn.content))
		if len(buf) > 0 {
			if _, err := ip.ov.Read(ctx, oIno, 0, buf); err != nil {
				ip.t.Fatalf("read %d: %v", oIno, err)
			}
			if !bytes.Equal(buf, mn.content) {
				ip.t.Fatalf("content mismatch ino %d (%d bytes)", mIno, len(buf))
			}
		}
	case tLink:
		target, err := ip.ov.Readlink(ctx, oIno)
		if err != nil || target != mn.target {
			ip.t.Fatalf("symlink mismatch ino %d: %q vs %q (%v)", mIno, target, mn.target, err)
		}
	case tDir:
		entries, err := ip.ov.Readdir(ctx, oIno)
		if err != nil {
			ip.t.Fatalf("readdir %d: %v", oIno, err)
		}
		got := map[string]uint64{}
		for _, e := range entries {
			got[e.Name] = e.Node.Inode
		}
		if len(got) != len(mn.children) {
			ip.t.Fatalf("dir %d entry count: overlay %v model %v", mIno, keys(got), keys2(mn.children))
		}
		for cname, cIno := range mn.children {
			ovChild, ok := got[cname]
			if !ok {
				ip.t.Fatalf("dir %d missing %q in overlay", mIno, cname)
			}
			if known, ok := ip.toOv[cIno]; ok && known != ovChild {
				ip.t.Fatalf("ino correspondence broke for %q: %d vs %d", cname, known, ovChild)
			}
			ip.toOv[cIno] = ovChild
			ip.compare(cIno, ovChild)
		}
	}
}

func keys(m map[string]uint64) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func keys2(m map[string]uint64) []string { return keys(m) }

func FuzzOps(f *testing.F) {
	root, scratch := requireContainment(f)
	fx := newFixture(f, "0fbeef00-0000-4000-8000-00000000f0f0")
	var runSeq atomic.Uint64

	f.Add(bytes.Repeat([]byte{0, 1, 2, 3}, 32))
	f.Add([]byte{0, 1, 0, 0, 7, 1, 9, 200, 3, 1, 0, 0})
	f.Add(bytes.Repeat([]byte{5, 9, 13, 200}, 24))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := scratchDir(t, root, scratch, fmt.Sprintf("run-%d-%d", os.Getpid(), runSeq.Add(1)))
		defer os.RemoveAll(dir) //nolint:errcheck
		ov, err := overlay.Open(dir, fx.base, fx.options())
		if err != nil {
			t.Fatal(err)
		}
		defer ov.Close() //nolint:errcheck

		// Model seeded with an EMPTY root view is wrong — the base has
		// content. Seed by walking the overlay's merged root (which
		// equals the base at open).
		m := &model{nodes: map[uint64]*mnode{}, next: 0}
		ip := &interp{t: t, ov: ov, m: m, toOv: map[uint64]uint64{}}
		seed(t, ip, 1, 1)
		if m.next < 1 {
			m.next = 1
		}

		for i := 0; i+4 <= len(data) && i < 400*4; i += 4 {
			ip.step(data[i : i+4])
		}
		ip.compare(1, 1)
	})
}

// seed mirrors the merged base tree into the model (model ino == walk
// order; correspondence recorded in toOv). Descent goes through Lookup,
// honoring the ErrStale contract: residency exists only after a Lookup,
// exactly as the kernel drives the real filesystem.
func seed(t *testing.T, ip *interp, ovIno, mIno uint64) {
	ctx := context.Background()
	node, err := ip.ov.GetAttr(ctx, ovIno)
	if err != nil {
		t.Fatalf("seed GetAttr %d: %v", ovIno, err)
	}
	ip.toOv[mIno] = ovIno
	mn := &mnode{nlink: int(node.Nlink)}
	ip.m.nodes[mIno] = mn
	if mIno > ip.m.next {
		ip.m.next = mIno
	}
	switch {
	case node.Type == 2: // dir
		mn.typ = tDir
		mn.children = map[string]uint64{}
		entries, err := ip.ov.Readdir(ctx, ovIno)
		if err != nil {
			t.Fatalf("seed readdir: %v", err)
		}
		for _, e := range entries {
			// Establish residency for the child before descending.
			cn, err := ip.ov.Lookup(ctx, ovIno, e.Name)
			if err != nil {
				t.Fatalf("seed lookup %q: %v", e.Name, err)
			}
			ip.m.next++
			child := ip.m.next
			mn.children[e.Name] = child
			seed(t, ip, cn.Inode, child)
		}
	case node.Type == 3: // symlink
		mn.typ = tLink
		target, err := ip.ov.Readlink(ctx, ovIno)
		if err != nil {
			t.Fatalf("seed readlink: %v", err)
		}
		mn.target = target
	default:
		mn.typ = tFile
		mn.content = make([]byte, node.Length)
		if node.Length > 0 {
			if _, err := ip.ov.Read(ctx, ovIno, 0, mn.content); err != nil {
				t.Fatalf("seed read: %v", err)
			}
		}
	}
}

// TestConcurrentOpsStress hammers the overlay from many goroutines with
// random ops — no model comparison (interleaving is nondeterministic),
// only invariants: no panic, no deadlock, and a final full-tree walk that
// terminates with consistent metadata. Run under -race in the container.
func TestConcurrentOpsStress(t *testing.T) {
	root, scratch := requireContainment(t)
	fx := newFixture(t, "0fbeef00-0000-4000-8000-00000000f1f1")
	ov := openOverlay(t, fx, scratchDir(t, root, scratch, "stress"))
	ctx := context.Background()

	rootIno := uint64(1)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(seedByte byte) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				b := []byte{byte(i) + seedByte, byte(i >> 3), byte(i * 7), seedByte}
				name := namePool[int(b[2])%len(namePool)]
				switch b[0] % 6 {
				case 0:
					_, _ = ov.Create(ctx, rootIno, name, 0644, 1, 1)
				case 1:
					_, _ = ov.Mkdir(ctx, rootIno, name, 0755, 1, 1)
				case 2:
					_ = ov.Unlink(ctx, rootIno, name)
				case 3:
					_ = ov.Rmdir(ctx, rootIno, name)
				case 4:
					if n, err := ov.Lookup(ctx, rootIno, name); err == nil && n.Type == 1 {
						_, _ = ov.Write(ctx, n.Inode, int64(b[1]), b)
					}
				case 5:
					_ = ov.Rename(ctx, rootIno, name, rootIno, namePool[int(b[3])%len(namePool)])
				}
			}
		}(byte(g * 31))
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	// The tree must still be fully walkable with self-consistent metadata.
	var walk func(ino uint64)
	walk = func(ino uint64) {
		entries, err := ov.Readdir(ctx, ino)
		if err != nil {
			t.Fatalf("post-stress readdir %d: %v", ino, err)
		}
		for _, e := range entries {
			// Descend via Lookup: residency is established by lookups,
			// never by readdir (the ErrStale contract).
			n, err := ov.Lookup(ctx, ino, e.Name)
			if err != nil {
				t.Fatalf("post-stress lookup %s: %v", e.Name, err)
			}
			if n.Type == 2 && n.Inode != ino {
				walk(n.Inode)
			}
		}
	}
	walk(rootIno)
	if _, err := ov.Dirty(); err != nil {
		t.Fatalf("post-stress Dirty: %v", err)
	}
	fmt.Fprintln(os.Stderr, "stress walk clean")
}
