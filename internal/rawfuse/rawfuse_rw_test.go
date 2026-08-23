//go:build !windows

package rawfuse_test

import (
	"bytes"
	"context"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// Statuses the fuse package does not name.
var (
	errExist    = fuse.Status(syscall.EEXIST)
	errNotEmpty = fuse.Status(syscall.ENOTEMPTY)
)

// --- fixture: the read-only fixture's tree, shadowed by a write overlay
// and bound with BindRW ---

// rwFixture is a published base tree behind a read-write binding:
//
//	/base.txt        small text
//	/dir/child.txt   small text
//	/dir/inner/      empty-ish subdir holding leaf.txt
//	/dir/inner/leaf.txt
type rwFixture struct {
	raw fuse.RawFileSystem
	ov  *overlay.FS

	ino  map[string]uint64
	body map[string][]byte
}

func newRWFixture(t *testing.T, uuid string) *rwFixture {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})

	f := &rwFixture{ino: map[string]uint64{}, body: map[string][]byte{}}
	f.body["base.txt"] = []byte("the base file body, generation zero")
	f.body["dir/child.txt"] = []byte("child body")
	f.body["dir/inner/leaf.txt"] = []byte("leaf body")

	f.ino["base.txt"] = v.WriteFile(rootIno, "base.txt", f.body["base.txt"])
	f.ino["dir"] = v.Mkdir(rootIno, "dir")
	f.ino["dir/child.txt"] = v.WriteFile(f.ino["dir"], "child.txt", f.body["dir/child.txt"])
	f.ino["dir/inner"] = v.Mkdir(f.ino["dir"], "inner")
	f.ino["dir/inner/leaf.txt"] = v.WriteFile(f.ino["dir/inner"], "leaf.txt", f.body["dir/inner/leaf.txt"])

	res := v.Publish(publish.Options{TargetPackSize: 1 << 20})
	base, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	f.ov, err = overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      res.Superblock.NextInode,
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = f.ov.Close() })
	f.raw = rawfuse.BindRW(f.ov)
	return f
}

// --- raw-op helpers for the write side ---

func create(t *testing.T, r fuse.RawFileSystem, parent uint64, name string, mode uint32) (*fuse.CreateOut, fuse.Status) {
	t.Helper()
	out := &fuse.CreateOut{}
	st := r.Create(nil, &fuse.CreateIn{InHeader: *header(parent), Mode: mode}, name, out)
	return out, st
}

func mustCreate(t *testing.T, r fuse.RawFileSystem, parent uint64, name string, mode uint32) *fuse.CreateOut {
	t.Helper()
	out, st := create(t, r, parent, name, mode)
	if st != fuse.OK {
		t.Fatalf("Create(%d, %q) = %v", parent, name, st)
	}
	return out
}

func mustMkdir(t *testing.T, r fuse.RawFileSystem, parent uint64, name string) *fuse.EntryOut {
	t.Helper()
	out := &fuse.EntryOut{}
	if st := r.Mkdir(nil, &fuse.MkdirIn{InHeader: *header(parent), Mode: 0755}, name, out); st != fuse.OK {
		t.Fatalf("Mkdir(%d, %q) = %v", parent, name, st)
	}
	return out
}

func mustWrite(t *testing.T, r fuse.RawFileSystem, ino uint64, off int64, data []byte) {
	t.Helper()
	n, st := r.Write(nil, &fuse.WriteIn{
		InHeader: *header(ino), Offset: uint64(off), Size: uint32(len(data)),
	}, data)
	if st != fuse.OK || int(n) != len(data) {
		t.Fatalf("Write(%d, %d) = %d, %v; want %d, OK", ino, off, n, st, len(data))
	}
}

// readAll reads size bytes through the binding in one call.
func readAll(t *testing.T, r fuse.RawFileSystem, ino uint64, size int) []byte {
	t.Helper()
	buf := make([]byte, size)
	rr, st := r.Read(nil, &fuse.ReadIn{InHeader: *header(ino), Size: uint32(size)}, buf)
	if st != fuse.OK {
		t.Fatalf("Read(%d) = %v", ino, st)
	}
	data, st := rr.Bytes(make([]byte, rr.Size()))
	if st != fuse.OK {
		t.Fatalf("ReadResult.Bytes = %v", st)
	}
	return data
}

func setattr(t *testing.T, r fuse.RawFileSystem, ino uint64, in fuse.SetAttrIn) (*fuse.AttrOut, fuse.Status) {
	t.Helper()
	in.InHeader = *header(ino)
	out := &fuse.AttrOut{}
	return out, r.SetAttr(nil, &in, out)
}

// listPlus returns one ReadDirPlus page of ino (the fixture dirs are small
// enough to fit a 8 KiB buffer).
func listPlus(t *testing.T, r fuse.RawFileSystem, ino uint64) []parsedEntry {
	t.Helper()
	fh := opendir(t, r, ino)
	defer r.ReleaseDir(&fuse.ReleaseIn{InHeader: *header(ino), Fh: fh})
	l := fuse.NewDirEntryList(make([]byte, 8192), 0)
	if st := r.ReadDirPlus(nil, &fuse.ReadIn{InHeader: *header(ino), Fh: fh}, l); st != fuse.OK {
		t.Fatalf("ReadDirPlus(%d) = %v", ino, st)
	}
	return parseList(t, l, true)
}

func entryOf(es []parsedEntry, name string) *parsedEntry {
	for i := range es {
		if es[i].name == name {
			return &es[i]
		}
	}
	return nil
}

// --- tests ---

func TestRWCreateWriteRead(t *testing.T) {
	f := newRWFixture(t, "10101010-2020-3030-4040-505050505050")

	co := mustCreate(t, f.raw, rootIno, "fresh.txt", syscall.S_IFREG|0644)
	if co.NodeId == 0 || co.Attr.Mode != syscall.S_IFREG|0644 || co.Attr.Size != 0 {
		t.Fatalf("CreateOut entry = %+v", co.EntryOut)
	}
	if co.Attr.Nlink != 1 || co.Attr.Ino != co.NodeId {
		t.Fatalf("CreateOut attr = %+v", co.Attr)
	}
	// A file this mount is about to write is not immutable: no page-cache
	// retention across open, and short TTLs from the first reply on.
	if co.OpenFlags&fuse.FOPEN_KEEP_CACHE != 0 {
		t.Fatal("Create set FOPEN_KEEP_CACHE on a writable file")
	}
	checkDirtyValidity(t, "Create", co.EntryValid, co.AttrValid)
	ino := co.NodeId

	body := []byte("written through the raw binding")
	mustWrite(t, f.raw, ino, 0, body)
	if got := readAll(t, f.raw, ino, len(body)+16); !bytes.Equal(got, body) {
		t.Fatalf("read back %q, want %q", got, body)
	}

	ao, st := getattr(f.raw, ino)
	if st != fuse.OK || ao.Attr.Size != uint64(len(body)) {
		t.Fatalf("GetAttr after write = %d bytes (%v), want %d", ao.Attr.Size, st, len(body))
	}

	// Writing past EOF extends; the payload is trimmed to WriteIn.Size, so
	// a longer server buffer never leaks bytes into the file.
	tail := []byte("TAIL")
	n, st := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: *header(ino), Offset: uint64(len(body)), Size: uint32(len(tail)),
	}, append(tail, []byte("garbage")...))
	if st != fuse.OK || n != uint32(len(tail)) {
		t.Fatalf("Write(trimmed) = %d, %v", n, st)
	}
	want := append(append([]byte{}, body...), tail...)
	if got := readAll(t, f.raw, ino, len(want)+16); !bytes.Equal(got, want) {
		t.Fatalf("read after append = %q, want %q", got, want)
	}

	// Open of the new file: writable and dirty, so the page cache must not
	// be kept across open.
	oo := &fuse.OpenOut{}
	if st := f.raw.Open(nil, &fuse.OpenIn{InHeader: *header(ino), Flags: syscall.O_RDWR}, oo); st != fuse.OK {
		t.Fatalf("Open(O_RDWR) = %v", st)
	}
	if oo.OpenFlags&fuse.FOPEN_KEEP_CACHE != 0 {
		t.Fatal("Open(O_RDWR) set FOPEN_KEEP_CACHE")
	}
	f.raw.Flush(nil, &fuse.FlushIn{InHeader: *header(ino)})
	if st := f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: *header(ino)}); st != fuse.OK {
		t.Fatalf("Fsync = %v, want OK", st)
	}
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: *header(ino)})
}

// TestRWDirtyTTLPolicy is the design rule itself: clean inodes reply with
// effectively infinite validity, dirty ones with a short one.
func TestRWDirtyTTLPolicy(t *testing.T) {
	f := newRWFixture(t, "20202020-3030-4040-5050-606060606060")

	base := mustLookup(t, f.raw, rootIno, "base.txt")
	checkValidity(t, "clean base.txt", base.EntryValid, base.AttrValid)
	ao, st := getattr(f.raw, base.NodeId)
	if st != fuse.OK || ao.AttrValid <= minValiditySec {
		t.Fatalf("clean GetAttr validity = %d (%v)", ao.AttrValid, st)
	}
	// A clean file keeps its page cache across open.
	oo := &fuse.OpenOut{}
	if st := f.raw.Open(nil, &fuse.OpenIn{InHeader: *header(base.NodeId)}, oo); st != fuse.OK ||
		oo.OpenFlags&fuse.FOPEN_KEEP_CACHE == 0 {
		t.Fatalf("Open(clean, rdonly) flags = %#x (%v)", oo.OpenFlags, st)
	}

	mustWrite(t, f.raw, base.NodeId, 0, []byte("DIRTY"))

	dirty := mustLookup(t, f.raw, rootIno, "base.txt")
	if dirty.NodeId != base.NodeId {
		t.Fatalf("inode renumbered on write: %d -> %d", base.NodeId, dirty.NodeId)
	}
	checkDirtyValidity(t, "dirty base.txt", dirty.EntryValid, dirty.AttrValid)
	ao, st = getattr(f.raw, base.NodeId)
	if st != fuse.OK {
		t.Fatalf("dirty GetAttr = %v", st)
	}
	checkDirtyValidity(t, "dirty GetAttr", ao.AttrValid, ao.AttrValid)
	if oo := (&fuse.OpenOut{}); f.raw.Open(nil, &fuse.OpenIn{InHeader: *header(base.NodeId)}, oo) == fuse.OK &&
		oo.OpenFlags&fuse.FOPEN_KEEP_CACHE != 0 {
		t.Fatal("Open(dirty, rdonly) kept the page cache")
	}

	// Untouched neighbours stay clean: the rule is per inode, not per mount.
	dir := mustLookup(t, f.raw, rootIno, "dir")
	checkValidity(t, "clean dir", dir.EntryValid, dir.AttrValid)
	child := mustLookup(t, f.raw, dir.NodeId, "child.txt")
	checkValidity(t, "clean dir/child.txt", child.EntryValid, child.AttrValid)

	// ReadDirPlus obeys the same rule per row.
	es := listPlus(t, f.raw, rootIno)
	if e := entryOf(es, "base.txt"); e == nil {
		t.Fatal("readdirplus lost base.txt")
	} else {
		checkDirtyValidity(t, "readdirplus base.txt", e.entry.EntryValid, e.entry.AttrValid)
	}
	if e := entryOf(es, "dir"); e == nil {
		t.Fatal("readdirplus lost dir")
	} else {
		checkValidity(t, "readdirplus dir", e.entry.EntryValid, e.entry.AttrValid)
	}

	// Mutating a directory's namespace dirties the directory as well.
	mustMkdir(t, f.raw, dir.NodeId, "made")
	dir = mustLookup(t, f.raw, rootIno, "dir")
	checkDirtyValidity(t, "dir after mkdir inside", dir.EntryValid, dir.AttrValid)
}

func TestRWNamespaceRoundTrips(t *testing.T) {
	f := newRWFixture(t, "30303030-4040-5050-6060-707070707070")
	baseIno := mustLookup(t, f.raw, rootIno, "base.txt").NodeId
	dirIno := mustLookup(t, f.raw, rootIno, "dir").NodeId

	newDir := mustMkdir(t, f.raw, rootIno, "made")
	file := mustCreate(t, f.raw, newDir.NodeId, "f.txt", syscall.S_IFREG|0600)
	mustWrite(t, f.raw, file.NodeId, 0, []byte("payload"))

	sym := &fuse.EntryOut{}
	if st := f.raw.Symlink(nil, header(rootIno), "made/f.txt", "sym", sym); st != fuse.OK {
		t.Fatalf("Symlink = %v", st)
	}
	if sym.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK || sym.Attr.Size != uint64(len("made/f.txt")) {
		t.Fatalf("symlink attr = %+v", sym.Attr)
	}
	if target, st := f.raw.Readlink(nil, header(sym.NodeId)); st != fuse.OK || string(target) != "made/f.txt" {
		t.Fatalf("Readlink = %q, %v", target, st)
	}

	// Hard link a BASE file into the new directory: same inode, nlink 2.
	link := &fuse.EntryOut{}
	if st := f.raw.Link(nil, &fuse.LinkIn{InHeader: *header(newDir.NodeId), Oldnodeid: baseIno}, "hard", link); st != fuse.OK {
		t.Fatalf("Link = %v", st)
	}
	if link.NodeId != baseIno || link.Attr.Nlink != 2 {
		t.Fatalf("link entry = NodeId %d nlink %d, want %d/2", link.NodeId, link.Attr.Nlink, baseIno)
	}

	es := listPlus(t, f.raw, rootIno)
	if got, want := names(es), []string{".", "..", "base.txt", "dir", "made", "sym"}; !equalStrings(got, want) {
		t.Fatalf("root listing = %v, want %v", got, want)
	}
	es = listPlus(t, f.raw, newDir.NodeId)
	if got, want := names(es), []string{".", "..", "f.txt", "hard"}; !equalStrings(got, want) {
		t.Fatalf("made/ listing = %v, want %v", got, want)
	}
	if e := entryOf(es, "hard"); e == nil || e.entry.NodeId != baseIno {
		t.Fatalf("hard link entry = %+v, want inode %d", e, baseIno)
	}

	// Rename across directories moves the inode, not its identity.
	if st := f.raw.Rename(nil, &fuse.RenameIn{InHeader: *header(newDir.NodeId), Newdir: rootIno}, "f.txt", "moved.txt"); st != fuse.OK {
		t.Fatalf("Rename = %v", st)
	}
	moved := mustLookup(t, f.raw, rootIno, "moved.txt")
	if moved.NodeId != file.NodeId {
		t.Fatalf("rename renumbered %d -> %d", file.NodeId, moved.NodeId)
	}
	if got := readAll(t, f.raw, moved.NodeId, 64); !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("content after rename = %q", got)
	}
	if _, st := lookup(t, f.raw, newDir.NodeId, "f.txt"); st != fuse.ENOENT {
		t.Fatalf("source name after rename = %v, want ENOENT", st)
	}

	// Unlink an OVERLAY name and a BASE name; Rmdir the emptied directory.
	if st := f.raw.Unlink(nil, header(newDir.NodeId), "hard"); st != fuse.OK {
		t.Fatalf("Unlink(overlay link) = %v", st)
	}
	if st := f.raw.Rmdir(nil, header(rootIno), "made"); st != fuse.OK {
		t.Fatalf("Rmdir = %v", st)
	}
	mustLookup(t, f.raw, dirIno, "child.txt")
	if st := f.raw.Unlink(nil, header(dirIno), "child.txt"); st != fuse.OK {
		t.Fatalf("Unlink(base entry) = %v", st)
	}
	if _, st := lookup(t, f.raw, dirIno, "child.txt"); st != fuse.ENOENT {
		t.Fatalf("whiteouted base entry = %v, want ENOENT", st)
	}

	es = listPlus(t, f.raw, rootIno)
	if got, want := names(es), []string{".", "..", "base.txt", "dir", "moved.txt", "sym"}; !equalStrings(got, want) {
		t.Fatalf("root listing after removals = %v, want %v", got, want)
	}
	es = listPlus(t, f.raw, dirIno)
	if got, want := names(es), []string{".", "..", "inner"}; !equalStrings(got, want) {
		t.Fatalf("dir listing after unlink = %v, want %v", got, want)
	}
}

func TestRWRenameLoopAndReplace(t *testing.T) {
	f := newRWFixture(t, "40404040-5050-6060-7070-808080808080")
	dirIno := mustLookup(t, f.raw, rootIno, "dir").NodeId
	innerIno := mustLookup(t, f.raw, dirIno, "inner").NodeId

	// Into its own descendant, and into itself: EINVAL, enforced by the
	// binding (the overlay defers the loop check here).
	if st := f.raw.Rename(nil, &fuse.RenameIn{InHeader: *header(rootIno), Newdir: innerIno}, "dir", "loop"); st != fuse.EINVAL {
		t.Fatalf("Rename(dir -> dir/inner/loop) = %v, want EINVAL", st)
	}
	if st := f.raw.Rename(nil, &fuse.RenameIn{InHeader: *header(rootIno), Newdir: dirIno}, "dir", "self"); st != fuse.EINVAL {
		t.Fatalf("Rename(dir -> dir/self) = %v, want EINVAL", st)
	}
	// The guard is directory-only and depth-aware: a sibling move is fine.
	if st := f.raw.Rename(nil, &fuse.RenameIn{InHeader: *header(dirIno), Newdir: rootIno}, "inner", "inner"); st != fuse.OK {
		t.Fatalf("Rename(dir/inner -> /inner) = %v", st)
	}
	if got := mustLookup(t, f.raw, rootIno, "inner").NodeId; got != innerIno {
		t.Fatalf("moved dir inode = %d, want %d", got, innerIno)
	}

	// Rename onto an existing target replaces it.
	src := mustCreate(t, f.raw, rootIno, "src.txt", syscall.S_IFREG|0644)
	mustWrite(t, f.raw, src.NodeId, 0, []byte("source"))
	dst := mustCreate(t, f.raw, rootIno, "dst.txt", syscall.S_IFREG|0644)
	mustWrite(t, f.raw, dst.NodeId, 0, []byte("destination"))
	if st := f.raw.Rename(nil, &fuse.RenameIn{InHeader: *header(rootIno), Newdir: rootIno}, "src.txt", "dst.txt"); st != fuse.OK {
		t.Fatalf("Rename(replace) = %v", st)
	}
	replaced := mustLookup(t, f.raw, rootIno, "dst.txt")
	if replaced.NodeId != src.NodeId {
		t.Fatalf("dst.txt inode = %d, want the source's %d", replaced.NodeId, src.NodeId)
	}
	if got := readAll(t, f.raw, replaced.NodeId, 64); !bytes.Equal(got, []byte("source")) {
		t.Fatalf("replaced content = %q, want %q", got, "source")
	}
	if _, st := lookup(t, f.raw, rootIno, "src.txt"); st != fuse.ENOENT {
		t.Fatalf("src.txt after replace = %v, want ENOENT", st)
	}
}

func TestRWSetAttr(t *testing.T) {
	f := newRWFixture(t, "50505050-6060-7070-8080-909090909090")
	base := mustLookup(t, f.raw, rootIno, "base.txt")
	body := f.body["base.txt"]

	// chmod.
	ao, st := setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_MODE, Mode: 0600},
	})
	if st != fuse.OK || ao.Attr.Mode != syscall.S_IFREG|0600 {
		t.Fatalf("SetAttr(chmod) = %o (%v), want %o", ao.Attr.Mode, st, syscall.S_IFREG|0600)
	}
	checkDirtyValidity(t, "SetAttr reply", ao.AttrValid, ao.AttrValid)
	got, st := getattr(f.raw, base.NodeId)
	if st != fuse.OK || got.Attr.Mode != syscall.S_IFREG|0600 {
		t.Fatalf("GetAttr after chmod = %o (%v)", got.Attr.Mode, st)
	}

	// chown plus mtime, including the MTIME_NOW form.
	ao, st = setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{
			Valid: fuse.FATTR_UID | fuse.FATTR_GID | fuse.FATTR_MTIME,
			Owner: fuse.Owner{Uid: 1234, Gid: 5678},
			Mtime: 1000, Mtimensec: 250,
		},
	})
	if st != fuse.OK || ao.Attr.Uid != 1234 || ao.Attr.Gid != 5678 {
		t.Fatalf("SetAttr(chown) = %+v (%v)", ao.Attr, st)
	}
	if ao.Attr.Mtime != 1000 || ao.Attr.Mtimensec != 250 {
		t.Fatalf("SetAttr(mtime) = %d.%d", ao.Attr.Mtime, ao.Attr.Mtimensec)
	}
	// ATIME is accepted and dropped: the format has no atime, and mtime
	// stands in for it in every reply.
	ao, st = setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_ATIME, Atime: 77, Atimensec: 7},
	})
	if st != fuse.OK || ao.Attr.Atime != ao.Attr.Mtime || ao.Attr.Mtime != 1000 {
		t.Fatalf("SetAttr(atime) = atime %d mtime %d (%v), want atime==mtime==1000",
			ao.Attr.Atime, ao.Attr.Mtime, st)
	}
	ao, st = setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_MTIME | fuse.FATTR_MTIME_NOW},
	})
	if st != fuse.OK || ao.Attr.Mtime <= 1000 {
		t.Fatalf("SetAttr(MTIME_NOW) mtime = %d (%v), want a current timestamp", ao.Attr.Mtime, st)
	}

	// Truncate down: size and content follow (COW of the base file).
	ao, st = setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_SIZE, Size: 8},
	})
	if st != fuse.OK || ao.Attr.Size != 8 {
		t.Fatalf("SetAttr(truncate) size = %d (%v)", ao.Attr.Size, st)
	}
	if got := readAll(t, f.raw, base.NodeId, 64); !bytes.Equal(got, body[:8]) {
		t.Fatalf("content after truncate = %q, want %q", got, body[:8])
	}

	// Truncate up zero-fills.
	if _, st := setattr(t, f.raw, base.NodeId, fuse.SetAttrIn{
		SetAttrInCommon: fuse.SetAttrInCommon{Valid: fuse.FATTR_SIZE, Size: 12},
	}); st != fuse.OK {
		t.Fatalf("SetAttr(extend) = %v", st)
	}
	want := append(append([]byte{}, body[:8]...), 0, 0, 0, 0)
	if got := readAll(t, f.raw, base.NodeId, 64); !bytes.Equal(got, want) {
		t.Fatalf("content after extend = %q, want %q", got, want)
	}
	if got, _ := getattr(f.raw, base.NodeId); got.Attr.Size != 12 {
		t.Fatalf("size after extend = %d, want 12", got.Attr.Size)
	}
}

func TestRWXattr(t *testing.T) {
	f := newRWFixture(t, "60606060-7070-8080-9090-a0a0a0a0a0a0")
	base := mustLookup(t, f.raw, rootIno, "base.txt")

	if st := f.raw.SetXAttr(nil, &fuse.SetXAttrIn{InHeader: *header(base.NodeId)}, "user.color", []byte("green")); st != fuse.OK {
		t.Fatalf("SetXAttr = %v", st)
	}
	// The ERANGE sizing protocol is unchanged on the read side.
	if sz, st := f.raw.GetXAttr(nil, header(base.NodeId), "user.color", make([]byte, 1)); st != fuse.ERANGE || sz != 5 {
		t.Fatalf("GetXAttr(short) = %d, %v; want 5, ERANGE", sz, st)
	}
	dest := make([]byte, 64)
	sz, st := f.raw.GetXAttr(nil, header(base.NodeId), "user.color", dest)
	if st != fuse.OK || string(dest[:sz]) != "green" {
		t.Fatalf("GetXAttr = %q, %v", dest[:sz], st)
	}
	if sz, st := f.raw.ListXAttr(nil, header(base.NodeId), dest); st != fuse.OK ||
		!bytes.Equal(dest[:sz], []byte("user.color\x00")) {
		t.Fatalf("ListXAttr = %q, %v", dest[:sz], st)
	}

	if st := f.raw.RemoveXAttr(nil, header(base.NodeId), "user.color"); st != fuse.OK {
		t.Fatalf("RemoveXAttr = %v", st)
	}
	if _, st := f.raw.GetXAttr(nil, header(base.NodeId), "user.color", dest); st != fuse.ENODATA && int(st) != 93 {
		t.Fatalf("GetXAttr after remove = %v, want ENODATA/ENOATTR", st)
	}
	// Removing what is not there is an xattr-protocol error, not ENOENT.
	if st := f.raw.RemoveXAttr(nil, header(base.NodeId), "user.color"); st != fuse.ENODATA && int(st) != 93 {
		t.Fatalf("RemoveXAttr(missing) = %v, want ENODATA/ENOATTR", st)
	}
}

func TestRWErrors(t *testing.T) {
	f := newRWFixture(t, "70707070-8080-9090-a0a0-b0b0b0b0b0b0")
	dirIno := mustLookup(t, f.raw, rootIno, "dir").NodeId
	mustLookup(t, f.raw, dirIno, "inner")

	if st := f.raw.Unlink(nil, header(rootIno), "absent"); st != fuse.ENOENT {
		t.Fatalf("Unlink(missing) = %v, want ENOENT", st)
	}
	if st := f.raw.Rmdir(nil, header(rootIno), "dir"); st != errNotEmpty {
		t.Fatalf("Rmdir(non-empty) = %v, want ENOTEMPTY", st)
	}
	if st := f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: *header(rootIno), Mode: 0755}, "dir", &fuse.EntryOut{}); st != errExist {
		t.Fatalf("Mkdir(existing) = %v, want EEXIST", st)
	}
	if _, st := create(t, f.raw, rootIno, "dir", syscall.S_IFREG|0644); st != errExist {
		t.Fatalf("Create(existing) = %v, want EEXIST", st)
	}
	if st := f.raw.Unlink(nil, header(rootIno), "dir"); st != fuse.EISDIR {
		t.Fatalf("Unlink(directory) = %v, want EISDIR", st)
	}
	mustLookup(t, f.raw, rootIno, "base.txt")
	if st := f.raw.Rmdir(nil, header(rootIno), "base.txt"); st != fuse.ENOTDIR {
		t.Fatalf("Rmdir(file) = %v, want ENOTDIR", st)
	}
	// Mknod of a directory is the caller's mistake, not an unimplemented op.
	if st := f.raw.Mknod(nil, &fuse.MknodIn{InHeader: *header(rootIno), Mode: syscall.S_IFDIR | 0755}, "nope", &fuse.EntryOut{}); st != fuse.EINVAL {
		t.Fatalf("Mknod(S_IFDIR) = %v, want EINVAL", st)
	}
	// Fabricated node ids stay ESTALE on the write side too.
	if st := f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: *header(1 << 40), Mode: 0755}, "x", &fuse.EntryOut{}); st != errStale {
		t.Fatalf("Mkdir(unresident parent) = %v, want ESTALE", st)
	}
}

func TestRWMknodFifo(t *testing.T) {
	f := newRWFixture(t, "80808080-9090-a0a0-b0b0-c0c0c0c0c0c0")
	out := &fuse.EntryOut{}
	if st := f.raw.Mknod(nil, &fuse.MknodIn{InHeader: *header(rootIno), Mode: syscall.S_IFIFO | 0644}, "fifo", out); st != fuse.OK {
		t.Fatalf("Mknod(fifo) = %v", st)
	}
	if out.Attr.Mode != syscall.S_IFIFO|0644 {
		t.Fatalf("fifo mode = %o", out.Attr.Mode)
	}
	// A bare mode with no S_IFMT bits is a regular file (POSIX mknod).
	if st := f.raw.Mknod(nil, &fuse.MknodIn{InHeader: *header(rootIno), Mode: 0640}, "plain", out); st != fuse.OK {
		t.Fatalf("Mknod(no type bits) = %v", st)
	}
	if out.Attr.Mode != syscall.S_IFREG|0640 {
		t.Fatalf("plain mode = %o", out.Attr.Mode)
	}
}

// The refresher must swap generations and invalidate exactly what
// changed. A nil server exercises swap and reporting without a kernel;
// the mount gate covers the notification path for real.
func TestRefresherSwapsGenerations(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "9e9e9e9e-0000-4000-8000-0000000000ee")

	// Descend as the kernel does — parent before child — so both inodes
	// become resident; only what the kernel holds gets invalidated.
	mustLookup(t, f.raw, rootIno, "dir")
	mustLookup(t, f.raw, f.dirIno, "small.txt")

	// Publish a second generation with that file changed.
	f.vol.Lookup(f.vol.Lookup(rootIno, "dir"), "small.txt")
	f.vol.Truncate(f.smallIno, 0)
	f.vol.Write(f.smallIno, []byte("second generation content"))
	gen1 := f.vol.Publish(publish.Options{TargetPackSize: 2 << 20})

	var fetched int
	r := rawfuse.NewRefresher(f.gfs, nil, func(context.Context) (*superblock.Superblock, error) {
		fetched++
		return gen1.Superblock, nil
	}, 0)
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if fetched != 1 || f.gfs.Generation() != gen1.Superblock.Generation {
		t.Fatalf("fetched=%d generation=%d, want 1 and %d",
			fetched, f.gfs.Generation(), gen1.Superblock.Generation)
	}

	// The mount now serves the new content through the binding.
	entry := mustLookup(t, f.raw, f.dirIno, "small.txt")
	if entry.Attr.Size != uint64(len("second generation content")) {
		t.Fatalf("post-refresh size = %d, want %d", entry.Attr.Size, len("second generation content"))
	}

	// Same head again: no swap, no error.
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("idempotent Refresh: %v", err)
	}
}
