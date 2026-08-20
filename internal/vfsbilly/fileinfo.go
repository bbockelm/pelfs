package vfsbilly

import (
	"io/fs"
	"os"
	"syscall"
	"time"

	nfsfile "github.com/willscott/go-nfs/file"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/idmap"
)

// info presents a genfs.Node as os.FileInfo.
//
// Sys() returns go-nfs's file.FileInfo rather than the node: go-nfs reads
// link count, ownership, and the NFS fileid from exactly that type, and
// without it falls back to hashing the path — a fileid that changes under
// rename, which clients read as a different file. Node() exposes the node
// itself for callers that want it.
type info struct {
	name string
	node genfs.Node
	sys  nfsfile.FileInfo
}

var _ os.FileInfo = (*info)(nil)

func newInfo(name string, n genfs.Node, ids idmap.Map) *info {
	// Whose name to put on it. The NFS backend serves the same volumes the
	// FUSE one does, from the same machines, so it answers the ownership
	// question the same way (internal/idmap).
	uid, gid := ids.Apply(n.UID, n.GID)
	nlink := n.Nlink
	if nlink == 0 {
		nlink = 1
	}
	// Major/Minor stay zero: device nodes are out of scope for a mounted
	// scratch volume, and splitting rdev portably needs x/sys/unix.
	return &info{name: name, node: n, sys: nfsfile.FileInfo{
		Nlink:  nlink,
		UID:    uid,
		GID:    gid,
		Fileid: n.Inode,
	}}
}

func (i *info) Name() string       { return i.name }
func (i *info) Size() int64        { return i.node.Length }
func (i *info) Mode() os.FileMode  { return nodeMode(i.node) }
func (i *info) ModTime() time.Time { return time.Unix(0, i.node.MtimeNS) }
func (i *info) IsDir() bool        { return i.node.Type == catalog.TypeDir }
func (i *info) Sys() any           { return &i.sys }

// Node returns the underlying generation node.
func (i *info) Node() genfs.Node { return i.node }

// nodeMode projects a node onto os.FileMode: permission bits from the
// stored mode, type bits from the catalog entry type (the stored mode's
// S_IFMT half is not authoritative — see rawfuse.fillAttr).
func nodeMode(n genfs.Node) os.FileMode {
	m := fs.FileMode(n.Mode & 0777)
	if n.Mode&syscall.S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if n.Mode&syscall.S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if n.Mode&syscall.S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	switch n.Type {
	case catalog.TypeDir:
		m |= os.ModeDir
	case catalog.TypeSymlink:
		m |= os.ModeSymlink
	case catalog.TypeFIFO:
		m |= os.ModeNamedPipe
	case catalog.TypeSocket:
		m |= os.ModeSocket
	case catalog.TypeCharDev:
		m |= os.ModeDevice | os.ModeCharDevice
	case catalog.TypeBlockDev:
		m |= os.ModeDevice
	}
	return m
}

// unixMode is the inverse for SETATTR: the stat mode bits the overlay
// stores, S_IFMT excluded (the type comes from the entry, not the mode).
func unixMode(m os.FileMode) uint32 {
	out := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		out |= syscall.S_ISUID
	}
	if m&os.ModeSetgid != 0 {
		out |= syscall.S_ISGID
	}
	if m&os.ModeSticky != 0 {
		out |= syscall.S_ISVTX
	}
	return out
}
