package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// InitVolume creates generation 0 of a brand-new volume: an empty root
// directory, one catalog, one pack, a signed ref. Everything after it is
// ordinary — mount the generation read-write and seal. Options.VolumeID
// must be set (the caller owns volume identity); Overlay must not be.
func InitVolume(ctx context.Context, o Options) (*Result, error) {
	if o.Prev != nil {
		return nil, errors.New("publish: InitVolume creates generation 0; a volume with generations already exists")
	}
	if o.Overlay != nil || o.OverlaySnapshot != nil {
		return nil, errors.New("publish: InitVolume takes no source (it creates an empty root)")
	}
	if o.VolumeID == ([16]byte{}) {
		return nil, errors.New("publish: InitVolume requires a VolumeID")
	}
	o.emptySource = true
	return Publish(ctx, o)
}

// emptyRoot is the Source of a volume with nothing in it: one directory,
// inode 1, no entries. Publish needs no special case — an empty tree is
// just a tree.
type emptyRoot struct{ nextInode uint64 }

func (e *emptyRoot) Root() uint64      { return 1 }
func (e *emptyRoot) NextInode() uint64 { return e.nextInode }
func (e *emptyRoot) Readdir(context.Context, uint64) ([]SrcEntry, error) {
	return nil, nil
}

func (e *emptyRoot) Stat(_ context.Context, ino uint64) (SrcNode, error) {
	if ino != 1 {
		return SrcNode{}, fmt.Errorf("publish: empty volume has no inode %d", ino)
	}
	// Own the root as the user creating the volume. Leaving UID/GID at
	// zero made a fresh volume's root owned by root with mode 0755 --
	// unwritable by the very person who just created it, so the first
	// command run in the new mount failed with EPERM. It only escaped
	// notice because the container gate runs as root.
	return SrcNode{
		Inode: 1,
		Type:  catalog.TypeDir,
		Mode:  0755,
		UID:   uint32(os.Getuid()),
		GID:   uint32(os.Getgid()),
		Nlink: 2,
	}, nil
}

func (e *emptyRoot) Readlink(context.Context, uint64) (string, error) {
	return "", errors.New("publish: empty volume has no symlinks")
}

func (e *emptyRoot) Xattrs(context.Context, uint64) (map[string][]byte, error) {
	return nil, nil
}

func (e *emptyRoot) Open(context.Context, uint64, int64) (io.ReadCloser, error) {
	return nil, errors.New("publish: empty volume has no files")
}
