// Package testvol builds real volumes for tests.
//
// A test that needs "a published generation containing this tree" would
// otherwise have to wire up InitVolume, a genfs over the result, an
// overlay over that, and a seal — five packages of boilerplate, repeated
// in every suite that reads a generation back. This does it once.
//
// The volumes it produces are the real thing: signed superblocks, real
// packs, real catalogs. Mutations go through the write overlay, and
// Publish seals them into the next generation exactly as an unmounting
// writable mount does, so a fixture never exercises a code path that
// production does not.
package testvol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// RootInode is the tree root of every volume.
const RootInode = genfs.RootInode

// ParseUUID turns a canonical UUID string into a volume id, so a fixture
// can pin an identity readably (two volumes that must not be confused for
// each other, say) instead of by 32 hex digits.
func ParseUUID(t testing.TB, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("bad volume uuid %q", s)
	}
	var id [16]byte
	copy(id[:], b)
	return id
}

// Options configures the volume New creates.
type Options struct {
	// VolumeID identifies the volume; zero mints a random one.
	VolumeID [16]byte
	// Branch defaults to "main".
	Branch string
	// SigningKey signs every generation; nil mints one.
	SigningKey ed25519.PrivateKey
	// DEK/IdentityKey/KeyID/KeyTable make the volume encrypted. They are
	// passed through to every publish and to the genfs that reads it back.
	DEK         []byte
	IdentityKey []byte
	KeyID       uint32
	KeyTable    []superblock.KeyEntry
	// Grace records T_grace on generation 0; zero takes the format's
	// default. Set on the CREATE only, exactly as `pelfs init --grace`
	// does — every later seal carries the recorded value forward, and a
	// fixture that re-stated it on each publish would be exercising
	// something no writer does.
	Grace time.Duration
}

// Volume is a live volume: the published head, plus a write overlay over
// it that Publish seals into the next generation.
type Volume struct {
	t     testing.TB
	inner pelicanobj.Store
	opts  Options
	dir   string

	sb      *superblock.Superblock
	raw     []byte
	gfs     *genfs.FS
	ov      *overlay.FS
	seq     int
	stopped bool
}

// New creates generation 0 (an empty root) and opens a write overlay over
// it. Mutate through the Volume, then call Publish.
func New(t testing.TB, inner pelicanobj.Store, o Options) *Volume {
	t.Helper()
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.SigningKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate signing key: %v", err)
		}
		o.SigningKey = priv
	}
	if o.VolumeID == ([16]byte{}) {
		if _, err := rand.Read(o.VolumeID[:]); err != nil {
			t.Fatalf("mint volume id: %v", err)
		}
	}
	v := &Volume{t: t, inner: inner, opts: o, dir: t.TempDir()}
	res, err := publish.InitVolume(context.Background(), publish.Options{
		Inner:       inner,
		SpoolDir:    v.dir,
		Branch:      o.Branch,
		SigningKey:  o.SigningKey,
		VolumeID:    o.VolumeID,
		DEK:         o.DEK,
		IdentityKey: o.IdentityKey,
		KeyID:       o.KeyID,
		KeyTable:    o.KeyTable,
		Grace:       o.Grace,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	v.sb, v.raw = res.Superblock, res.Raw
	v.openLayers()
	t.Cleanup(v.close)
	return v
}

// Superblock is the current head: generation 0 until the first Publish.
func (v *Volume) Superblock() *superblock.Superblock { return v.sb }

// Raw is the head's wire bytes (a successor generation's lineage input).
func (v *Volume) Raw() []byte { return v.raw }

// SigningKey is the volume's identity; a test that publishes on its own
// must reuse it or every reader rejects the result.
func (v *Volume) SigningKey() ed25519.PrivateKey { return v.opts.SigningKey }

// Overlay is the live write overlay, for operations this helper does not
// wrap.
func (v *Volume) Overlay() *overlay.FS { return v.ov }

func (v *Volume) openLayers() {
	v.t.Helper()
	ctx := context.Background()
	gfs, err := genfs.Open(ctx, genfs.Options{
		Inner:    v.inner,
		SB:       v.sb,
		DEK:      v.opts.DEK,
		CacheDir: filepath.Join(v.dir, "gencache"),
	})
	if err != nil {
		v.t.Fatalf("genfs.Open: %v", err)
	}
	v.seq++
	ov, err := overlay.Open(filepath.Join(v.dir, "overlay", itoa(v.seq)), gfs, overlay.Options{
		NextInode:      gfs.NextInode(),
		BaseRoot:       gfs.RootCatalog(),
		BaseGeneration: gfs.Generation(),
	})
	if err != nil {
		_ = gfs.Close()
		v.t.Fatalf("overlay.Open: %v", err)
	}
	v.gfs, v.ov = gfs, ov
}

func (v *Volume) closeLayers() {
	if v.ov != nil {
		_ = v.ov.Close()
		v.ov = nil
	}
	if v.gfs != nil {
		_ = v.gfs.Close()
		v.gfs = nil
	}
}

func (v *Volume) close() {
	if v.stopped {
		return
	}
	v.stopped = true
	v.closeLayers()
}

// Publish seals everything written since the last Publish into the next
// generation and reopens the overlay over it. Options carries the
// per-publish knobs (SMax, TargetPackSize, ...); the volume fills in the
// rest.
func (v *Volume) Publish(o publish.Options) *publish.Result {
	v.t.Helper()
	o.Overlay = v.ov
	o.Inner = v.inner
	o.SpoolDir = v.t.TempDir()
	o.Branch = v.opts.Branch
	o.SigningKey = v.opts.SigningKey
	o.Prev, o.PrevRaw = v.sb, v.raw
	o.DEK, o.IdentityKey, o.KeyID = v.opts.DEK, v.opts.IdentityKey, v.opts.KeyID
	o.KeyTable = v.opts.KeyTable
	res, err := publish.Seal(context.Background(), o)
	if err != nil {
		v.t.Fatalf("publish: %v", err)
	}
	v.sb, v.raw = res.Superblock, res.Raw
	// A sealed overlay is spent: it is pinned to the generation it
	// shadowed, which is no longer the head. Start a fresh one over what
	// was just published.
	v.closeLayers()
	v.openLayers()
	return res
}

// SetBranch points the volume's next Publish at another ref.
//
// It is deliberately separate from Adopt, because the two halves are
// separate in reality: a branch is a NAME over a generation, so publishing
// onto one means both building on that branch's head (Adopt) and flipping
// that branch's ref (this). A test that did one without the other would be
// describing something the tool cannot do, and would prove nothing about
// it.
func (v *Volume) SetBranch(name string) { v.opts.Branch = name }

// Branch is the ref the next Publish flips.
func (v *Volume) Branch() string { return v.opts.Branch }

// Adopt re-seats the volume on a generation SOMEONE ELSE published — a
// repack, or a second writer — exactly as a mount does when it notices the
// branch has moved (genfs.Swap).
//
// A test that repacks and then goes on writing needs it: without it the
// volume keeps growing from a generation that is no longer the head, and
// the next seal either loses the repack or is refused for it. Pending
// overlay writes are discarded, so adopt at a point where there are none.
func (v *Volume) Adopt(sb *superblock.Superblock, raw []byte) {
	v.t.Helper()
	v.closeLayers()
	v.sb, v.raw = sb, raw
	v.openLayers()
}

// ---- tree mutation ----

// Lookup resolves one name and returns its inode. The overlay establishes
// residency on the way DOWN, so an inode that came from an earlier
// generation must be looked up by descent before it can be written; this
// is what a kernel does on every path it touches.
func (v *Volume) Lookup(parent uint64, name string) uint64 {
	v.t.Helper()
	n, err := v.ov.Lookup(context.Background(), parent, name)
	if err != nil {
		v.t.Fatalf("lookup %s: %v", name, err)
	}
	return n.Inode
}

func (v *Volume) Mkdir(parent uint64, name string) uint64 {
	v.t.Helper()
	n, err := v.ov.Mkdir(context.Background(), parent, name, 0755, 0, 0)
	if err != nil {
		v.t.Fatalf("mkdir %s: %v", name, err)
	}
	return n.Inode
}

func (v *Volume) Create(parent uint64, name string) uint64 {
	v.t.Helper()
	n, err := v.ov.Create(context.Background(), parent, name, 0644, 0, 0)
	if err != nil {
		v.t.Fatalf("create %s: %v", name, err)
	}
	return n.Inode
}

// Write replaces a file's content from offset zero.
func (v *Volume) Write(ino uint64, data []byte) { v.WriteAt(ino, 0, data) }

func (v *Volume) WriteAt(ino uint64, off int64, data []byte) {
	v.t.Helper()
	for done := 0; done < len(data); {
		n, err := v.ov.Write(context.Background(), ino, off+int64(done), data[done:])
		if err != nil {
			v.t.Fatalf("write inode %d at %d: %v", ino, off+int64(done), err)
		}
		if n == 0 {
			v.t.Fatalf("write inode %d at %d made no progress", ino, off+int64(done))
		}
		done += n
	}
}

// WriteFile is the common case: create a file and fill it.
func (v *Volume) WriteFile(parent uint64, name string, data []byte) uint64 {
	v.t.Helper()
	ino := v.Create(parent, name)
	if len(data) > 0 {
		v.Write(ino, data)
	}
	return ino
}

func (v *Volume) Symlink(parent uint64, name, target string) uint64 {
	v.t.Helper()
	n, err := v.ov.Symlink(context.Background(), parent, name, target, 0, 0)
	if err != nil {
		v.t.Fatalf("symlink %s: %v", name, err)
	}
	return n.Inode
}

func (v *Volume) Link(ino, parent uint64, name string) {
	v.t.Helper()
	if _, err := v.ov.Link(context.Background(), ino, parent, name); err != nil {
		v.t.Fatalf("link %s: %v", name, err)
	}
}

func (v *Volume) SetXattr(ino uint64, name string, value []byte) {
	v.t.Helper()
	if err := v.ov.SetXattr(context.Background(), ino, name, value); err != nil {
		v.t.Fatalf("setxattr %s: %v", name, err)
	}
}

func (v *Volume) Unlink(parent uint64, name string) {
	v.t.Helper()
	if err := v.ov.Unlink(context.Background(), parent, name); err != nil {
		v.t.Fatalf("unlink %s: %v", name, err)
	}
}

func (v *Volume) Rmdir(parent uint64, name string) {
	v.t.Helper()
	if err := v.ov.Rmdir(context.Background(), parent, name); err != nil {
		v.t.Fatalf("rmdir %s: %v", name, err)
	}
}

func (v *Volume) Chmod(ino uint64, mode uint32) {
	v.t.Helper()
	m := mode
	if _, err := v.ov.SetAttr(context.Background(), ino, overlay.SetAttrIn{Mode: &m}); err != nil {
		v.t.Fatalf("chmod inode %d: %v", ino, err)
	}
}

func (v *Volume) Truncate(ino uint64, size int64) {
	v.t.Helper()
	s := size
	if _, err := v.ov.SetAttr(context.Background(), ino, overlay.SetAttrIn{Size: &s}); err != nil {
		v.t.Fatalf("truncate inode %d: %v", ino, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
