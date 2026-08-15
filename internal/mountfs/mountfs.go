// Package mountfs assembles the JuiceFS library pieces (SQLite metadata
// engine, cached chunk store, VFS, FUSE server) into an in-process mount
// backed by a Pelican federation, mirroring the essential parts of
// `juicefs format` + `juicefs mount`.
package mountfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/juicedata/juicefs/pkg/chunk"
	jfs "github.com/juicedata/juicefs/pkg/fs"
	"github.com/juicedata/juicefs/pkg/fuse"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/juicedata/juicefs/pkg/utils"
	"github.com/juicedata/juicefs/pkg/version"
	"github.com/juicedata/juicefs/pkg/vfs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/bbockelm/pelfs/internal/nfsmount"
)

var logger = utils.GetLogger("pelfs")

// lineFilterWriter drops log lines containing any of the given substrings.
// logrus writes one entry per Write call, so per-call matching is safe.
type lineFilterWriter struct {
	w    io.Writer
	drop []string
}

func (f *lineFilterWriter) Write(p []byte) (int, error) {
	for _, s := range f.drop {
		if bytes.Contains(p, []byte(s)) {
			return len(p), nil
		}
	}
	return f.w.Write(p)
}

// encryptAlgo records the (only) data-encryption algorithm pelfs uses when a
// key is configured; empty otherwise so the format omits it.
func encryptAlgo(keyPEM string) string {
	if keyPEM == "" {
		return ""
	}
	return "aes256gcm-rsa"
}

// Options configures an in-process JuiceFS mount.
type Options struct {
	VolumeName string // JuiceFS volume name
	MetaPath   string // path of the SQLite metadata database
	MountPoint string // directory to mount on (must exist)
	CacheDir   string // local block-cache directory
	PrefixURL  string // recorded in the volume format (informational)
	Blob       object.ObjectStorage

	BlockSizeKiB int   // object block size in KiB (default 4096)
	CacheSizeMiB int64 // local cache size limit (default 10240)
	Writeback    bool  // asynchronous block upload
	ReadOnly     bool  // mount read-only (metadata rejects modification)
	Debug        bool
	// IORetries caps how many times a failing block operation is retried
	// (default 5). Each attempt is bounded by a 60s timeout, so this also
	// bounds how long a blocked read/write hangs when the federation is
	// unreachable before the caller sees EIO.
	IORetries int
	// FlushTimeout bounds how long Close waits for writeback-staged blocks
	// to finish uploading (0 = wait forever). Only relevant with Writeback.
	FlushTimeout time.Duration
	// CacheFreeRatio is the minimum free space/inode fraction the block
	// cache tries to preserve on its filesystem (default 0.05).
	CacheFreeRatio float64

	// Backend selects how the filesystem is exposed to the OS: "fuse"
	// (default) uses the kernel FUSE interface; "nfs" serves NFSv3 on
	// 127.0.0.1 and mounts it with the OS NFS client — kext- and
	// install-free on macOS (works unprivileged).
	Backend string

	// Compression ("none" or "zstd") is recorded in the volume format at
	// creation; an existing volume's setting always wins.
	Compression string
	// EncryptKeyPEM, when non-empty, is recorded in the volume format at
	// creation and signals that opts.Blob is already wrapped with
	// client-side encryption. Mounting an encrypted volume without it (or
	// vice versa) is refused.
	EncryptKeyPEM string
}

// Mounted is a live mount; Close unmounts and flushes it.
type Mounted struct {
	MountPoint string

	m            meta.Meta
	blob         object.ObjectStorage
	v            *vfs.VFS // FUSE backend only
	store        chunk.ChunkStore
	registry     *prometheus.Registry
	writeback    bool
	flushTimeout time.Duration
	served       chan error

	// NFS backend only.
	jfs    *jfs.FileSystem
	nfsSrv *nfsmount.Server
}

// Mount formats the metadata database if needed, starts a FUSE server on
// opts.MountPoint, and waits until the mount is visible.
func Mount(opts Options) (*Mounted, error) {
	if opts.BlockSizeKiB <= 0 {
		opts.BlockSizeKiB = 4096
	}
	if opts.CacheSizeMiB <= 0 {
		opts.CacheSizeMiB = 10240
	}
	if opts.IORetries <= 0 {
		opts.IORetries = 5
	}
	if opts.CacheFreeRatio <= 0 {
		opts.CacheFreeRatio = 0.05
	}
	if opts.Debug {
		utils.SetLogLevel(logrus.DebugLevel)
	} else {
		utils.SetLogLevel(logrus.WarnLevel)
	}
	// pelfs always uses a local SQLite metadata file, so JuiceFS's
	// database-latency warning (a fixed 5ms ping threshold aimed at remote
	// MySQL/Postgres) is noise — the first ping includes file open and WAL
	// setup, which slow container filesystems routinely exceed.
	utils.SetOutput(&lineFilterWriter{
		w:    os.Stderr,
		drop: []string{"The latency to database is too high"},
	})

	if opts.Compression == "" {
		opts.Compression = "none"
	}

	// Unprivileged sessions take ownership of the whole volume before
	// mounting: files created by other sessions (e.g. the root-running
	// Docker fallback) would otherwise be unwritable through the kernel's
	// mode-bit checks on a FUSE mount.
	if os.Getuid() != 0 {
		if n, err := squashOwnership(opts.MetaPath, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
			logger.Warnf("could not normalize volume ownership: %s", err)
		} else if n > 0 {
			logger.Infof("took ownership of %d inodes created by other sessions", n)
		}
	}

	metaConf := meta.DefaultConf()
	metaConf.MountPoint = opts.MountPoint
	metaConf.AtimeMode = meta.NoAtime
	metaConf.ReadOnly = opts.ReadOnly

	m := meta.NewClient("sqlite3://"+opts.MetaPath, metaConf)
	format, err := m.Load(true)
	if err != nil {
		if opts.ReadOnly {
			return nil, fmt.Errorf("no volume metadata found (and read-only mode cannot create one): %w", err)
		}
		// Fresh database: create the volume.
		format = &meta.Format{
			Name:        opts.VolumeName,
			UUID:        uuid.New().String(),
			Storage:     "pelican",
			Bucket:      opts.PrefixURL,
			BlockSize:   opts.BlockSizeKiB,
			Compression: opts.Compression,
			EncryptKey:  opts.EncryptKeyPEM,
			EncryptAlgo: encryptAlgo(opts.EncryptKeyPEM),
			TrashDays:   0,
			DirStats:    true,
		}
		if err := m.Init(format, false); err != nil {
			return nil, fmt.Errorf("initialize volume metadata: %w", err)
		}
		if format, err = m.Load(true); err != nil {
			return nil, fmt.Errorf("load volume metadata: %w", err)
		}
	}
	if format.EncryptKey != "" && opts.EncryptKeyPEM == "" {
		return nil, fmt.Errorf("volume %q is encrypted; supply --encrypt-key", format.Name)
	}
	if format.EncryptKey == "" && opts.EncryptKeyPEM != "" {
		return nil, fmt.Errorf("volume %q is not encrypted, but --encrypt-key was given; refusing to mix encrypted and plaintext blocks", format.Name)
	}
	if format.Compression != opts.Compression {
		logger.Warnf("volume compression is %q (fixed at creation); ignoring requested %q", format.Compression, opts.Compression)
	}

	chunkConf := chunk.Config{
		BlockSize:  format.BlockSize * 1024,
		Compress:   format.Compression,
		HashPrefix: format.HashPrefix,

		GetTimeout:  time.Minute,
		PutTimeout:  time.Minute,
		MaxUpload:   20,
		MaxDownload: 100,
		MaxRetries:  opts.IORetries,
		Writeback:   opts.Writeback,
		Prefetch:    1,
		BufferSize:  300 << 20,

		CacheDir:       opts.CacheDir,
		CacheSize:      uint64(opts.CacheSizeMiB) << 20,
		FreeSpace:      float32(opts.CacheFreeRatio),
		CacheMode:      0600,
		CacheFullBlock: true,
		CacheChecksum:  "full",
		CacheEviction:  "2-random",
		OSCache:        true,
		AutoCreate:     true,
	}
	chunkConf.Readahead = 8 * chunkConf.BlockSize
	chunkConf.SelfCheck(format.UUID)

	registry := prometheus.NewRegistry()
	registerer := prometheus.WrapRegistererWithPrefix("juicefs_",
		prometheus.WrapRegistererWith(prometheus.Labels{"mp": opts.MountPoint, "vol_name": format.Name}, registry))

	store := chunk.NewCachedStore(opts.Blob, chunkConf, registerer)
	m.OnMsg(meta.DeleteSlice, func(args ...interface{}) error {
		return store.Remove(args[0].(uint64), int(args[1].(uint32)))
	})
	m.OnMsg(meta.CompactChunk, func(args ...interface{}) error {
		return vfs.Compact(chunkConf, store, args[0].([]meta.Slice), args[1].(uint64), args[2].(uint8))
	})

	if err := m.NewSession(true); err != nil {
		return nil, fmt.Errorf("create metadata session: %w", err)
	}

	vfsConf := &vfs.Config{
		Meta:     metaConf,
		Format:   *format,
		Version:  version.Version(),
		Chunk:    &chunkConf,
		Security: &vfs.SecurityConfig{},
		Port:     &vfs.Port{},
		Pid:      os.Getpid(),
		PPid:     os.Getppid(),
		UMask:    0xFFFF,
	}

	mnt := &Mounted{
		MountPoint:   opts.MountPoint,
		m:            m,
		blob:         opts.Blob,
		store:        store,
		registry:     registry,
		writeback:    opts.Writeback,
		flushTimeout: opts.FlushTimeout,
		served:       make(chan error, 1),
	}

	if opts.Backend == "nfs" {
		fsys, err := jfs.NewFileSystem(vfsConf, m, store, registry)
		if err != nil {
			_ = m.CloseSession()
			return nil, fmt.Errorf("filesystem layer: %w", err)
		}
		bfs := nfsmount.NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid()))
		srv, err := nfsmount.Serve(bfs)
		if err != nil {
			_ = m.CloseSession()
			return nil, err
		}
		if err := srv.Mount(opts.MountPoint, format.Name); err != nil {
			_ = srv.Close()
			_ = m.CloseSession()
			return nil, err
		}
		mnt.jfs = fsys
		mnt.nfsSrv = srv
		if err := waitForMounted(opts.MountPoint); err != nil {
			_ = nfsmount.Unmount(opts.MountPoint)
			_ = srv.Close()
			_ = m.CloseSession()
			return nil, err
		}
		return mnt, nil
	}

	var rawOpts string
	if runtime.GOOS == "darwin" {
		rawOpts = "allow_recursion"
	}
	fuseOpts := vfs.FuseOptions(fuse.GenFuseOpt(vfsConf, rawOpts, 1, true, true, 1<<17))
	vfsConf.FuseOpts = &fuseOpts

	v := vfs.NewVFS(vfsConf, m, store, registerer, registry)
	mnt.v = v
	go func() {
		mnt.served <- fuse.Serve(v, rawOpts, false, false)
	}()

	if err := waitForMount(opts.MountPoint, mnt.served); err != nil {
		_ = m.CloseSession()
		return nil, err
	}
	return mnt, nil
}

// waitForMounted polls until the mountpoint is attached (no server error
// channel variant, for the NFS backend where mount_nfs already returned).
func waitForMounted(mp string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if mounted(mp) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to mount", mp)
}

// waitForMount polls until the mountpoint's device differs from its
// parent's, i.e. the FUSE filesystem is attached.
func waitForMount(mp string, served <-chan error) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-served:
			if err == nil {
				err = fmt.Errorf("FUSE server exited before mount became visible")
			}
			return err
		default:
		}
		if mounted(mp) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to mount", mp)
}

func mounted(mp string) bool {
	var st, pst syscall.Stat_t
	if err := syscall.Stat(mp, &st); err != nil {
		return false
	}
	parent := mp
	if i := strings.LastIndex(strings.TrimRight(mp, "/"), "/"); i > 0 {
		parent = mp[:i]
	} else {
		parent = "/"
	}
	if err := syscall.Stat(parent, &pst); err != nil {
		return false
	}
	return st.Dev != pst.Dev
}

// Close unmounts the filesystem, flushes pending writes to the federation,
// and closes the metadata session. Safe to call once.
func (mnt *Mounted) Close() error {
	if mnt.nfsSrv != nil {
		return mnt.closeNFS()
	}
	var umountErr error
	for attempt := 0; ; attempt++ {
		umountErr = unmountCmd(mnt.MountPoint, attempt >= 3)
		select {
		case err := <-mnt.served:
			if err != nil {
				logger.Warnf("FUSE server: %s", err)
			}
			goto down
		case <-time.After(2 * time.Second):
			if attempt >= 5 {
				return fmt.Errorf("could not unmount %s: %v", mnt.MountPoint, umountErr)
			}
		}
	}
down:
	var flushErr error
	if err := mnt.v.FlushAll(""); err != nil {
		logger.Errorf("flush delayed data: %s", err)
		flushErr = fmt.Errorf("flush delayed data: %w", err)
	}
	// With writeback, blocks may still sit in the local staging area; they
	// are the only copy of the data, so the final upload must complete.
	if mnt.writeback && flushErr == nil {
		if err := mnt.drainStaging(mnt.flushTimeout); err != nil {
			flushErr = fmt.Errorf("writeback staging: %w", err)
		}
	}
	err := mnt.m.CloseSession()
	object.Shutdown(mnt.blob)
	if flushErr != nil {
		return flushErr
	}
	return err
}

// closeNFS is Close for the loopback-NFS backend: detach the OS mount, stop
// the server, then flush and shut down the volume like the FUSE path.
func (mnt *Mounted) closeNFS() error {
	umountErr := nfsmount.Unmount(mnt.MountPoint)
	if umountErr != nil {
		logger.Warnf("unmount %s: %s", mnt.MountPoint, umountErr)
	}
	_ = mnt.nfsSrv.Close()

	var flushErr error
	if err := mnt.jfs.Flush(); err != nil {
		logger.Errorf("flush delayed data: %s", err)
		flushErr = fmt.Errorf("flush delayed data: %w", err)
	}
	if mnt.writeback && flushErr == nil {
		if err := mnt.drainStaging(mnt.flushTimeout); err != nil {
			flushErr = fmt.Errorf("writeback staging: %w", err)
		}
	}
	err := mnt.m.CloseSession()
	object.Shutdown(mnt.blob)
	switch {
	case flushErr != nil:
		return flushErr
	case umountErr != nil:
		return umountErr
	default:
		return err
	}
}

func unmountCmd(mp string, force bool) error {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		if force {
			candidates = [][]string{{"umount", "-f", mp}, {"diskutil", "unmount", "force", mp}}
		} else {
			candidates = [][]string{{"umount", mp}}
		}
	default:
		if force {
			candidates = [][]string{{"umount", "-l", mp}, {"fusermount3", "-uz", mp}, {"fusermount", "-uz", mp}}
		} else {
			candidates = [][]string{{"umount", mp}, {"fusermount3", "-u", mp}, {"fusermount", "-u", mp}}
		}
	}
	var lastErr error
	for _, c := range candidates {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
	}
	return lastErr
}
