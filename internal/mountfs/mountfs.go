// Package mountfs assembles the JuiceFS library pieces (SQLite metadata
// engine, cached chunk store, VFS, FUSE server) into an in-process mount
// backed by a Pelican federation, mirroring the essential parts of
// `juicefs format` + `juicefs mount`.
package mountfs

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/fuse"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/juicedata/juicefs/pkg/utils"
	"github.com/juicedata/juicefs/pkg/version"
	"github.com/juicedata/juicefs/pkg/vfs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var logger = utils.GetLogger("pelfs")

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
	// FlushTimeout bounds how long Close waits for writeback-staged blocks
	// to finish uploading (0 = wait forever). Only relevant with Writeback.
	FlushTimeout time.Duration

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
	v            *vfs.VFS
	store        chunk.ChunkStore
	registry     *prometheus.Registry
	writeback    bool
	flushTimeout time.Duration
	served       chan error
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
	if opts.Debug {
		utils.SetLogLevel(logrus.DebugLevel)
	} else {
		utils.SetLogLevel(logrus.WarnLevel)
	}

	if opts.Compression == "" {
		opts.Compression = "none"
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
		MaxRetries:  10,
		Writeback:   opts.Writeback,
		Prefetch:    1,
		BufferSize:  300 << 20,

		CacheDir:       opts.CacheDir,
		CacheSize:      uint64(opts.CacheSizeMiB) << 20,
		FreeSpace:      0.1,
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

	var rawOpts string
	if runtime.GOOS == "darwin" {
		rawOpts = "allow_recursion"
	}
	fuseOpts := vfs.FuseOptions(fuse.GenFuseOpt(vfsConf, rawOpts, 1, true, true, 1<<17))
	vfsConf.FuseOpts = &fuseOpts

	v := vfs.NewVFS(vfsConf, m, store, registerer, registry)

	mnt := &Mounted{
		MountPoint:   opts.MountPoint,
		m:            m,
		blob:         opts.Blob,
		v:            v,
		store:        store,
		registry:     registry,
		writeback:    opts.Writeback,
		flushTimeout: opts.FlushTimeout,
		served:       make(chan error, 1),
	}
	go func() {
		mnt.served <- fuse.Serve(v, rawOpts, false, false)
	}()

	if err := waitForMount(opts.MountPoint, mnt.served); err != nil {
		_ = m.CloseSession()
		return nil, err
	}
	return mnt, nil
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
