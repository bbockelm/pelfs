// Package snapshot periodically copies the JuiceFS SQLite metadata database
// into the federation under <prefix>/meta/<session-id>/, and restores the
// most recent snapshot on startup. Snapshots are taken with `VACUUM INTO`,
// which produces a consistent copy even while the mount is writing (the
// database runs in WAL mode).
//
// Each periodic snapshot overwrites the same object,
// meta/<session>/current.db, relying on the origin's ETag support: the ETag
// observed after each upload is compared against the object before the next
// overwrite, so a concurrent writer to the same session directory is
// detected instead of silently clobbered. A separate final.db is written
// once at shutdown, after the filesystem has quiesced.
package snapshot

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// MetaDir is the key-space directory (relative to the federation prefix)
// holding metadata snapshots.
const MetaDir = "meta"

const (
	currentName = "current.db"
	finalName   = "final.db"
)

// ErrConflict indicates another writer modified this session's snapshot
// object — a second mount is likely active on the same prefix.
var ErrConflict = errors.New("snapshot object was modified by another writer (concurrent mount on this prefix?)")

// Manager uploads snapshots of one SQLite database to one session directory.
type Manager struct {
	MetaPath string           // local sqlite database path
	Store    pelicanobj.Store // federation prefix store
	Session  string           // unique per-session subdirectory name

	lastETag string // ETag of current.db after our most recent upload
}

// NewSessionID returns a directory name unique to this mount session.
func NewSessionID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102T150405Z"), host, hex.EncodeToString(b[:]))
}

// Run uploads a snapshot every interval until ctx is canceled. On a
// detected conflict it stops snapshotting (continuing would clobber the
// other writer).
func (mgr *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := mgr.Snapshot(ctx, false); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: metadata snapshot failed: %v\n", err)
				if errors.Is(err, ErrConflict) {
					return
				}
			}
		}
	}
}

func (mgr *Manager) currentKey() string {
	return fmt.Sprintf("%s/%s/%s", MetaDir, mgr.Session, currentName)
}

// Snapshot takes one consistent copy of the database and uploads it,
// overwriting meta/<session>/current.db (or writing final.db when final is
// set). Before overwriting, the object's ETag is compared with the one from
// our previous upload to detect a concurrent writer.
func (mgr *Manager) Snapshot(ctx context.Context, final bool) error {
	if mgr.lastETag != "" {
		if ki, err := mgr.Store.StatKey(ctx, mgr.currentKey()); err == nil &&
			ki.ETag != "" && ki.ETag != mgr.lastETag {
			return fmt.Errorf("%s: %w", mgr.currentKey(), ErrConflict)
		}
	}

	tmp := mgr.MetaPath + ".snap"
	_ = os.Remove(tmp) // VACUUM INTO refuses to overwrite
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite3", mgr.MetaPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return fmt.Errorf("VACUUM INTO: %w", err)
	}

	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	key := mgr.currentKey()
	if final {
		key = fmt.Sprintf("%s/%s/%s", MetaDir, mgr.Session, finalName)
	}
	if err := mgr.Store.Put(ctx, key, f); err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	if !final {
		if ki, err := mgr.Store.StatKey(ctx, key); err == nil {
			mgr.lastETag = ki.ETag
		}
	}
	return nil
}

// Restore finds the newest snapshot in any session directory under meta/ and
// downloads it to metaPath. It returns the key restored from, or "" when no
// snapshot exists.
func Restore(ctx context.Context, store pelicanobj.Store, metaPath string) (string, error) {
	sessions, err := store.ListDir(ctx, MetaDir)
	if err != nil {
		// A missing meta/ directory means a brand-new prefix.
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	var bestKey string
	var bestTime time.Time
	for _, s := range sessions {
		if !s.IsDir {
			continue
		}
		files, err := store.ListDir(ctx, MetaDir+"/"+s.Name)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir || (f.Name != currentName && f.Name != finalName) {
				continue
			}
			// final.db is written after current.db in a clean shutdown;
			// prefer it on mtime ties.
			if f.Mtime.After(bestTime) || (f.Mtime.Equal(bestTime) && f.Name == finalName) {
				bestTime = f.Mtime
				bestKey = MetaDir + "/" + s.Name + "/" + f.Name
			}
		}
	}
	if bestKey == "" {
		return "", nil
	}
	rc, err := store.Get(ctx, bestKey, 0, -1)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", bestKey, err)
	}
	defer rc.Close()
	tmp := metaPath + ".restore"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", fmt.Errorf("download %s: %w", bestKey, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, metaPath); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return bestKey, nil
}
