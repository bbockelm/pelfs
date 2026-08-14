// Package snapshot periodically copies the JuiceFS SQLite metadata database
// into the federation under <prefix>/meta/<session-id>/, and restores the
// most recent snapshot on startup. Snapshots are taken with `VACUUM INTO`,
// which produces a consistent copy even while the mount is writing (the
// database runs in WAL mode).
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

// Manager uploads snapshots of one SQLite database to one session directory.
type Manager struct {
	MetaPath string           // local sqlite database path
	Store    *pelicanobj.Store // federation prefix store
	Session  string           // unique per-session subdirectory name

	seq int
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

// Run uploads a snapshot every interval until ctx is canceled.
func (mgr *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := mgr.Snapshot(ctx, "periodic"); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: metadata snapshot failed: %v\n", err)
			}
		}
	}
}

// Snapshot takes one consistent copy of the database and uploads it as
// meta/<session>/<seq>-<label>.db.
func (mgr *Manager) Snapshot(ctx context.Context, label string) error {
	mgr.seq++
	tmp := fmt.Sprintf("%s.snap-%d", mgr.MetaPath, mgr.seq)
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
	key := fmt.Sprintf("%s/%s/%04d-%s.db", MetaDir, mgr.Session, mgr.seq, label)
	if err := mgr.Store.Put(ctx, key, f); err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	return nil
}

// Restore finds the newest snapshot in any session directory under meta/ and
// downloads it to metaPath. It returns the key restored from, or "" when no
// snapshot exists.
func Restore(ctx context.Context, store *pelicanobj.Store, metaPath string) (string, error) {
	sessions, err := store.ListDir(ctx, MetaDir)
	if err != nil {
		// A missing meta/ directory means a brand-new prefix.
		if os.IsNotExist(err) || isNotFound(err) {
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
			if f.IsDir {
				continue
			}
			if f.Mtime.After(bestTime) {
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

func isNotFound(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
