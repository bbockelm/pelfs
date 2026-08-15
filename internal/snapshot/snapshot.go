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
// once at shutdown, after the filesystem has quiesced, and the superseded
// current.db is removed.
//
// Snapshot bytes flow through the Data storage handle, which is the
// encryption-wrapped store when volume encryption is enabled — so metadata
// snapshots (filenames, directory structure) are protected the same way as
// data blocks. Listing and ETag checks use the raw Meta store, since ETags
// are server-side properties.
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
	"sort"
	"time"

	"github.com/juicedata/juicefs/pkg/object"

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
	MetaPath string               // local sqlite database path
	Meta     pelicanobj.Store     // raw store: listings and ETag checks
	Data     object.ObjectStorage // snapshot bytes; encrypted wrapper when enabled
	Session  string               // unique per-session subdirectory name

	// OnSnapshot, when set, is called after each successful upload (used to
	// surface last-snapshot time in `pelfs status`).
	OnSnapshot func(key string, when time.Time)
	// OnError, when set, is called for each failed periodic snapshot (used
	// by the session statistics collector).
	OnError func(err error)

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
				if mgr.OnError != nil {
					mgr.OnError(err)
				}
				if errors.Is(err, ErrConflict) {
					return
				}
			}
		}
	}
}

func (mgr *Manager) sessionKey(name string) string {
	return fmt.Sprintf("%s/%s/%s", MetaDir, mgr.Session, name)
}

// Snapshot takes one consistent copy of the database and uploads it,
// overwriting meta/<session>/current.db (or writing final.db when final is
// set, then removing the superseded current.db). Before overwriting, the
// object's ETag is compared with the one from our previous upload to detect
// a concurrent writer.
func (mgr *Manager) Snapshot(ctx context.Context, final bool) error {
	if mgr.lastETag != "" {
		if ki, err := mgr.Meta.StatKey(ctx, mgr.sessionKey(currentName)); err == nil &&
			ki.ETag != "" && ki.ETag != mgr.lastETag {
			return fmt.Errorf("%s: %w", mgr.sessionKey(currentName), ErrConflict)
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
	key := mgr.sessionKey(currentName)
	if final {
		key = mgr.sessionKey(finalName)
	}
	if err := mgr.Data.Put(ctx, key, f); err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	if final {
		// final.db supersedes this session's periodic snapshot.
		if err := mgr.Data.Delete(ctx, mgr.sessionKey(currentName)); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: could not remove superseded %s: %v\n", mgr.sessionKey(currentName), err)
		}
	} else if ki, err := mgr.Meta.StatKey(ctx, key); err == nil {
		mgr.lastETag = ki.ETag
	}
	if mgr.OnSnapshot != nil {
		mgr.OnSnapshot(key, time.Now())
	}
	return nil
}

// PruneSessions removes snapshot files from all but the newest keep session
// directories (session names sort chronologically). The current session is
// always kept.
func (mgr *Manager) PruneSessions(ctx context.Context, keep int) error {
	if keep < 1 {
		keep = 1
	}
	sessions, err := mgr.Meta.ListDir(ctx, MetaDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var names []string
	for _, s := range sessions {
		if s.IsDir && s.Name != mgr.Session {
			names = append(names, s.Name)
		}
	}
	sort.Strings(names)
	if len(names) <= keep-1 { // current session counts toward keep
		return nil
	}
	for _, name := range names[:len(names)-(keep-1)] {
		files, err := mgr.Meta.ListDir(ctx, MetaDir+"/"+name)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir {
				continue
			}
			key := MetaDir + "/" + name + "/" + f.Name
			if err := mgr.Data.Delete(ctx, key); err != nil {
				fmt.Fprintf(os.Stderr, "pelfs: prune %s: %v\n", key, err)
			}
		}
	}
	return nil
}

// Restore finds the newest snapshot in any session directory under meta/ and
// downloads it (through data, so encrypted snapshots decrypt) to metaPath.
// It returns the key restored from, or "" when no snapshot exists.
func Restore(ctx context.Context, meta pelicanobj.Store, data object.ObjectStorage, metaPath string) (string, error) {
	sessions, err := meta.ListDir(ctx, MetaDir)
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
		files, err := meta.ListDir(ctx, MetaDir+"/"+s.Name)
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
	rc, err := data.Get(ctx, bestKey, 0, -1)
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
