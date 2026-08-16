package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/stats"
)

// controlHooks connects a live session to its control socket. mnt-level
// operations (staging drain) belong to the frontend; the hooks cover what
// the session owns directly.
func (s *session) controlHooks(started time.Time, readOnly bool, mountPoint string) control.Hooks {
	h := control.Hooks{
		Status: func() map[string]any {
			return map[string]any{
				"pid":        os.Getpid(),
				"prefix":     s.prefix,
				"mountpoint": mountPoint,
				"read_only":  readOnly,
				"started":    started.Format(time.RFC3339),
				"uptime_s":   int64(time.Since(started).Seconds()),
			}
		},
		StatsJSON: func() ([]byte, error) {
			// The collector writes its file atomically every 30s and on
			// demand here; serve the same document.
			if err := s.stats.Flush(); err != nil {
				return nil, err
			}
			return os.ReadFile(s.statsPath)
		},
		BugreportExtra: func() map[string][]byte {
			extra := make(map[string][]byte)
			if b, err := os.ReadFile(filepath.Join(s.stateDir, "refs", "volume.pub")); err == nil {
				extra["volume.pub"] = b
			}
			return extra
		},
	}
	if !readOnly {
		h.Flush = func(ctx context.Context) error {
			return s.packs.Flush(ctx)
		}
		h.Publish = func(ctx context.Context) (string, error) {
			if err := s.packs.Flush(ctx); err != nil {
				return "", fmt.Errorf("pre-publish pack flush: %w", err)
			}
			res, err := publishCore(ctx, s, "main", "")
			if err != nil {
				return "", err
			}
			s.stats.Update(func(sum *stats.Summary) { sum.SnapshotsUploaded++ })
			return fmt.Sprintf("generation %d: %d chunks uploaded, %d catalogs, %d new packs",
				res.Superblock.Generation, res.Stats.ChunksAdded, res.Stats.Catalogs, len(res.NewPacks)), nil
		}
	}
	return h
}

// startControl brings the control socket up; failure is loud but never
// fatal — a mount without a control socket beats no mount.
func (s *session) startControl(started time.Time, readOnly bool, mountPoint string) *control.Server {
	srv, err := control.Start(s.stateDir, s.controlHooks(started, readOnly, mountPoint))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: control socket unavailable: %v\n", err)
		return nil
	}
	return srv
}

// cmdCtl talks to a running mount's control socket.
func cmdCtl(args []string) int {
	if len(args) < 2 {
		return exitErr(errors.New("usage: pelfs ctl <prefix-or-mountpoint> <status|stats|flush|publish|bugreport> [-o file]"))
	}
	target, verb := args[0], args[1]
	out := ""
	if len(args) >= 4 && args[2] == "-o" {
		out = args[3]
	}

	stateDir, err := findSessionState(target)
	if err != nil {
		return exitErr(err)
	}
	c := control.NewClient(stateDir)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var body []byte
	switch verb {
	case "status":
		body, err = c.Do(ctx, "GET", "/v1/status")
	case "stats":
		body, err = c.Do(ctx, "GET", "/v1/stats")
	case "flush":
		body, err = c.Do(ctx, "POST", "/v1/flush")
	case "publish":
		body, err = c.Do(ctx, "POST", "/v1/publish")
	case "pprof":
		// pelfs ctl <target> pprof [cpu|heap|goroutine|...] [-o file]
		kind := "profile?seconds=30"
		if len(args) >= 3 && args[2] != "-o" {
			kind = args[2]
			if kind == "cpu" {
				kind = "profile?seconds=30"
			}
			if len(args) >= 5 && args[3] == "-o" {
				out = args[4]
			}
		}
		body, err = c.Do(ctx, "GET", "/debug/pprof/"+kind)
		if err == nil && out == "" {
			out = "pelfs-" + strings.SplitN(kind, "?", 2)[0] + ".pprof"
		}
	case "bugreport":
		body, err = c.Do(ctx, "GET", "/v1/bugreport")
		if err == nil {
			if out == "" {
				out = fmt.Sprintf("pelfs-bugreport-%s.tar.gz", time.Now().Format("20060102-150405"))
			}
			if werr := os.WriteFile(out, body, 0600); werr != nil {
				return exitErr(werr)
			}
			fmt.Printf("wrote %s (%d bytes)\n", out, len(body))
			return 0
		}
	default:
		return exitErr(fmt.Errorf("unknown ctl verb %q", verb))
	}
	if err != nil {
		return exitErr(err)
	}
	if out != "" {
		if err := os.WriteFile(out, body, 0600); err != nil {
			return exitErr(err)
		}
		return 0
	}
	os.Stdout.Write(body) //nolint:errcheck
	return 0
}

// findSessionState resolves a prefix or mountpoint to a live session's
// state directory via the mount records.
func findSessionState(target string) (string, error) {
	infos, err := listMounts()
	if err != nil {
		return "", err
	}
	for _, e := range infos {
		if e.info.Prefix != target && filepath.Clean(e.info.MountPoint) != filepath.Clean(target) {
			continue
		}
		dir := filepath.Dir(e.path)
		if _, err := os.Stat(filepath.Join(dir, control.SocketName)); err != nil {
			return "", fmt.Errorf("mount %s has no control socket (older session?)", e.info.MountPoint)
		}
		return dir, nil
	}
	// Fall back: maybe the target IS a state dir (shell sessions with
	// --state-dir, tests).
	if _, err := os.Stat(filepath.Join(target, control.SocketName)); err == nil {
		return target, nil
	}
	var known []string
	for _, e := range infos {
		known = append(known, e.info.Prefix)
	}
	return "", fmt.Errorf("no running mount matches %q (known: %v)", target, known)
}
