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
)

// cmdCtl talks to a running mount's control socket.
func cmdCtl(args []string) int {
	if len(args) < 2 {
		return exitErr(errors.New("usage: pelfs ctl <prefix-or-mountpoint> <status|stats|publish|bugreport> [-o file]"))
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
		// Follow the session's state dir when it recorded one: a mount
		// started with --state-dir keeps its socket there, not beside
		// this record.
		dir := e.info.StateDir
		if dir == "" {
			dir = filepath.Dir(e.path)
		}
		if _, err := os.Stat(filepath.Join(dir, control.SocketName)); err != nil {
			return "", fmt.Errorf("mount %s has no control socket at %s (older session?)", e.info.MountPoint, dir)
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
