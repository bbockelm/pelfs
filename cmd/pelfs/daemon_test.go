package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLog puts a daemon.log of n bytes in dir whose contents identify the
// generation that wrote it, so a test can say which file ended up where.
func writeLog(t *testing.T, path string, mark string, n int) {
	t.Helper()
	body := append([]byte(mark), []byte(strings.Repeat("x", n-len(mark)))...)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

// The log a background mount writes is unbounded today and is the only
// place a checkpoint failure is reported, so the cap must be enforced
// without costing the reader the history they came for.
func TestDaemonLogRotatesAtTheCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	writeLog(t, path, "OLD", daemonLogCap)

	f, got, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got != path {
		t.Errorf("log path %q, want %q", got, path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("a rotated log starts fresh; got %d bytes", fi.Size())
	}
	rolled, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("the history a rotation is for did not survive: %v", err)
	}
	if !strings.HasPrefix(string(rolled), "OLD") {
		t.Errorf(".1 holds the wrong generation: %.10q", rolled)
	}
}

// Rotation keeps exactly one generation: the bound users are owed is 2x
// the cap, not "a cap and then whatever accumulated".
func TestDaemonLogKeepsOneGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	writeLog(t, path+".1", "ANCIENT", 32)
	writeLog(t, path, "PREVIOUS", daemonLogCap)

	f, _, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	rolled, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(rolled), "PREVIOUS") {
		t.Errorf("the older generation was kept over the newer one: %.10q", rolled)
	}
	entries, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("want daemon.log and one .1, got %v", entries)
	}
}

// Below the cap the log is appended to, because a mount's history across
// restarts is what makes an intermittent checkpoint failure diagnosable.
func TestDaemonLogAppendsBelowTheCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	writeLog(t, path, "KEEP", daemonLogCap-1)

	f, _, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("more"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("a log under the cap must not rotate (stat .1: %v)", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(daemonLogCap - 1 + len("more")); fi.Size() != want {
		t.Errorf("log is %d bytes, want %d appended bytes", fi.Size(), want)
	}
}

// A first mount has no log to rotate.
func TestDaemonLogCreatesFirstLog(t *testing.T) {
	dir := t.TempDir()
	f, path, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("daemon.log mode %v, want 0600: it carries a user's paths", fi.Mode().Perm())
	}
}
