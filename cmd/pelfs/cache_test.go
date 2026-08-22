package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/control"
	"github.com/bbockelm/pelfs/internal/genfs"
)

func TestParseCacheSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		bad  bool
	}{
		{in: "", want: 0},
		{in: "1024", want: 1024},
		{in: "8K", want: 8 << 10},
		{in: "4M", want: 4 << 20},
		{in: "4G", want: 4 << 30},
		{in: "4Gi", want: 4 << 30},
		{in: "2T", want: 2 << 40},
		{in: "4g", want: 4 << 30},
		{in: "-1", bad: true},
		{in: "lots", bad: true},
		{in: "4GB", bad: true}, // B is not a unit here; say 4G
	}
	for _, c := range cases {
		got, err := parseCacheSize(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("parseCacheSize(%q) = %d, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCacheSize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseCacheSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestCacheClearRefusesALiveMount is the guard that keeps `pelfs cache
// clear` from being the one command that can break a running mount:
// unlinking a spilled catalog out from under the SQLite that has it open.
func TestCacheClearRefusesALiveMount(t *testing.T) {
	// A short path on purpose: a unix socket path is capped at ~104 bytes,
	// and the per-test temp directory is routinely longer than that.
	dir, err := os.MkdirTemp("/tmp", "pelfs-cache")
	if err != nil {
		t.Skipf("no short temp path for a unix socket: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) }) //nolint:errcheck
	if err := os.MkdirAll(filepath.Join(dir, "gencache", "packs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gencache", "packs", "p-deadbeef-0000"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, control.SocketName)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() //nolint:errcheck
		}
	}()

	if live, _ := mountIsLive(dir); !live {
		t.Fatal("a listening control socket did not read as a live mount")
	}
	if code := cmdCache([]string{"clear", "--state-dir", dir}); code == 0 {
		t.Fatal("cache clear ran against a live mount")
	}
	if u, err := genfs.InspectCache(filepath.Join(dir, "gencache")); err != nil || u.Files != 1 {
		t.Fatalf("the refused clear still took the cache: %+v (%v)", u, err)
	}

	// A dead session leaves the socket file behind. That must NOT count as
	// live, or a crash would make the cache unclearable and send the user
	// hunting a process that does not exist.
	ln.Close() //nolint:errcheck
	if _, err := os.Stat(sock); err != nil {
		if err := os.WriteFile(sock, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if live, how := mountIsLive(dir); live {
		t.Fatalf("a leftover socket file read as a live mount (%s)", how)
	}
	if code := cmdCache([]string{"clear", "--state-dir", dir}); code != 0 {
		t.Fatalf("cache clear refused a dead session's leftovers (exit %d)", code)
	}
	if u, err := genfs.InspectCache(filepath.Join(dir, "gencache")); err != nil || u.Files != 0 {
		t.Fatalf("cache not cleared: %+v (%v)", u, err)
	}
}
