package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func testHooks(published *int) Hooks {
	return Hooks{
		Status: func() map[string]any {
			return map[string]any{"prefix": "pelican://x/y", "generation": 3}
		},
		StatsJSON: func() ([]byte, error) {
			return []byte(`{"clean_shutdown":false}`), nil
		},
		Publish: func(ctx context.Context) (string, error) {
			*published++
			return "generation 4", nil
		},
		BugreportExtra: func() map[string][]byte {
			return map[string][]byte{"lineage.txt": []byte("gen 3")}
		},
	}
}

func TestControlRoundTrip(t *testing.T) {
	dir := t.TempDir()
	published := 0
	srv, err := Start(dir, testHooks(&published))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close() //nolint:errcheck
	c := NewClient(dir)
	ctx := context.Background()

	body, err := c.Do(ctx, "GET", "/v1/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil || st["prefix"] != "pelican://x/y" {
		t.Fatalf("status body %s (err %v)", body, err)
	}

	if body, err = c.Do(ctx, "GET", "/v1/stats"); err != nil || !strings.Contains(string(body), "clean_shutdown") {
		t.Fatalf("stats: %s err=%v", body, err)
	}
	if body, err = c.Do(ctx, "POST", "/v1/publish"); err != nil || !strings.Contains(string(body), "generation 4") {
		t.Fatalf("publish: %s err=%v", body, err)
	}
	if published != 1 {
		t.Fatalf("publish hook ran %d times", published)
	}
	// Verb matters: publishing via GET must not work.
	if _, err := c.Do(ctx, "GET", "/v1/publish"); err == nil {
		t.Fatal("GET /v1/publish succeeded")
	}
	if published != 1 {
		t.Fatalf("GET ran the publish hook (%d)", published)
	}

	// Bugreport: a valid tar.gz containing the goroutine dump and extras.
	body, err = c.Do(ctx, "GET", "/v1/bugreport")
	if err != nil {
		t.Fatalf("bugreport: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("bugreport not gzip: %v", err)
	}
	names := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("bugreport tar: %v", err)
		}
		names[hdr.Name] = true
	}
	for _, want := range []string{"status.json", "stats.json", "goroutines.txt", "runtime.json", "lineage.txt"} {
		if !names[want] {
			t.Errorf("bugreport missing %s (have %v)", want, names)
		}
	}
}

func TestNilHooks404(t *testing.T) {
	dir := t.TempDir()
	srv, err := Start(dir, Hooks{Status: func() map[string]any { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close() //nolint:errcheck
	c := NewClient(dir)
	if _, err := c.Do(context.Background(), "POST", "/v1/publish"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("nil publish hook: err=%v, want 404", err)
	}
}

func TestSocketLifecycle(t *testing.T) {
	dir := t.TempDir()
	published := 0
	srv, err := Start(dir, testHooks(&published))
	if err != nil {
		t.Fatal(err)
	}
	// A second listener in the same state dir must refuse.
	if _, err := Start(dir, Hooks{}); err == nil {
		t.Fatal("second Start on a live socket succeeded")
	}
	// After a clean close, the socket path is free again (and a stale
	// file left by a crash is handled by the liveness probe).
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	srv2, err := Start(dir, testHooks(&published))
	if err != nil {
		t.Fatalf("restart after close: %v", err)
	}
	defer srv2.Close() //nolint:errcheck
}
