package pelicanobj

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
)

func newTestStore(t *testing.T, prefix string) (Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	s, err := New(context.Background(), Config{PrefixURL: srv.URL + prefix})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, root
}

func TestPutGetHeadDelete(t *testing.T) {
	ctx := context.Background()
	s, root := newTestStore(t, "/ns/base")

	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "chunks/0/0/1_0_1048576", bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "ns/base/chunks/0/0/1_0_1048576")); err != nil {
		t.Fatalf("object not on disk under prefix: %v", err)
	}

	rc, err := s.Get(ctx, "chunks/0/0/1_0_1048576", 0, -1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatalf("Get roundtrip mismatch: %d vs %d bytes", len(got), len(data))
	}

	// Ranged read.
	rc, err = s.Get(ctx, "chunks/0/0/1_0_1048576", 1000, 500)
	if err != nil {
		t.Fatalf("ranged Get: %v", err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data[1000:1500]) {
		t.Fatalf("ranged Get mismatch")
	}

	obj, err := s.Head(ctx, "chunks/0/0/1_0_1048576")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if obj.Size() != int64(len(data)) {
		t.Fatalf("Head size = %d, want %d", obj.Size(), len(data))
	}

	if _, err := s.Head(ctx, "no/such/key"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Head missing: err = %v, want os.ErrNotExist", err)
	}

	if err := s.Delete(ctx, "chunks/0/0/1_0_1048576"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, "chunks/0/0/1_0_1048576"); err != nil {
		t.Fatalf("Delete (idempotent): %v", err)
	}
	if _, err := s.Get(ctx, "chunks/0/0/1_0_1048576", 0, -1); err == nil {
		t.Fatal("Get after Delete should fail")
	}
}

func TestListDirAndListAll(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, "/ns")

	files := []string{"meta/s1/0001-a.db", "meta/s2/0001-b.db", "chunks/0/0/1_0_100", "chunks/0/0/2_0_100"}
	for _, f := range files {
		if err := s.Put(ctx, f, strings.NewReader("payload-"+f)); err != nil {
			t.Fatalf("Put %s: %v", f, err)
		}
	}

	entries, err := s.ListDir(ctx, "meta")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 2 || !entries[0].IsDir || entries[0].Name != "s1" || entries[1].Name != "s2" {
		t.Fatalf("ListDir(meta) = %+v", entries)
	}

	entries, err = s.ListDir(ctx, "meta/s1")
	if err != nil {
		t.Fatalf("ListDir(meta/s1): %v", err)
	}
	if len(entries) != 1 || entries[0].IsDir || entries[0].Name != "0001-a.db" || entries[0].Size <= 0 {
		t.Fatalf("ListDir(meta/s1) = %+v", entries)
	}

	ch, err := s.ListAll(ctx, "chunks/", "", false)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	var keys []string
	for o := range ch {
		keys = append(keys, o.Key())
	}
	want := []string{"chunks/0/0/1_0_100", "chunks/0/0/2_0_100"}
	if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("ListAll keys = %v, want %v", keys, want)
	}
}

// TestRedirectKeepsAuth checks that a director-style 307 redirect to a
// different host re-sends both the Authorization header and the PUT body.
func TestRedirectKeepsAuth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	inner := fakeorigin.Handler(root)
	const token = "sekrit-token"

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer origin.Close()

	director := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, origin.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer director.Close()

	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, Config{PrefixURL: director.URL + "/ns", TokenPath: tokFile})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put(ctx, "obj", strings.NewReader("hello through redirect")); err != nil {
		t.Fatalf("Put via redirect: %v", err)
	}
	rc, err := s.Get(ctx, "obj", 0, -1)
	if err != nil {
		t.Fatalf("Get via redirect: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "hello through redirect" {
		t.Fatalf("body = %q", body)
	}
}

// TestStatKeyETag checks the ETag surface the snapshot manager depends on.
func TestStatKeyETag(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, "/ns")

	if err := s.Put(ctx, "meta/s/current.db", strings.NewReader("one")); err != nil {
		t.Fatal(err)
	}
	ki1, err := s.StatKey(ctx, "meta/s/current.db")
	if err != nil {
		t.Fatalf("StatKey: %v", err)
	}
	if ki1.ETag == "" || ki1.Size != 3 {
		t.Fatalf("StatKey = %+v", ki1)
	}
	time.Sleep(10 * time.Millisecond)
	if err := s.Put(ctx, "meta/s/current.db", strings.NewReader("two-longer")); err != nil {
		t.Fatal(err)
	}
	ki2, err := s.StatKey(ctx, "meta/s/current.db")
	if err != nil {
		t.Fatal(err)
	}
	if ki2.ETag == ki1.ETag {
		t.Fatal("ETag did not change on overwrite")
	}
	if _, err := s.StatKey(ctx, "meta/s/missing.db"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("StatKey missing: %v", err)
	}
}
