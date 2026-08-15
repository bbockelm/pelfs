package pelicanobj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
)

func TestPreflightOpenOrigin(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, "/ns")
	if err := Preflight(ctx, s, "http://origin/ns", false); err != nil {
		t.Fatalf("Preflight on open origin: %v", err)
	}
	// The probe object must not linger.
	entries, err := s.ListDir(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name, ".pelfs-probe-") {
			t.Fatalf("probe object left behind: %s", e.Name)
		}
	}
}

func TestPreflightReadOnlyOrigin(t *testing.T) {
	ctx := context.Background()
	inner := fakeorigin.Handler(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut || r.Method == http.MethodDelete {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	s, err := New(ctx, Config{PrefixURL: srv.URL + "/ns"})
	if err != nil {
		t.Fatal(err)
	}

	// Read-only preflight should pass...
	if err := Preflight(ctx, s, srv.URL+"/ns", true); err != nil {
		t.Fatalf("read-only Preflight: %v", err)
	}
	// ...but a read-write preflight must fail with a scope hint.
	err = Preflight(ctx, s, srv.URL+"/ns", false)
	if err == nil {
		t.Fatal("expected write preflight to fail")
	}
	if !strings.Contains(err.Error(), "write permission") {
		t.Fatalf("error should name the missing permission, got: %v", err)
	}
}

func TestPreflightNoReadAccess(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	s, err := New(ctx, Config{PrefixURL: srv.URL + "/ns"})
	if err != nil {
		t.Fatal(err)
	}
	err = Preflight(ctx, s, srv.URL+"/ns", true)
	if err == nil || !strings.Contains(err.Error(), "read permission") {
		t.Fatalf("expected read-permission error, got: %v", err)
	}
}
