package webapi_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/browsesession"
)

// The whole download path, end to end: an authenticated caller mints a
// ticket, the browser navigates to /d/<ticket> WITH NO CREDENTIAL, and the
// bytes come out of the volume. M1 built the ticket half and left the Source
// nil; this is the half that was missing.
func TestDownloadByTicket(t *testing.T) {
	f := newFix(t)
	d := f.dir(rootIno, "dir-0")
	f.text(d, "payload.bin", "the bytes a browser downloads")

	m, err := browsesession.New()
	if err != nil {
		t.Fatalf("browsesession.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /d/{"+browsesession.TicketPathValue+"}",
		browsesession.DownloadHandler(m, f.api.Source()))

	tk, err := m.MintTicket("/dir-0/payload.bin")
	if err != nil {
		t.Fatalf("MintTicket: %v", err)
	}
	rec := httptest.NewRecorder()
	// NO session header, no Authorization, no cookie: an <a href> cannot send
	// one, which is the whole reason the ticket exists.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/d/"+tk, nil))
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /d/<ticket> = %d: %s", res.StatusCode, body)
	}
	if string(body) != "the bytes a browser downloads" {
		t.Errorf("the download served %q", body)
	}
	// The headers the stored-XSS problem requires: a volume holds files the
	// user did not write, and serving one as text/html from this origin would
	// run its script with the app's session in reach.
	for _, tc := range []struct{ header, want string }{
		{"Content-Type", "application/octet-stream"},
		{"X-Content-Type-Options", "nosniff"},
	} {
		if got := res.Header.Get(tc.header); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "payload.bin") {
		t.Errorf("Content-Disposition = %q, want an attachment named payload.bin", cd)
	}

	// The ticket is spent, so the URL sitting in the browser's download
	// history is already worthless.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/d/"+tk, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a second redemption of the same ticket = %d, want 404", rec.Code)
	}
}

// Range works, because a billy.File is an io.ReadSeeker and the handler hands
// it to http.ServeContent. That is what makes a resumed download of a 68 MB
// SIF possible at all, and it retires docs/design-guiclients.md's concern
// about go-billy's helper/iofs having no Seek: this path never touches iofs.
func TestDownloadServesARange(t *testing.T) {
	f := newFix(t)
	f.text(rootIno, "ranged.bin", "0123456789")

	m, err := browsesession.New()
	if err != nil {
		t.Fatalf("browsesession.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /d/{"+browsesession.TicketPathValue+"}",
		browsesession.DownloadHandler(m, f.api.Source()))
	tk, err := m.MintTicket("/ranged.bin")
	if err != nil {
		t.Fatalf("MintTicket: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/d/"+tk, nil)
	req.Header.Set("Range", "bytes=3-6")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("a ranged download = %d, want 206", rec.Code)
	}
	if got := rec.Body.String(); got != "3456" {
		t.Errorf("the range served %q, want 3456", got)
	}
}

// What the Source refuses, and with which error — because the download
// handler renders ErrForbidden as 403 and fs.ErrNotExist as 404, and "you
// cannot" and "there is nothing" are different answers a user acts
// differently on.
func TestDownloadSourceRefusals(t *testing.T) {
	f := newFix(t)
	f.dir(rootIno, "adir")
	f.file(rootIno, "unreadable.bin", 0o000, f.they, f.thgr, []byte("secret"))
	f.text(rootIno, "target.bin", "linked-to")
	f.symlink(rootIno, "to-file", "target.bin")
	f.symlink(rootIno, "to-dir", "adir")
	f.symlink(rootIno, "dangling", "nowhere")
	f.fifo(rootIno, "pipe")

	src := f.api.Source()
	for _, tc := range []struct {
		name string
		path string
		// want is the sentinel the handler distinguishes; nil means the
		// open must succeed.
		want error
		body string
	}{
		{name: "an ordinary file", path: "/target.bin", body: "linked-to"},
		{name: "a symlink to a file is followed, as the listing said", path: "/to-file", body: "linked-to"},
		{name: "a file the session may not read", path: "/unreadable.bin", want: browsesession.ErrForbidden},
		{name: "a path that is not there", path: "/nope.bin", want: fs.ErrNotExist},
		{name: "a directory", path: "/adir", want: fs.ErrNotExist},
		{name: "a symlink to a directory", path: "/to-dir", want: fs.ErrNotExist},
		{name: "a dangling symlink", path: "/dangling", want: fs.ErrNotExist},
		{name: "a fifo, which would hang the request forever", path: "/pipe", want: fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := src.Open(context.Background(), tc.path)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("opening %s gave %v, want %v", tc.path, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("opening %s: %v", tc.path, err)
			}
			defer c.Body.Close() //nolint:errcheck
			got, err := io.ReadAll(c.Body)
			if err != nil {
				t.Fatalf("reading %s: %v", tc.path, err)
			}
			if string(got) != tc.body {
				t.Errorf("%s served %q, want %q", tc.path, got, tc.body)
			}
			if c.Size != int64(len(tc.body)) {
				t.Errorf("%s reported size %d, want %d", tc.path, c.Size, len(tc.body))
			}
		})
	}
}

// A read-only session downloads exactly as a read-write one does: a download
// is a read, and the session mode has nothing to say about it.
func TestDownloadWorksOnAReadOnlySession(t *testing.T) {
	rw := newFix(t)
	rw.text(rootIno, "readable.bin", "bytes")
	c, err := rw.readOnly().api.Source().Open(context.Background(), "/readable.bin")
	if err != nil {
		t.Fatalf("a read-only session could not download: %v", err)
	}
	defer c.Body.Close() //nolint:errcheck
	got, _ := io.ReadAll(c.Body)
	if string(got) != "bytes" {
		t.Errorf("served %q", got)
	}
}
