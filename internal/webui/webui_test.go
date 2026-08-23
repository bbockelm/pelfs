package webui

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"testing"
)

// The committed bundle is an artefact no reviewer reads, so these tests are
// the review. Every one of them runs in the ordinary `go test ./...` lane,
// with no Node anywhere -- which is the point: the properties the JavaScript
// toolchain is responsible for are asserted against the bytes that actually
// ship.

func TestEmbeddedBundleIsComplete(t *testing.T) {
	f := FS()
	for _, want := range []string{"index.html", "brand/PelicanPlatformLogo_Icon.png", "brand/favicon.svg"} {
		if _, err := fs.Stat(f, want); err != nil {
			t.Errorf("embedded bundle is missing %q: %v\n"+
				"Run `go generate ./internal/webui` and commit the result.", want, err)
		}
	}
	var js, css int
	err := fs.WalkDir(f, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch path.Ext(p) {
		case ".js":
			js++
		case ".css":
			css++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking assets/: %v", err)
	}
	if js == 0 || css == 0 {
		t.Errorf("assets/ holds %d .js and %d .css files; want at least one of each", js, css)
	}
	// index.html must reference the hashed assets that are actually present.
	// A stale index.html is the failure mode of a hand-edited dist/.
	idx, err := fs.ReadFile(f, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="\./(assets/[^"]+)"`).FindAllStringSubmatch(string(idx), -1) {
		if _, err := fs.Stat(f, m[1]); err != nil {
			t.Errorf("index.html references %q, which is not in the bundle: %v", m[1], err)
		}
	}
}

// The bundle lives in git, so its size is a cost the repository pays on every
// clone. The ceiling is here so growth is a decision someone makes rather
// than something that happens: at the time of writing the whole bundle is
// ~430 KB, of which 51 KB is the brand PNG.
func TestBundleSizeCeiling(t *testing.T) {
	const ceiling = 2 << 20
	var total int64
	err := fs.WalkDir(FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("embedded bundle: %d bytes", total)
	if total > ceiling {
		t.Errorf("embedded bundle is %d bytes, over the %d-byte ceiling.\n"+
			"Every byte here is in every clone and every binary. Raise the ceiling "+
			"deliberately, with a note saying what was added and why.", total, ceiling)
	}
}

// The UI is served by a Go binary on loopback and must work with no network.
// The U0 probe caught the SVAR theme injecting a stylesheet link to
// cdn.svar.dev and its icon callback building CDN URLs per file extension;
// webui/frontend turns both off, and this is the tripwire that notices if a
// rebuild ever brings them back into a stylesheet or the page itself.
func TestNoRemoteOriginsInStylesheetsOrPage(t *testing.T) {
	remote := regexp.MustCompile(`(?:url\(\s*['"]?|@import\s+['"]|\bsrc=['"]|\bhref=['"])(?:https?:)?//([^'")\s/]+)`)
	err := fs.WalkDir(FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch path.Ext(p) {
		case ".css", ".html", ".svg":
		default:
			return nil
		}
		b, err := fs.ReadFile(FS(), p)
		if err != nil {
			return err
		}
		for _, m := range remote.FindAllStringSubmatch(string(b), -1) {
			host := m[1]
			if host == "localhost" || strings.HasPrefix(host, "127.0.0.1") {
				continue
			}
			t.Errorf("%s fetches from a remote origin (%s). The embedded UI must load "+
				"nothing off loopback.", p, host)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The licence guard, on the Go side of the fence. webui/frontend's
// licence-check runs under Node and gates the build; this one runs in every
// `go test ./...` against the artefact that actually ships, so a hand-edited
// third_party.txt or a bundle built on someone's laptop with a copyleft
// dependency is caught without a JavaScript toolchain in the room.
func TestThirdPartyNoticesAreCarried(t *testing.T) {
	n := ThirdParty()
	if len(n) < 1000 {
		t.Fatalf("third_party.txt is %d bytes; that cannot be a real notices file", len(n))
	}
	for _, want := range []string{
		"@svar-ui/react-filemanager",
		"react",
		"MIT License",
		"Permission is hereby granted, free of charge",
	} {
		if !strings.Contains(n, want) {
			t.Errorf("third_party.txt does not mention %q", want)
		}
	}
	// The retired generation of these components is GPLv3. pelfs is
	// Apache-2.0 and the bundle ships inside the binary, so this is a
	// relicensing event, not a footnote.
	for _, forbidden := range []string{"GPL", "GNU General Public", "Affero"} {
		if strings.Contains(n, forbidden) {
			t.Errorf("third_party.txt mentions %q: a copyleft licence has entered the bundle.\n"+
				"See webui/frontend/tools/licence-check.mjs and the `wx-*` rule in "+
				"docs/design-webui.md, Verification 1.", forbidden)
		}
	}
	if strings.Contains(n, "wx-react") || strings.Contains(n, "\n  wx-") {
		t.Error("third_party.txt lists a wx-* package; that generation of the SVAR " +
			"components is GPLv3 and must never be bundled")
	}
}

func TestHandlerServesTheBundle(t *testing.T) {
	h := Handler()
	get := func(p string) *http.Response {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec.Result()
	}

	t.Run("root serves index.html, uncached", func(t *testing.T) {
		res := get("/")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /: %d", res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type %q, want text/html", ct)
		}
		// An index.html cached across a pelfs upgrade is a UI calling an API
		// that has moved.
		if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control %q, want no-store", cc)
		}
		b, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(b), "<div id=\"root\">") {
			t.Errorf("index.html does not look like the app shell: %q", firstBytes(b))
		}
	})

	t.Run("hashed assets are immutable", func(t *testing.T) {
		var asset string
		_ = fs.WalkDir(FS(), "assets", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && path.Ext(p) == ".js" {
				asset = p
			}
			return nil
		})
		if asset == "" {
			t.Skip("no JS asset in the bundle")
		}
		res := get("/" + asset)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /%s: %d", asset, res.StatusCode)
		}
		if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("Cache-Control %q for a content-hashed asset, want immutable", cc)
		}
	})

	t.Run("a missing asset is a 404, not the page", func(t *testing.T) {
		// Serving index.html for a missing script would hand the browser HTML
		// with a JavaScript content type, which fails in a way that looks
		// like a bundler bug.
		if res := get("/assets/index-deadbeef.js"); res.StatusCode != http.StatusNotFound {
			t.Errorf("GET a missing asset: %d, want 404", res.StatusCode)
		}
	})

	t.Run("an unknown route falls back to the page", func(t *testing.T) {
		res := get("/volumes/abc")
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET a client-side route: %d, want 200 (the SPA shell)", res.StatusCode)
		}
	})

	t.Run("the notices are served", func(t *testing.T) {
		res := get("/third_party.txt")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /third_party.txt: %d", res.StatusCode)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Content-Type %q, want text/plain", ct)
		}
		b, _ := io.ReadAll(res.Body)
		if string(b) != ThirdParty() {
			t.Error("/third_party.txt does not serve the embedded notices")
		}
	})

	t.Run("the brand assets and their NOTICE ship together", func(t *testing.T) {
		// The mark is used with permission; the permission is recorded next
		// to the asset, and it travels with it.
		for _, p := range []string{"/brand/PelicanPlatformLogo_Icon.png", "/brand/NOTICE.txt"} {
			if res := get(p); res.StatusCode != http.StatusOK {
				t.Errorf("GET %s: %d, want 200", p, res.StatusCode)
			}
		}
		res := get("/brand/NOTICE.txt")
		b, _ := io.ReadAll(res.Body)
		flat := strings.Join(strings.Fields(string(b)), " ")
		if !strings.Contains(flat, "NOT an official Pelican Platform product") {
			t.Error("brand/NOTICE.txt no longer says what pelfs is not")
		}
	})
}

func firstBytes(b []byte) string {
	if len(b) > 120 {
		return string(b[:120]) + "..."
	}
	return string(b)
}
