// Package webui carries the browser UI: a Vite + React bundle, built from
// webui/frontend, COMMITTED under dist/, and embedded here.
//
// # Why the build output is in the tree
//
// A Go program that needs a JavaScript toolchain to compile is a Go program
// that breaks for everyone who does not have one. This repository already
// learned that from the outside: scripts/build-pelican-server.sh's header
// records pelican's CI dying with "/bin/sh: 1: pnpm: not found" forty lines
// into someone else's Makefile, "which reads like a test failure and is not
// one".
//
// So the bundle is committed, and the rules that follow from that are:
//
//   - go build ./..., go vet ./... and go test ./... need NO Node, ever.
//   - go install github.com/bbockelm/pelfs/cmd/pelfs@latest produces a
//     binary with a working UI. A placeholder plus a release-time build
//     would not.
//   - go generate ./internal/webui is the only thing that needs pnpm, and
//     only a contributor changing the UI runs it.
//   - CGO_ENABLED=0 and the cross-builds are unaffected: go:embed is pure Go
//     and dist/ is platform-neutral bytes.
//
// The precedent is pelican's, one step further: pelican's frontend
// .gitignore ignores /out/* and then re-includes !/out/placeholder purely so
// its non-optional //go:embed matches at least one file on a pristine
// checkout, which yields a server with no UI. pelfs commits the real bundle,
// which yields a binary with one. The corresponding rule here is that
// webui/frontend/.gitignore must NEVER ignore the output -- and it cannot,
// because the output is not written under webui/frontend at all (see
// vite.config.ts: outDir is ../../internal/webui/dist).
//
// # What keeps the committed output honest
//
// A committed artefact rots silently unless something rebuilds it and
// compares, so .github/workflows/webui.yml does exactly that -- on the paths
// that can change it, off the Go PR path -- and fails on any diff. It also
// builds twice to prove the output is byte-reproducible, and greps the
// lockfile for the GPLv3 `wx-*` package generation.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// The build, and the notices the MIT licences of the bundled packages
// require to travel with a distribution. Both are produced by
// scripts/webui-build.sh; run it with `go generate ./internal/webui`.
//
// A single //go:generate line, rather than two shell one-liners, because the
// order matters (licence guard, then bundle, then notices) and a script can
// be run by a human who is debugging it.
//
//go:generate ../../scripts/webui-build.sh

//go:embed all:dist
var dist embed.FS

//go:embed third_party.txt
var thirdParty string

// CSP is the policy the bundle needs, and the one it must not be given more
// than.
//
// It lives here rather than at the mount site because it is a fact about the
// BUNDLE — which sources its own code comes from — and there is more than one
// mount site: cmd/pelfs's route table serves it to users, and serve_test.go
// serves it to the browser suite. Two copies of a policy is how the harness
// comes to prove a page under rules the real server does not use.
//
// Every clause earns its place:
//
//   - script-src / style-src 'self': every byte of script and style in the
//     bundle is a content-hashed file under assets/. So 'self' is exactly as
//     tight as the connection page's per-response nonce and needs no secret.
//     'unsafe-inline' must NEVER appear: docs/design-webui.md A5 is that the
//     volume holds files the user did not write, and a stored-XSS payload
//     that could satisfy script-src would run with the tab's session in
//     reach. (The one inline style the page had — the noscript notice's —
//     became a class for this reason.)
//   - img-src 'self' data:: the brand PNG and the favicon are files; `data:`
//     is for the icons the component inlines.
//   - connect-src 'self': fetch and EventSource, and nothing else. This is
//     what makes a bundled dependency that decided to phone home fail loudly
//     rather than silently.
//   - default-src 'none' plus the four hardening clauses: whatever is not
//     named above cannot load at all.
//
// It is NOT set by Handler. Handler owns the bundle's caching and nothing
// else, on the principle its doc comment states — a handler that
// half-enforces a threat model is worse than one that plainly does not — so
// the caller sets this, and cmd/pelfs's tests assert that the caller did.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// FS returns the built UI rooted at the bundle's top level, so index.html is
// at "index.html".
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: dist is embedded at compile time, so a failure here
		// would mean the embed directive itself did not match.
		panic("webui: embedded dist is not a directory: " + err.Error())
	}
	return sub
}

// ThirdParty returns the generated third-party notices. It is served at
// /third_party.txt and linked from the app's status line, because the
// obligation the MIT licences impose has to be satisfiable by someone who has
// nothing but the binary. (The link used to be in a page footer; the footer
// was dropped — see webui/frontend/src/brand/Brand.tsx for whose call that
// was — and the link moved rather than going with it.)
func ThirdParty() string { return thirdParty }

// Handler serves the embedded UI.
//
// It deliberately does NOT do any of the security work: the Host allowlist,
// the Origin check, the session credential and the security headers belong to
// internal/httpguard, which wraps this. A handler that half-enforces a threat
// model is worse than one that plainly does not, because the wrapper's
// absence stops being visible.
//
// Two behaviours it does own, because they are properties of the bundle
// rather than of the session:
//
//   - Hashed assets (assets/index-<hash>.js) are immutable and get a
//     year-long cache; everything else, index.html above all, is no-store.
//     An index.html cached across a pelfs upgrade is a UI calling an API
//     that has moved.
//   - Unknown paths fall back to index.html so a client-side route survives
//     a reload -- except under assets/, where a miss is a miss and must be a
//     404 rather than an HTML page served as JavaScript.
//
// That second behaviour is a property of the HANDLER and not of pelfs: this
// app has no client-side routes (there is no router in it -- the open
// directory is component state, not the URL), so both mount sites give it four
// EXACT patterns and the fallback is never reached. It stays because a bundle
// handler that 404s a reload of a client-side route is a trap for whoever adds
// the first route; what must not happen is a catch-all on the same listener as
// the JSON API, which would answer a mistyped /api/v1/fil with an HTML page.
func Handler() http.Handler {
	files := FS()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")

		if p == "third_party.txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(thirdParty))
			return
		}

		if p == "" {
			p = "index.html"
		}
		if info, err := fs.Stat(files, p); err != nil || info.IsDir() {
			if strings.HasPrefix(p, "assets/") {
				// Serving the page for a missing script would hand the
				// browser HTML under a JavaScript content type, which fails
				// in a way that looks like a bundler bug rather than a 404.
				http.NotFound(w, r)
				return
			}
			p = "index.html"
		}

		body, err := fs.ReadFile(files, p)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if strings.HasPrefix(p, "assets/") {
			// Content-hashed by Vite, so the name changes when the bytes do.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}

		// http.FileServer is deliberately not used: it redirects any request
		// for .../index.html to the directory, which turns a plain GET / into
		// a 301 and makes every caller handle a redirect for no reason. The
		// bundle is a handful of files already in memory, so serving them
		// directly is both simpler and one fewer behaviour to explain.
		//
		// A zero modtime means no Last-Modified and no If-Modified-Since
		// handling, which is what we want: the asset names carry the version.
		http.ServeContent(w, r, p, time.Time{}, bytes.NewReader(body))
	})
}
