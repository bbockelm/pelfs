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
// /third_party.txt and linked from the UI's footer, because the obligation
// the MIT licences impose has to be satisfiable by someone who has nothing
// but the binary.
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
