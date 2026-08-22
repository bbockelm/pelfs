#!/bin/bash
# Build the pelican-server binary the integration gate tests against, from the
# exact pelican revision go.mod pins -- and with no JavaScript toolchain at all.
#
# WHY THIS EXISTS. CI used to run `make web-build` in the pelican tree before
# `go build`, on the assumption that a server binary needs the Next.js bundle
# built first. It does not, and the assumption broke the job the moment
# upstream pelican switched its frontend from npm to pnpm (pelican 0ee5489b8,
# "Update to use PNPM with security features", which arrived here with the
# branch rebase behind pelfs 962a6ec). Makefile:93 became
#     cd web_ui/frontend && pnpm install --frozen-lockfile && pnpm run build
# the runner had no pnpm, and the job died with `/bin/sh: 1: pnpm: not found`
# forty lines into someone else's Makefile -- which reads like a test failure
# and is not one.
#
# WHAT THE BINARY ACTUALLY NEEDS is that pelican's `//go:embed frontend/out/*`
# (web_ui/ui.go) matches at least one file, and pelican commits an empty
# `web_ui/frontend/out/placeholder` for precisely that purpose -- the frontend
# .gitignore ignores `/out/*` and then re-includes `!/out/placeholder`. So a
# pristine checkout builds a server binary with `go build` and nothing else.
# Verified: the whole internal/integration suite passes against a federation
# served by a binary built this way.
#
# WHAT WE GIVE UP is the web bundle, and the gate gives up nothing by it: the
# federation in scripts/integration-pelican.sh runs with `Server.EnableUI:
# false` and no test ever fetches a page. Building it would spend minutes of
# `pnpm install` to embed assets nobody looks at, and would put a whole
# second language toolchain -- pinned Node, pinned pnpm, a lockfile install
# over the network -- between this repo and a red X.
#
# Every assumption above is CHECKED below, before the build, so that if
# pelican ever stops shipping the placeholder, stops committing its generated
# Go, or the gate starts serving the UI, this script says so in a sentence
# instead of failing somewhere further downstream.
#
# Usage:  scripts/build-pelican-server.sh [output-binary] [source-checkout]
# Defaults: ./pelican-bin and ./pelican-src, both relative to the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd -P)

OUT=${1:-$REPO_ROOT/pelican-bin}
SRC=${2:-$REPO_ROOT/pelican-src}

die() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------- toolchain
# Named up front, individually, because "which tool is missing" is the whole
# content of this class of failure and it should not have to be inferred from
# a Makefile's exit code.
for tool in go git; do
  command -v "$tool" >/dev/null || die "\`$tool\` is not on PATH; the integration job cannot build a pelican server without it"
done
echo "== $(go version) =="

# ------------------------------------------------- which pelican do we build
# Resolve the module we ACTUALLY build against: with a replace in effect,
# .Version is the replaced-away pin, so cloning upstream at it would build a
# server without the very fixes the replace exists to supply. This follows the
# replacement and falls back to upstream automatically once it is dropped.
mod=$(go list -m -f '{{if .Replace}}{{.Replace.Path}}{{else}}{{.Path}}{{end}}' github.com/pelicanplatform/pelican)
ver=$(go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' github.com/pelicanplatform/pelican)
sha=$(echo "$ver" | grep -oE '[0-9a-f]{12}$' || true)
[ -n "$sha" ] || die "could not derive a commit from $mod $ver (a tagged release rather than a pseudo-version? this script only knows how to check out a commit)"
echo "== building pelican from $mod at $sha ($ver) =="

# ------------------------------------------------------------------- fetch
# Reuse an existing checkout when it is already at the right commit: a local
# re-run then costs nothing, and CI's workspace is always empty anyway.
if [ -d "$SRC/.git" ] && git -C "$SRC" rev-parse --verify --quiet "$sha^{commit}" >/dev/null &&
   [ "$(git -C "$SRC" rev-parse HEAD)" = "$(git -C "$SRC" rev-parse "$sha^{commit}")" ]; then
  echo "   reusing $SRC, already at $sha"
else
  if [ -d "$SRC/.git" ]; then
    echo "   $SRC exists at another commit; fetching $sha"
    git -C "$SRC" fetch --filter=blob:none --quiet origin "$sha" ||
      git -C "$SRC" fetch --filter=blob:none --quiet origin
  else
    [ -e "$SRC" ] && die "$SRC exists and is not a git checkout; refusing to touch it"
    git clone --filter=blob:none --quiet "https://$mod" "$SRC"
  fi
  git -C "$SRC" checkout --quiet --detach "$sha" ||
    die "pelican $mod has no commit $sha -- a force-push or a rebase can strand the pin in go.mod (that is exactly what pelfs f4e6111 was fixing)"
fi
echo "   $(git -C "$SRC" log -1 --format='%h %s')"

# ------------------------------------------------- the assumptions, checked
# 1. The embed target. `//go:embed frontend/out/*` is not an optional embed:
#    with an empty directory the compiler says "pattern frontend/out/*: no
#    matching files found" and the reader is left to work out that a web build
#    was skipped. Say it here instead, with the remedy.
n=$(find "$SRC/web_ui/frontend/out" -type f 2>/dev/null | wc -l | tr -d ' ')
[ "${n:-0}" -gt 0 ] || die "pelican no longer ships a file under web_ui/frontend/out/ (it used to commit an empty \`placeholder\` there).
       Its web_ui/ui.go embeds frontend/out/* non-optionally, so the server
       binary cannot be built without SOME file there. Either put a stub back
       (\`mkdir -p web_ui/frontend/out && touch web_ui/frontend/out/index.html\`,
       which is what pelican's own Makefile does on Windows) or build the real
       bundle -- which now needs pnpm, and a pinned Node and pnpm in ci.yml."

# 2. The generated Go. `make web-build` also ran `go generate ./...`; we skip
#    it because pelican commits its generated parameter tables. If that ever
#    stops being true the build fails as an ordinary compile error with no
#    hint that a generate step was skipped, so check the file by name.
[ -f "$SRC/param/parameters.go" ] || die "pelican no longer commits param/parameters.go, so its generated code is not in the checkout.
       This script skips \`make generate\` on the grounds that it is committed;
       that is no longer true and the build needs \`go generate ./...\` (which
       may in turn want the swagger and frontend toolchains)."

# 3. The gate does not serve the UI. This binary embeds no web bundle -- only
#    the placeholder -- so a federation with the UI switched on would serve a
#    broken console. Nothing here looks at it today, and this check is what
#    makes that a decision rather than a coincidence.
grep -q 'EnableUI: false' "$REPO_ROOT/scripts/integration-pelican.sh" ||
  die "scripts/integration-pelican.sh no longer sets \`Server.EnableUI: false\`.
       The binary this script builds embeds NO web assets (see the header), so
       a gate that serves or scrapes the UI needs a real \`make web-build\` and
       the pnpm toolchain that now implies."

# ------------------------------------------------------------------- build
# The tags are the server flavor: `server` selects the server subcommands a
# client-only build omits, `forceposix` the POSIX flag parsing the harness
# expects. scripts/integration-pelican.sh re-checks the flavor of whatever
# binary it is handed; failing here names the BUILD as the culprit instead.
echo "== go build -tags forceposix,server ./cmd =="
( cd "$SRC" && go build -tags forceposix,server -o "$OUT" ./cmd )

# A smoke test, because "it linked" and "it runs" are different claims and the
# gate has already once been handed a binary that did not run.
"$OUT" --version >/dev/null 2>&1 || die "the binary built but does not run: $("$OUT" --version 2>&1 | head -3)"
"$OUT" origin --help >/dev/null 2>&1 || die "the binary has no \`origin\` subcommand -- this is a client-only build; check the -tags"
echo "== built $OUT ($("$OUT" --version 2>&1 | head -1)) =="
