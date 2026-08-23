#!/usr/bin/env bash
#
# The browser gate: a real Chromium against a real pelfs server.
#
# WHY A BROWSER AT ALL. Exactly one thing here needs one: the browser half of
# the threat model. SameSite, CORS preflight behaviour, Local Network Access
# and DNS rebinding are enforced by the browser, and a Go test asserting "we
# return 403" does not prove "the browser never sent it". Everything else a
# browser could check -- does the grid render, does drag-and-drop work -- is
# out of scope on purpose: those failures are loud in manual use, while the
# CSRF ones are silent.
#
# WHAT IT DRIVES. Preference order, decided at runtime because the verb is
# another milestone's work:
#
#   browse mode  `pelfs browse` against a fakeorigin federation stub and a
#                real v2 volume. This is the gate worth having: the URL and
#                the single-use bootstrap token are both chosen at runtime,
#                and both are handed to the suite in the environment.
#   embed mode   the committed bundle served by `go test` (internal/webui,
#                TestServeEmbeddedForBrowserSuite) when `pelfs browse` is not
#                in the binary yet. The harness is then still proven end to
#                end rather than theoretically wired.
#
# NOTHING HERE TOUCHES A DEVELOPER'S REAL STATE: every volume, state dir and
# origin root is under one mktemp -d, and ~/.local/state/pelfs is never
# consulted because --state-dir is always passed.
#
# Usage:
#   scripts/webui-playwright.sh [-- playwright args...]
#
# Environment:
#   PELFS_WEBUI_SKIP_BROWSER_INSTALL=1   assume the browser is cached
#   PELFS_WEBUI_FORCE_MODE=embed|browse  override the mode detection
#   PELFS_WEBUI_ATTACKER_HOST=...        the rebinding hostname (default attacker.test)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONT="$REPO/webui/frontend"
W="$(mktemp -d)"
PIDS=()

# EVERY path this harness touches lives under $W. --state-dir covers the
# volume's own state, but pelfs also derives a per-volume directory from
# stateRoot() (cmd/pelfs/daemon.go), which is $XDG_STATE_HOME/pelfs or
# ~/.local/state/pelfs -- so a run without this line leaves an empty vol-<id>
# directory in the developer's real state root. Measured: it did.
export XDG_STATE_HOME="$W/xdg"
mkdir -p "$XDG_STATE_HOME"

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$W"
}
trap cleanup EXIT

if command -v pnpm >/dev/null 2>&1; then
    PNPM=(pnpm)
elif command -v corepack >/dev/null 2>&1; then
    PNPM=(corepack pnpm)
    export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
else
    echo "webui-playwright: needs pnpm or corepack (see webui/frontend/.nvmrc)" >&2
    exit 1
fi

# Waits for a line to appear in a log, without a fixed sleep. A fixed sleep is
# how a gate becomes flaky: too short on a loaded runner, wasted time
# everywhere else.
wait_for_line() {
    local file="$1" pattern="$2" what="$3" tries=${4:-600}
    for _ in $(seq "$tries"); do
        if [[ -s "$file" ]] && grep -qE "$pattern" "$file"; then
            return 0
        fi
        sleep 0.1
    done
    echo "webui-playwright: $what never appeared (waited $((tries / 10))s)" >&2
    echo "--- log ---" >&2
    cat "$file" >&2 || true
    return 1
}

cd "$FRONT"
"${PNPM[@]}" install --frozen-lockfile

# The browser build is pinned by the @playwright/test version in
# package.json: playwright refuses to run against a revision it was not built
# for, which is exactly the pin we want -- an unpinned browser download is a
# silently moving target. `playwright install` is a no-op once the revision is
# cached, which is why CI caches ~/.cache/ms-playwright keyed on that version.
if [[ "${PELFS_WEBUI_SKIP_BROWSER_INSTALL:-}" != "1" ]]; then
    "${PNPM[@]}" exec playwright install chromium
fi

# THE ATTACKER ORIGIN, and it has to be a server of its own.
#
# The obvious shortcut -- point the browser at OUR server under the mapped
# hostname and call that the attacker page -- does not work for the battery,
# and quietly: `pelfs browse` answers a rebound Host with 421 and every
# response carries `Content-Security-Policy: default-src 'none'; form-action
# 'none'`, so a fetch or a form submission from that page is stopped by OUR
# OWN CSP before it is stopped by anything the test is about. The spec would
# pass while proving nothing. (Keeping the 421 assertion itself is right: that
# IS the rebinding case.)
#
# So: a five-line static server on its own port, serving one empty page, with
# no CSP and no relationship to pelfs. Chromium's --host-resolver-rules maps
# the hostname for every port, so http://attacker.test:<its port>/ is a
# genuinely cross-site origin whose requests to pelfs are refused -- or not --
# on their merits.
node -e 'require("http").createServer(function(q,s){s.writeHead(200,{"content-type":"text/html; charset=utf-8"});s.end("<!doctype html><meta charset=utf-8><title>attacker</title><body>a page the user merely visited")}).listen(0,"127.0.0.1",function(){console.log("ATTACKER "+this.address().port)})' >"$W/attacker.log" 2>&1 &
PIDS+=($!)
wait_for_line "$W/attacker.log" '^ATTACKER ' "the attacker page server"
ATTACKER_PORT="$(sed -n 's/^ATTACKER //p' "$W/attacker.log" | head -1)"
export PELFS_WEBUI_ATTACKER_URL="http://${PELFS_WEBUI_ATTACKER_HOST:-attacker.test}:$ATTACKER_PORT/"
echo "== attacker page at $PELFS_WEBUI_ATTACKER_URL =="

# The session token the suite exchanges is cached here rather than in the
# system temp directory, so a run leaves nothing behind and two concurrent
# runs cannot read each other's.
export PELFS_WEBUI_SESSION_DIR="$W"

echo "== building pelfs =="
(cd "$REPO" && CGO_ENABLED=0 go build -o "$W/pelfs" ./cmd/pelfs)

# `|| true` and a captured string rather than a pipeline: printing usage is a
# non-zero exit, and `set -o pipefail` would turn that into "the verb is
# missing" -- a detection bug that silently downgrades the gate.
MODE=embed
usage="$("$W/pelfs" 2>&1 || true)"
if grep -q 'pelfs browse' <<<"$usage"; then
    MODE=browse
fi
# The fallback path has to stay runnable even after `pelfs browse` exists, or
# it rots exactly like any other untested branch.
if [[ -n "${PELFS_WEBUI_FORCE_MODE:-}" ]]; then
    MODE="$PELFS_WEBUI_FORCE_MODE"
fi
echo "== mode: $MODE =="

if [[ "$MODE" == browse ]]; then
    (cd "$REPO" && CGO_ENABLED=0 go build -o "$W/fakeorigin" ./cmd/fakeorigin)

    mkdir -p "$W/origin" "$W/state"
    "$W/fakeorigin" -listen 127.0.0.1:0 -root "$W/origin" >"$W/origin.log" 2>&1 &
    PIDS+=($!)
    wait_for_line "$W/origin.log" '^LISTENING ' "the fakeorigin listen address"
    ORIGIN="$(sed -n 's/^LISTENING //p' "$W/origin.log" | head -1)"
    PREFIX="http://$ORIGIN/vol"
    echo "== fakeorigin on $ORIGIN, volume $PREFIX =="

    # The volume's signing key lands in the state dir that created it, and a
    # later seal needs it, so create and serve share one --state-dir.
    "$W/pelfs" shell --state-dir "$W/state" "$PREFIX" -- true >"$W/create.log" 2>&1

    # --rw so the suite can exercise the publish path; the page is read-only
    # otherwise and "Publish now" is not reachable at all.
    #
    # --test-hooks is what makes the states the suite has to cover REACHABLE:
    # a fresh volume is clean, so "staged but not published" cannot happen by
    # itself, and a lease that has gone stale, been interrupted or been lost
    # cannot be arranged from outside at all. The flag is off by default, it
    # announces itself in the terminal and in a banner on the page, and it
    # sits on the authenticated API surface -- see cmd/pelfs/browse.go's
    # serveTestHook for why it is a flag rather than a build tag: a build tag
    # would mean the browser suite drives a DIFFERENT BINARY from the one CI
    # ships, which is the one property a browser test exists to check.
    "$W/pelfs" browse --rw --test-hooks --state-dir "$W/state" "$PREFIX" >"$W/browse.log" 2>&1 &
    PIDS+=($!)
    # The FRAGMENT is what identifies the launch URL. The log also contains
    # the volume prefix, which is itself an http://127.0.0.1 URL on this
    # harness (the federation is a fakeorigin on loopback), so matching the
    # first loopback URL in the log picks up the wrong one -- it did, and the
    # suite then asserted against a 404 from the fakeorigin.
    wait_for_line "$W/browse.log" 'http://127\.0\.0\.1:[0-9]+/#bt=' "the browse URL"

    LAUNCH="$(grep -oE 'http://127\.0\.0\.1:[0-9]+/#bt=[A-Za-z0-9._~-]+' "$W/browse.log" | head -1)"
    export PELFS_WEBUI_URL="${LAUNCH%%#*}"
    # The bootstrap token is single-use and arrives in the FRAGMENT, which is
    # why it has to be handed over separately: a fragment is not sent to the
    # server, so the suite has to put it back on the URL itself.
    if [[ "$LAUNCH" == *"#bt="* ]]; then
        export PELFS_WEBUI_BOOTSTRAP="${LAUNCH#*#bt=}"
    fi
    export PELFS_WEBUI_MODE=browse
    # The volume the page must name, so the suite asserts against the volume
    # this run actually created rather than a hard-coded string.
    export PELFS_WEBUI_VOLUME="$PREFIX"
    echo "== serving $PELFS_WEBUI_URL (bootstrap token: ${PELFS_WEBUI_BOOTSTRAP:+present}) =="
else
    # The embedded bundle, served by the Go test. -count=1 so a cached PASS
    # cannot masquerade as a running server.
    (cd "$REPO" && PELFS_WEBUI_SERVE=1 PELFS_WEBUI_SERVE_TIMEOUT=10m \
        CGO_ENABLED=0 go test ./internal/webui -run TestServeEmbeddedForBrowserSuite \
        -count=1 -timeout 12m -v >"$W/serve.log" 2>&1) &
    PIDS+=($!)
    wait_for_line "$W/serve.log" '^PELFS_WEBUI_BOOTSTRAP=' "the embedded server's bootstrap token"
    export PELFS_WEBUI_URL="$(sed -n 's/^PELFS_WEBUI_URL=//p' "$W/serve.log" | head -1)"
    # The embedded server runs the REAL internal/browsesession and a mock JSON
    # API (internal/webui/mockapi_test.go), so the app's own credential flow --
    # single-use bootstrap in the fragment, header-borne session token,
    # ticketed download -- is what the suite drives here. The token is handed
    # over separately for the same reason it is in browse mode: a fragment is
    # not sent to the server, so the suite has to put it back on the URL
    # itself. Waiting for the BOOTSTRAP line also waits for the URL line,
    # which is printed first.
    export PELFS_WEBUI_BOOTSTRAP="$(sed -n 's/^PELFS_WEBUI_BOOTSTRAP=//p' "$W/serve.log" | head -1)"
    export PELFS_WEBUI_MODE=embed
    echo "== serving $PELFS_WEBUI_URL (embedded bundle + mock API; \`pelfs browse\` not in this binary) =="
fi

set +e
"${PNPM[@]}" exec playwright test "$@"
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
    echo "--- server log ---" >&2
    cat "$W/browse.log" "$W/serve.log" 2>/dev/null >&2 || true
fi
exit $rc
