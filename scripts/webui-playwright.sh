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
    "$W/pelfs" browse --rw --state-dir "$W/state" "$PREFIX" >"$W/browse.log" 2>&1 &
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
    wait_for_line "$W/serve.log" '^PELFS_WEBUI_URL=' "the embedded server's URL"
    export PELFS_WEBUI_URL="$(sed -n 's/^PELFS_WEBUI_URL=//p' "$W/serve.log" | head -1)"
    export PELFS_WEBUI_MODE=embed
    echo "== serving $PELFS_WEBUI_URL (embedded bundle only; \`pelfs browse\` not in this binary) =="
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
