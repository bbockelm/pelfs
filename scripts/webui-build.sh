#!/usr/bin/env bash
#
# Builds the browser UI into internal/webui/dist and regenerates
# internal/webui/third_party.txt. Both outputs are COMMITTED, and a CI job
# rebuilds them and fails on any diff -- so this script is the single
# definition of how that output is produced. `go generate ./internal/webui`
# runs exactly this and nothing else.
#
# It also records WHICH SOURCES the output was built from, by content, in
# internal/webui/bundle.inputs. That file is what lets `make build` notice a
# bundle older than its sources and refuse to embed it in silence
# (scripts/webui-stale.sh); it is committed with the bundle, and the CI
# regenerate-and-diff gate covers it too.
#
# THIS IS THE ONLY THING IN THE REPOSITORY THAT NEEDS NODE. `go build ./...`,
# `go vet ./...` and `go test ./...` need none of it, because the bundle is in
# the tree; that property is the whole point of committing it, and
# scripts/build-pelican-server.sh's header records what happens when a Go
# build path assumes a JavaScript toolchain is present ("died with
# `/bin/sh: 1: pnpm: not found` forty lines into someone else's Makefile --
# which reads like a test failure and is not one").
#
# Usage:
#   scripts/webui-build.sh            build + notices
#   scripts/webui-build.sh --twice    build twice and prove the output is
#                                     byte-identical (the determinism check
#                                     the regenerate-and-diff gate rests on)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
front="$root/webui/frontend"
dist="$root/internal/webui/dist"
notices="$root/internal/webui/third_party.txt"
inputs="$root/internal/webui/bundle.inputs"

# pnpm is reached through whatever the machine has: a real pnpm on PATH, or
# corepack, which every Node >= 16.9 ships and which reads the exact version
# from package.json's `packageManager` field. Nothing here installs a global.
if command -v pnpm >/dev/null 2>&1; then
    PNPM=(pnpm)
elif command -v corepack >/dev/null 2>&1; then
    PNPM=(corepack pnpm)
    export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
else
    cat >&2 <<'MSG'
webui-build: no pnpm and no corepack on PATH.

Nothing in `go build`, `go vet` or `go test` needs them -- the bundle in
internal/webui/dist is committed. You only need them to CHANGE the UI. Install
Node (see webui/frontend/.nvmrc for the pinned version) and either `corepack
enable` or `npm i -g pnpm@$(sed -n 's/.*"packageManager": "pnpm@\([^"]*\)".*/\1/p' webui/frontend/package.json)`.
MSG
    exit 1
fi

echo "webui-build: node $(node --version 2>/dev/null || echo '?'), pnpm $("${PNPM[@]}" --version)"
cd "$front"

# --frozen-lockfile: the lockfile is an input to a committed artefact, so a
# build that silently resolves something else is a build whose output nobody
# can reproduce.
"${PNPM[@]}" install --frozen-lockfile

# The licence guard runs BEFORE the bundle is written, so a GPLv3 `wx-*`
# package can never reach internal/webui/dist even locally.
"${PNPM[@]}" run licence-check

"${PNPM[@]}" run build
"${PNPM[@]}" run notices

if [[ "${1:-}" == "--twice" ]]; then
    first="$(mktemp)"
    (cd "$root" && find internal/webui/dist -type f -exec shasum -a 256 {} + | sort) >"$first"
    "${PNPM[@]}" run build >/dev/null
    second="$(mktemp)"
    (cd "$root" && find internal/webui/dist -type f -exec shasum -a 256 {} + | sort) >"$second"
    if ! diff -u "$first" "$second"; then
        echo "webui-build: THE BUILD IS NOT DETERMINISTIC -- two runs of the pinned" >&2
        echo "toolchain produced different bytes. The regenerate-and-diff gate cannot" >&2
        echo "be trusted until this is fixed; do not paper over it with a retry." >&2
        exit 1
    fi
    echo "webui-build: two runs produced byte-identical output"
    rm -f "$first" "$second"
fi

# LAST, and only after a build that succeeded: the manifest is a claim that
# dist was produced from these exact bytes, so writing it earlier would let a
# failed build leave a claim behind that nothing had checked.
{
    cat <<'HDR'
# What internal/webui/dist and internal/webui/third_party.txt were built from,
# by CONTENT. Written by scripts/webui-build.sh and checked by
# scripts/webui-stale.sh, which `make build` runs so that a bundle older than
# its sources cannot be embedded in silence. Timestamps cannot do this job: a
# fresh clone writes webui/frontend AFTER internal/webui/dist, so every clean
# checkout would look stale. scripts/webui-inputs.sh defines what an input is.
HDR
    "$root/scripts/webui-inputs.sh"
} >"$inputs"

echo "webui-build: wrote $dist, $notices and $inputs"
