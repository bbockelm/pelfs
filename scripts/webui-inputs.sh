#!/usr/bin/env bash
#
# Prints `sha256  path` for every file that goes INTO internal/webui/dist and
# internal/webui/third_party.txt, sorted. It is the single definition of what
# an input is: scripts/webui-build.sh writes this list to
# internal/webui/bundle.inputs after a build, and scripts/webui-stale.sh
# recomputes it to decide whether the committed bundle still matches the
# sources in the tree.
#
# WHY CONTENT AND NOT MTIME. `make` would normally answer this with timestamps,
# and timestamps cannot answer it here: `git clone` and `git checkout` write
# files in index order, so webui/frontend/** always lands AFTER
# internal/webui/dist/** and every clean checkout would look stale. A
# contributor with no Node has to get a silent, clean build out of an unmodified
# tree -- that is the whole reason the bundle is committed -- so the check has
# to be about bytes, and bytes survive a clone.
#
# WHAT COUNTS AS AN INPUT is everything the bundle or the notices are built
# from, and nothing else:
#
#   src/**            the app
#   index.html        vite's entry document
#   public/**         the brand assets, copied into dist verbatim
#   vite.config.ts    the build itself, including the two plugins that rewrite
#                     CSS and the offline scan
#   tsconfig.json     compiler options the transform obeys
#   package.json      dependencies, the pinned pnpm, and the scripts run
#   pnpm-lock.yaml    the exact versions resolved -- a bundle built from a
#                     different lockfile is a different bundle
#   tools/**          third-party.mjs writes third_party.txt, which is a
#                     committed output, and licence-check.mjs gates the build
#
# tests/, probe/ and playwright.config.ts are deliberately NOT inputs: nothing
# in them reaches dist, and a spec edit that forced a rebuild would train
# people to ignore this check.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

singles=(
    webui/frontend/index.html
    webui/frontend/package.json
    webui/frontend/pnpm-lock.yaml
    webui/frontend/tsconfig.json
    webui/frontend/vite.config.ts
)
trees=(
    webui/frontend/src
    webui/frontend/public
    webui/frontend/tools
)

for f in "${singles[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "webui-inputs: $f is missing; the input set in this script is wrong" >&2
        exit 1
    fi
done
for d in "${trees[@]}"; do
    if [[ ! -d "$d" ]]; then
        echo "webui-inputs: $d is missing; the input set in this script is wrong" >&2
        exit 1
    fi
done

# LC_ALL=C on both sorts: a locale-dependent order would make the manifest
# differ between a contributor's machine and CI, which is the one thing a
# committed artefact must never do.
{
    printf '%s\n' "${singles[@]}"
    find "${trees[@]}" -type f -print
} | LC_ALL=C sort | tr '\n' '\0' | xargs -0 shasum -a 256 | LC_ALL=C sort -k 2
