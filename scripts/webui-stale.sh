#!/usr/bin/env bash
#
# Is the committed bundle still the one webui/frontend would produce?
#
# THE FAILURE THIS EXISTS TO END. `make` runs `go build`, which embeds the
# COMMITTED internal/webui/dist and never runs `go generate`. For a plain
# checkout that is correct and is the entire point of committing the bundle: a
# contributor with no Node gets a working UI. But when the frontend sources are
# newer than the bundle, `make` embedded the old one and said nothing -- and
# from the outside that is indistinguishable from "my change did not happen".
# It was reported in exactly those words: "the previously requested changes for
# the 'Publish Now' button look like they weren't done. Is that a problem with
# the make target?"
#
# So: SILENCE IS THE ONE OUTCOME THAT IS NOT ALLOWED. Either the bundle is
# current, or this regenerates it, or it fails with the command to run.
#
# Usage:
#   scripts/webui-stale.sh          regenerate if stale and Node is here,
#                                   otherwise fail with the command to run
#   scripts/webui-stale.sh --check  report and fail; never build
#
# UI_STALE=allow in the environment downgrades the failure to a warning, for
# the one honest case (no Node, no network, and a binary is needed now). It is
# still a line on the terminal, which is all this script is really for.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

manifest="internal/webui/bundle.inputs"
mode="${1:-}"

now="$(scripts/webui-inputs.sh)"

if [[ -f "$manifest" ]]; then
    then_="$(grep -v '^#' "$manifest" || true)"
else
    then_=""
fi

if [[ "$now" == "$then_" ]]; then
    exit 0
fi

# WHICH FILES, because "something changed" is a worse message than the one the
# reader can act on. Compare the two manifests by path.
changed="$(
    {
        printf '%s\n' "$then_" | sed 's/^/O /'
        printf '%s\n' "$now" | sed 's/^/N /'
    } | awk '
        $1 == "O" && $3 != "" { old[$3] = $2; next }
        $1 == "N" && $3 != "" { cur[$3] = $2 }
        END {
            for (f in cur) {
                if (!(f in old))          printf "    + %s (new)\n", f
                else if (old[f] != cur[f]) printf "    M %s\n", f
            }
            for (f in old) if (!(f in cur)) printf "    - %s (gone)\n", f
        }' | LC_ALL=C sort -k 2
)"
# A missing manifest is one fact, not thirty: listing every input as new tells
# the reader nothing they can act on.
if [[ -z "$then_" ]]; then
    changed="    ($manifest is missing, so what the bundle was built from is unknown)"
else
    # Long enough to see the shape of the change, short enough to read.
    total=$(printf '%s\n' "$changed" | wc -l | tr -d ' ')
    if ((total > 12)); then
        changed="$(printf '%s\n' "$changed" | head -12)
    ... and $((total - 12)) more"
    fi
fi

# Node, by the same rule scripts/webui-build.sh uses: a real pnpm, or corepack,
# which every Node >= 16.9 ships.
if command -v node >/dev/null 2>&1 &&
    { command -v pnpm >/dev/null 2>&1 || command -v corepack >/dev/null 2>&1; }; then
    have_node=yes
else
    have_node=no
fi

if [[ "$mode" != "--check" && "$have_node" == "yes" ]]; then
    echo "webui: the committed bundle is older than webui/frontend; regenerating." >&2
    echo "$changed" >&2
    exec scripts/webui-build.sh
fi

cat >&2 <<MSG

THE COMMITTED WEB UI BUNDLE DOES NOT MATCH webui/frontend.

internal/webui/dist is a committed build artefact and \`go build\` embeds it as
it is -- it does not run \`go generate\`. Building now would put the OLD UI in
the binary and say nothing, which looks exactly like a change that did not
happen. These inputs differ from the ones the bundle was built from:

$changed

To fix it:

    make ui

MSG

if [[ "$have_node" == "no" ]]; then
    cat >&2 <<'MSG'
(That needs Node, which is not on PATH here. webui/frontend/.nvmrc has the
pinned version; then `corepack enable` or install pnpm.)

MSG
fi

if [[ "${UI_STALE:-}" == "allow" ]]; then
    echo "webui: UI_STALE=allow -- building with the COMMITTED bundle anyway." >&2
    exit 0
fi

cat >&2 <<'MSG'
Or, to build with the committed bundle anyway and know that you did:

    make build UI_STALE=allow

MSG
exit 1
