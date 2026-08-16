#!/usr/bin/env bash
# Op-sequence fuzzing containment launcher — the ONLY sanctioned way to
# run the overlay op fuzzer (internal/overlay/opfuzz_test.go).
#
# Split by trust: COMPILATION happens on the host (compiling is not
# fuzzing; CGO_ENABLED=0 cross-compile to a static linux binary), and
# EXECUTION happens inside a sealed container that receives nothing but
# that binary, read-only:
#   - no network, all capabilities dropped, no-new-privileges,
#     unprivileged user, read-only rootfs,
#   - the ONLY writable space is a tmpfs scratch,
#   - no repo mount, no module cache, no toolchain — nothing to damage,
#   - PELFS_OPFUZZ_CONTAINED=1 is set only here; the harness skips
#     without it and does its own path work through os.Root.
#
# Usage: scripts/opfuzz-docker.sh [fuzztime] [pattern]
#   scripts/opfuzz-docker.sh 5m              # fuzz FuzzOps for 5 minutes
#   scripts/opfuzz-docker.sh 0 Stress        # stress test instead
set -euo pipefail

FUZZTIME="${1:-60s}"
PATTERN="${2:-FuzzOps}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_OPFUZZ_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_OPFUZZ_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
BIN="$(mktemp -d)/opfuzz.test"
trap 'rm -rf "$(dirname "$BIN")"' EXIT

command -v docker >/dev/null || { echo "docker is required (containment is mandatory)" >&2; exit 1; }

echo "== cross-compiling fuzz binary (linux/$ARCH, static) =="
if [[ "$PATTERN" == Fuzz* ]]; then
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go test -c -tags "opfuzz,nogspt,notikv" -o "$BIN" ./internal/overlay/)
  RUNARGS=(-test.run xxx -test.fuzz "^${PATTERN}\$" -test.fuzztime "$FUZZTIME" -test.fuzzcachedir /scratch/fuzzcache)
else
  # The race detector needs cgo, so cross-compiles from macOS run the
  # stress test race-less; a linux host compiles it with -race natively.
  RACE=""
  [[ "$(uname -s)" == "Linux" ]] && RACE=1 || true
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go test -c ${RACE:+-race} -tags "opfuzz,nogspt,notikv" -o "$BIN" ./internal/overlay/)
  RUNARGS=(-test.run "$PATTERN" -test.count=1 -test.v)
fi

echo "== running sealed (network none, caps dropped, RO rootfs, tmpfs scratch) =="
exec docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65534:65534 \
  --read-only \
  --tmpfs /scratch:rw,size=1g,uid=65534,gid=65534,mode=0700 \
  --tmpfs /tmp:rw,size=256m,uid=65534,gid=65534,mode=0700 \
  -v "$BIN":/opfuzz.test:ro \
  -e HOME=/scratch \
  -e PELFS_OPFUZZ_CONTAINED=1 \
  -e PELFS_OPFUZZ_SCRATCH=/scratch/fuzz \
  -w /scratch \
  "$IMAGE" \
  sh -c 'mkdir -p /scratch/fuzz /scratch/fuzzcache && /opfuzz.test "$@"' -- "${RUNARGS[@]}"
