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
# Usage: scripts/opfuzz-docker.sh [budget] [pattern]
#   scripts/opfuzz-docker.sh                 # exactly what CI's gate runs
#   scripts/opfuzz-docker.sh 1000000x        # ... or a longer soak
#   scripts/opfuzz-docker.sh 5m              # ... or a wall-clock budget
#   scripts/opfuzz-docker.sh 0 Stress        # stress test instead
#
# BUDGET THE WORK, NOT THE WALL CLOCK. `Nx` (a -fuzztime exec count) is
# the form CI uses, for two reasons:
#
#   1. It is the honest unit. Coverage is a function of executions, and
#      this fuzzer runs ~6x slower on a 4-vCPU GitHub runner (~900/sec)
#      than on the author's laptop (~5000/sec), so a wall-clock budget
#      buys an unknown and machine-dependent amount of fuzzing.
#   2. A duration budget walks into an open bug in Go's fuzzing engine
#      (golang/go#72104, #72088; see KL-23 in docs/known-issues.md): at
#      the fuzztime boundary the coordinator can report its own normal
#      termination as the test failure "context deadline exceeded" —
#      no crasher, no input written, just a red job. `Nx` sets
#      CoordinateFuzzingOpts.Limit and leaves Timeout at 0, so the
#      deadline context that loses that race is never created.
#
# The engine's wall clock was also the only bound on a HUNG fuzz target,
# so a COUNT budget gets -test.timeout instead (PELFS_OPFUZZ_HARDTIMEOUT,
# default 15m): a hang dies with every goroutine stack rather than with a
# job kill. A duration budget keeps its own clock and gets no extra one.
#
# Repro knobs, for making a laptop behave like a contended CI runner
# (they only ever add restrictions to the sealed container):
#   PELFS_OPFUZZ_CPUS=2 PELFS_OPFUZZ_GOMAXPROCS=4 PELFS_OPFUZZ_MEMORY=2g
set -euo pipefail

# Default: the CI budget, so `make opfuzz` is the gate and not a cousin.
FUZZTIME="${1:-120000x}"
PATTERN="${2:-FuzzOps}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_OPFUZZ_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_OPFUZZ_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
BIN="$(mktemp -d)/opfuzz.test"
trap 'rm -rf "$(dirname "$BIN")"' EXIT

command -v docker >/dev/null || { echo "docker is required (containment is mandatory)" >&2; exit 1; }

# The race detector needs cgo, and a cgo binary must run on the libc it
# was built against — so for the stress mode we build INSIDE the image
# that will run it, rather than cross-compiling on the host. Fuzzing
# proper stays a static cross-compile: no toolchain in the sealed
# container at all.
if [[ "$PATTERN" == Fuzz* ]]; then
  echo "== cross-compiling fuzz binary (linux/$ARCH, static) =="
  # A count budget has no wall clock of its own; give the binary one, so a
  # hung fuzz target prints goroutines instead of waiting for the job cap.
  # 15m is ~6x the time this budget takes on the slowest runner measured.
  if [[ "$FUZZTIME" == *x ]]; then
    HARDTIMEOUT="${PELFS_OPFUZZ_HARDTIMEOUT:-15m}"
  else
    HARDTIMEOUT="${PELFS_OPFUZZ_HARDTIMEOUT:-0}"
  fi
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go test -c -tags opfuzz -o "$BIN" ./internal/overlay/)
  RUNARGS=(-test.run xxx -test.fuzz "^${PATTERN}\$" -test.fuzztime "$FUZZTIME" -test.timeout "$HARDTIMEOUT" -test.fuzzcachedir /scratch/fuzzcache)
else
  echo "== building the race binary inside the runner image =="
  BUILDER="${PELFS_OPFUZZ_BUILDER:-golang:1.26}"
  docker run --rm \
    --network none \
    -v "$REPO":/src:ro \
    -v "$(go env GOMODCACHE)":/gomod:ro \
    --tmpfs /out:rw,size=256m,exec \
    --tmpfs /gocache:rw,size=8g \
    -e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOFLAGS=-mod=readonly \
    -e CGO_ENABLED=1 -w /src \
    "$BUILDER" \
    sh -c 'go test -c -race -tags opfuzz -o /out/opfuzz.test ./internal/overlay/ && cp /out/opfuzz.test /dev/stdout' > "$BIN"
  chmod +x "$BIN"
  IMAGE="$BUILDER" # run on the libc it was built against
  RUNARGS=(-test.run "$PATTERN" -test.count=1 -test.v)
fi

# Optional extra restrictions on the sealed container, for reproducing a
# contended CI runner on a fast laptop. Never relaxations.
LIMITS=()
[[ -n "${PELFS_OPFUZZ_CPUS:-}" ]] && LIMITS+=(--cpus "$PELFS_OPFUZZ_CPUS")
[[ -n "${PELFS_OPFUZZ_MEMORY:-}" ]] && LIMITS+=(--memory "$PELFS_OPFUZZ_MEMORY")
[[ -n "${PELFS_OPFUZZ_GOMAXPROCS:-}" ]] && LIMITS+=(-e GOMAXPROCS="$PELFS_OPFUZZ_GOMAXPROCS")

echo "== running sealed (network none, caps dropped, RO rootfs, tmpfs scratch) =="
exec docker run --rm \
  ${LIMITS[@]+"${LIMITS[@]}"} \
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
