#!/usr/bin/env bash
# Metadata-throughput benchmark for the catalog-native read-write mount,
# run on a real Linux kernel in a container (macOS denies the shell access
# to its own FUSE mounts, so this is the only honest local measurement).
#
# The workload is the untar shape: tens of thousands of small files across
# thousands of directories, the thing that is slow in practice while bulk
# transfer is fine. Three layers are timed so the cost can be ATTRIBUTED
# rather than guessed at:
#
#   1. tmpfs        — the same untar with no pelfs at all (floor)
#   2. overlay-only — the overlay's Go benchmarks, no kernel, no FUSE
#   3. rw mount     — the full stack through /dev/fuse
#
# The federation is a fakeorigin on loopback with zero latency, so a slow
# run here proves the bottleneck is LOCAL (overlay/FUSE), not round trips
# to a remote origin.
#
# Usage: scripts/bench-untar-docker.sh [files] [dirs]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_PHASE3_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_PHASE3_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
FILES="${1:-30000}"
DIRS="${2:-3000}"
STAGE="$(mktemp -d)"
OUT="${PELFS_BENCH_OUT:-$STAGE/out}"
mkdir -p "$OUT"
trap 'rm -rf "$STAGE"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

IMAGE_TAG="pelfs-phase3-runner:1"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the test image (once) =="
  docker build -q -t "$IMAGE_TAG" - <<DOCKERFILE
FROM ${IMAGE}
RUN apt-get -qq update && apt-get -qq install -y fuse3 curl nfs-common \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

echo "== cross-compiling for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
# The overlay benchmarks run in the same container so layer 2 is measured
# on the same kernel and the same tmpfs as layer 3.
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go test -c -o "$STAGE/overlay.test" ./internal/overlay)

cat > "$STAGE/bench.sh" <<'INNER'
set -euo pipefail
FILES="$1"; DIRS="$2"
W=/work
mkdir -p "$W/origin" "$W/mnt" "$W/tmpfsdst" "$W/out"

t0() { date +%s.%N; }
rate() { # rate <label> <start> <end> <count>
  awk -v l="$1" -v s="$2" -v e="$3" -v n="$4" \
    'BEGIN{d=e-s; printf "%-28s %8.2fs  %9.0f files/s  %8.0f us/file\n", l, d, n/d, d*1e6/n}'
}

echo "== generating a $FILES-file / $DIRS-dir corpus on tmpfs =="
SRC="$W/src/tree"
per=$(( FILES / DIRS )); [ "$per" -lt 1 ] && per=1
S=$(t0)
for d in $(seq 0 $((DIRS - 1))); do
  dir="$SRC/g$((d / 64))/d$d"
  mkdir -p "$dir"
  for f in $(seq 0 $((per - 1))); do
    printf 'file %d %d\n%*s' "$d" "$f" 900 '' > "$dir/f$f.c"
  done
done
E=$(t0)
NFILES=$(find "$SRC" -type f | wc -l)
rate "corpus generation" "$S" "$E" "$NFILES"
tar -C "$W/src" -cf "$W/tree.tar" tree
echo "corpus: $NFILES files, $(find "$SRC" -type d | wc -l) dirs"

echo
echo "== layer 1: untar into bare tmpfs (floor) =="
S=$(t0); tar -C "$W/tmpfsdst" -xf "$W/tree.tar"; E=$(t0)
rate "tmpfs untar" "$S" "$E" "$NFILES"

echo
echo "== layer 2: overlay only (no kernel, no FUSE) =="
TMPDIR=$W /stage/overlay.test -test.run '^$' \
  -test.bench 'BenchmarkOverlayCreate$|BenchmarkOverlayCreateWrite$' \
  -test.benchtime 20000x -test.benchmem 2>/dev/null | grep -E '^Benchmark' || true

echo
echo "== starting fakeorigin (loopback, zero latency) =="
/stage/fakeorigin -listen 127.0.0.1:18999 -root "$W/origin" &
ORIGIN_PID=$!
for _ in $(seq 50); do curl -fsS http://127.0.0.1:18999/ >/dev/null 2>&1 && break; sleep 0.1; done
PREFIX="http://127.0.0.1:18999/vol"

# The volume's signing key lands in the state dir that created it, and a
# later seal needs it, so create and mount share one state dir.
echo "== creating the v2 volume =="
/stage/pelfs shell --state-dir "$W/state" "$PREFIX" -- true > "$W/out/create.log" 2>&1

# One small run with FUSE tracing on: the op MIX per extracted file is
# what says whether the cost is per-operation work or operation count.
echo "== FUSE op mix (200-file sample, traced) =="
mkdir -p "$W/dbgsrc/t" "$W/dbgmnt"
for i in $(seq 0 199); do echo x > "$W/dbgsrc/t/f$i"; done
tar -C "$W/dbgsrc" -cf "$W/dbg.tar" t
/stage/pelfs mount-gen --rw --no-lease --no-seal --debug --state-dir "$W/statedbg" \
  "$PREFIX" "$W/dbgmnt" > "$W/out/debug.log" 2>&1 &
DBG_PID=$!
for _ in $(seq 300); do mountpoint -q "$W/dbgmnt" && break; sleep 0.1; done
tar -C "$W/dbgmnt" -xf "$W/dbg.tar"
fusermount3 -u "$W/dbgmnt" 2>/dev/null || umount "$W/dbgmnt" || true
wait "$DBG_PID" 2>/dev/null || true
grep -oE 'rx [0-9]+: [A-Z]+' "$W/out/debug.log" | awk '{print $3}' | sort | uniq -c | sort -rn |
  awk -v n=200 '{tot+=$1; printf "  %-12s %6d  %5.1f/file\n", $2, $1, $1/n} END{printf "  %-12s %6d  %5.1f/file\n", "TOTAL", tot, tot/n}'

echo "== layer 3: untar into a catalog-native rw mount =="
/stage/pelfs mount-gen --rw --no-lease --state-dir "$W/state" "$PREFIX" "$W/mnt" \
  > "$W/out/mount.log" 2>&1 &
MOUNT_PID=$!
for _ in $(seq 300); do mountpoint -q "$W/mnt" && break; sleep 0.1; done
mountpoint -q "$W/mnt" || { echo "mount did not come up" >&2; cat "$W/out/mount.log"; exit 1; }

# The profile covers the untar itself; 60s is longer than the run needs to
# be interesting and the fetch returns as soon as it elapses.
( /stage/pelfs ctl "$W/state" pprof 'profile?seconds=60' -o "$W/out/untar-cpu.pprof" \
    > "$W/out/pprof.log" 2>&1 || true ) &
PPROF_PID=$!

# utime+stime of the mount process across the untar answers "is this CPU
# in pelfs, or waiting?" — the question a sampling profile alone cannot.
cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }

mkdir -p "$W/mnt/dst"
C0=$(cpu_ticks "$MOUNT_PID")
S=$(t0); tar -C "$W/mnt/dst" -xf "$W/tree.tar"; E=$(t0)
C1=$(cpu_ticks "$MOUNT_PID")
rate "pelfs rw-mount untar" "$S" "$E" "$NFILES"
awk -v c0="$C0" -v c1="$C1" -v s="$S" -v e="$E" -v hz="$(getconf CLK_TCK)" \
  'BEGIN{cpu=(c1-c0)/hz; printf "%-28s %8.2fs  %9.1f%% of wall\n", "  of which pelfs CPU", cpu, 100*cpu/(e-s)}'
UNTAR_S=$S; UNTAR_E=$E

echo
echo "== metadata walk over the freshly written (dirty) tree =="
S=$(t0); find "$W/mnt/dst" -type f -printf '' ; E=$(t0)
rate "find over dirty tree" "$S" "$E" "$NFILES"

wait "$PPROF_PID" 2>/dev/null || true
awk -v s="$UNTAR_S" -v e="$UNTAR_E" 'BEGIN{printf "untar window: %.1fs of the 60s profile\n", e-s}'

echo
echo "== sealing (this is the federation-facing half) =="
S=$(t0)
fusermount3 -u "$W/mnt" 2>/dev/null || fusermount -u "$W/mnt" 2>/dev/null || umount "$W/mnt"
wait "$MOUNT_PID" 2>/dev/null || true
E=$(t0)
rate "seal + publish at unmount" "$S" "$E" "$NFILES"
tail -3 "$W/out/mount.log" || true

kill "$ORIGIN_PID" 2>/dev/null || true
cp -a "$W/out/." /out/ 2>/dev/null || true
INNER

echo "== running the metadata benchmark on a real Linux kernel =="
exec docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --network none \
  -v "$STAGE":/stage:ro \
  -v "$OUT":/out \
  --tmpfs /work:rw,size=4g,exec \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/bench.sh "$FILES" "$DIRS"
