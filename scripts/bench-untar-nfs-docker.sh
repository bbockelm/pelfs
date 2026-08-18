#!/usr/bin/env bash
# Metadata-throughput benchmark for the NFS frontend, measured against the
# FUSE frontend over the SAME corpus and the SAME catalog-native stack.
#
# The NFS backend is not a curiosity: it is the only mount a macOS box
# without macFUSE can get (`resolveBackend` picks it there), so it is the
# path the project owner actually runs. scripts/bench-untar-docker.sh
# measures the FUSE half; this measures both so the gap is a number.
#
# Everything runs on a real Linux kernel in a container: macOS denies the
# shell access to its own NFS/FUSE mounts, and the repo forbids mounting
# anywhere near $HOME. The Linux NFS client is NOT the macOS one, so the
# absolute macOS numbers do not transfer -- but server-side cost per RPC
# and RPC count per file do, and those are what this measures.
#
# The untar is split into equal chunks that are timed separately. A rate
# that decays chunk over chunk is the signature of a per-op cost that
# scales with how much has already been written, which a single aggregate
# rate hides completely.
#
# Usage: scripts/bench-untar-nfs-docker.sh [files] [dirs] [chunks]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_PHASE3_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_PHASE3_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
FILES="${1:-8000}"
DIRS="${2:-400}"
CHUNKS="${3:-4}"
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

cat > "$STAGE/bench.sh" <<'INNER'
set -euo pipefail
FILES="$1"; DIRS="$2"; CHUNKS="$3"
W=/work
mkdir -p "$W/origin" "$W/out"

t0() { date +%s.%N; }
rate() { # rate <label> <start> <end> <count>
  awk -v l="$1" -v s="$2" -v e="$3" -v n="$4" \
    'BEGIN{d=e-s; printf "%-30s %8.2fs  %9.1f files/s  %8.0f us/file\n", l, d, n/d, d*1e6/n}'
}

# ---------------------------------------------------------------- corpus
# One corpus, split into CHUNKS tarballs over disjoint directory sets, so
# each chunk can be extracted and timed on its own.
echo "== generating a $FILES-file / $DIRS-dir corpus on tmpfs =="
per=$(( FILES / DIRS )); [ "$per" -lt 1 ] && per=1
dpc=$(( (DIRS + CHUNKS - 1) / CHUNKS ))
for c in $(seq 0 $((CHUNKS - 1))); do
  lo=$(( c * dpc )); hi=$(( lo + dpc - 1 )); [ "$hi" -ge "$DIRS" ] && hi=$((DIRS - 1))
  [ "$lo" -gt "$hi" ] && continue
  for d in $(seq "$lo" "$hi"); do
    dir="$W/src/c$c/tree/g$((d / 64))/d$d"
    mkdir -p "$dir"
    for f in $(seq 0 $((per - 1))); do
      printf 'file %d %d\n%*s' "$d" "$f" 900 '' > "$dir/f$f.c"
      # Every fourth file also appears under a second name. Real archives
      # carry hardlink entries, and they are the entries a frontend is
      # most likely to get wrong -- so the corpus contains them, and the
      # extraction below is checked for the failures they used to cause.
      [ $(( f % 4 )) -eq 0 ] && ln "$dir/f$f.c" "$dir/f$f.link.c"
    done
  done
  tar -C "$W/src/c$c" -cf "$W/chunk$c.tar" tree
done
NFILES=$(find "$W/src" -type f | wc -l)
PERCHUNK=$(find "$W/src/c0" -type f | wc -l)
NLINKS=$(find "$W/src" -name '*.link.c' | wc -l)
echo "corpus: $NFILES files ($NLINKS of them hard links) in $CHUNKS chunks of ~$PERCHUNK"
rm -rf "$W/src"

# untar_chunks <label> <dest-root>: extract every chunk into its own
# subdirectory, timing each, then report the aggregate. tar's stderr is
# kept per label: an extraction that "succeeds" while refusing entries is
# the failure mode this benchmark has actually seen.
untar_chunks() {
  local label="$1" root="$2" c S E TS TE errs="$W/out/untar-$1.err"
  : > "$errs"
  TS=$(t0)
  for c in $(seq 0 $((CHUNKS - 1))); do
    [ -f "$W/chunk$c.tar" ] || continue
    mkdir -p "$root/c$c"
    S=$(t0); tar -C "$root/c$c" -xf "$W/chunk$c.tar" 2>>"$errs" || true; E=$(t0)
    rate "  $label chunk $c" "$S" "$E" "$PERCHUNK"
  done
  TE=$(t0)
  rate "$label TOTAL" "$TS" "$TE" "$NFILES"
  local n
  n=$(grep -c . "$errs" || true)
  if [ "$n" != 0 ]; then
    echo "  $label: $n tar failures:"
    sort "$errs" | uniq -c | sort -rn | head -5 | sed 's/^/    /'
  fi
}

echo
echo "== layer 1: bare tmpfs (floor) =="
mkdir -p "$W/tmpfsdst"
untar_chunks "tmpfs" "$W/tmpfsdst"
rm -rf "$W/tmpfsdst"

echo
echo "== starting fakeorigin (loopback, zero latency) =="
/stage/fakeorigin -listen 127.0.0.1:18999 -root "$W/origin" &
ORIGIN_PID=$!
for _ in $(seq 50); do curl -fsS http://127.0.0.1:18999/ >/dev/null 2>&1 && break; sleep 0.1; done
PREFIX="http://127.0.0.1:18999/vol"

echo "== creating the v2 volume =="
/stage/pelfs shell --state-dir "$W/state" "$PREFIX" -- true > "$W/out/create.log" 2>&1

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# ------------------------------------------------------------ FUSE layer
if [ "${SKIP_FUSE:-0}" != "1" ]; then
echo
echo "== FUSE backend (rawfuse, inode-keyed) =="
mkdir -p "$W/fmnt"
cp -a "$W/state" "$W/statef"
/stage/pelfs mount-gen --rw --no-lease --no-seal --snapshot-interval 0 \
  --state-dir "$W/statef" "$PREFIX" "$W/fmnt" > "$W/out/fuse.log" 2>&1 &
FUSE_PID=$!
for _ in $(seq 300); do mountpoint -q "$W/fmnt" && break; sleep 0.1; done
mountpoint -q "$W/fmnt" || { echo "fuse mount did not come up"; cat "$W/out/fuse.log"; exit 1; }
C0=$(cpu_ticks "$FUSE_PID")
untar_chunks "fuse" "$W/fmnt"
C1=$(cpu_ticks "$FUSE_PID")
awk -v c0="$C0" -v c1="$C1" -v hz="$(getconf CLK_TCK)" -v n="$NFILES" \
  'BEGIN{printf "%-30s %8.2fs  %9.0f us/file of CPU\n", "  fuse server CPU", (c1-c0)/hz, (c1-c0)/hz*1e6/n}'
fusermount3 -u "$W/fmnt" 2>/dev/null || umount "$W/fmnt" || true
kill "$FUSE_PID" 2>/dev/null || true
wait "$FUSE_PID" 2>/dev/null || true
fi

# ------------------------------------------------------------- NFS layer
echo
echo "== NFS backend (vfsbilly + go-nfs, path-keyed) =="
mkdir -p "$W/nmnt"
cp -a "$W/state" "$W/staten"
/stage/pelfs mount-gen --rw --no-lease --no-seal --snapshot-interval 0 --backend nfs \
  --state-dir "$W/staten" "$PREFIX" "$W/nmnt" > "$W/out/nfs.log" 2>&1 &
NFS_PID=$!
up=0
for _ in $(seq 300); do
  grep -q " $W/nmnt " /proc/mounts && { up=1; break; }
  kill -0 "$NFS_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$up" = 1 ] || { echo "nfs mount did not come up"; cat "$W/out/nfs.log"; kill "$NFS_PID" 2>/dev/null; exit 1; }

# Per-operation RPC counts come straight from the kernel client, which is
# the only source that cannot be argued with about what was actually sent.
mountstats() { awk -v mp="$W/nmnt" '
  $1=="device" { inmnt = ($5 == mp) }
  inmnt && $1 ~ /^(NULL|GETATTR|SETATTR|LOOKUP|ACCESS|READLINK|READ|WRITE|CREATE|MKDIR|SYMLINK|MKNOD|REMOVE|RMDIR|RENAME|LINK|READDIR|READDIRPLUS|FSSTAT|FSINFO|PATHCONF|COMMIT):$/ {
    printf "%s %s\n", substr($1,1,length($1)-1), $2 }' /proc/self/mountstats; }
mountstats > "$W/out/ms.before"

( /stage/pelfs ctl "$W/staten" pprof 'profile?seconds=45' -o "$W/out/nfs-cpu.pprof" \
    > "$W/out/pprof.log" 2>&1 || true ) &
PPROF_PID=$!

C0=$(cpu_ticks "$NFS_PID")
untar_chunks "nfs" "$W/nmnt"
C1=$(cpu_ticks "$NFS_PID")
awk -v c0="$C0" -v c1="$C1" -v hz="$(getconf CLK_TCK)" -v n="$NFILES" \
  'BEGIN{printf "%-30s %8.2fs  %9.0f us/file of CPU\n", "  nfs server CPU", (c1-c0)/hz, (c1-c0)/hz*1e6/n}'

mountstats > "$W/out/ms.after"
echo
echo "== NFS RPCs per created file =="
join "$W/out/ms.before" "$W/out/ms.after" | awk -v n="$NFILES" '
  { d = $3 - $2; if (d > 0) { tot += d; printf "  %-14s %8d  %6.2f/file\n", $1, d, d/n } }
  END { printf "  %-14s %8d  %6.2f/file\n", "TOTAL", tot, tot/n }' | sort -k2 -rn

wait "$PPROF_PID" 2>/dev/null || true

# Hard links are the entries the NFS frontend used to refuse outright, so
# the extraction is a gate and not just a stopwatch: an untar that reports
# any failure at all has not created the tree it was asked to.
echo
echo "== hard links through the NFS mount =="
NERR=$(grep -c . "$W/out/untar-nfs.err" || true)
[ "$NERR" = 0 ] || { echo "UNTAR FAILURES ($NERR):"; head -5 "$W/out/untar-nfs.err"; exit 1; }
SAMPLE=$(find "$W/nmnt" -name '*.link.c' -print -quit)
[ -n "$SAMPLE" ] || { echo "no hard link was extracted"; exit 1; }
ORIG="${SAMPLE%.link.c}.c"
LN=$(stat -c %h "$SAMPLE")
[ "$(stat -c %i "$SAMPLE")" = "$(stat -c %i "$ORIG")" ] || {
  echo "$SAMPLE and $ORIG are separate inodes, not a hard link"; exit 1; }
[ "$LN" = 2 ] || { echo "$SAMPLE has nlink $LN, want 2"; exit 1; }
echo "$NLINKS hard links extracted, no failures; a sample pair shares one inode with nlink 2"

# rmdir of a non-empty directory used to reach the client as EIO, because
# no handler answered NFS3ERR_NOTEMPTY. Anything that reads the errno --
# `rm -r` deciding whether to recurse, a build system cleaning a tree --
# needs the real one.
mkdir -p "$W/nmnt/notempty" && : > "$W/nmnt/notempty/keep"
RMERR=$(rmdir "$W/nmnt/notempty" 2>&1 || true)
case "$RMERR" in
  *"not empty"*) echo "rmdir of a non-empty directory: $RMERR" ;;
  *) echo "rmdir of a non-empty directory reported: ${RMERR:-success}, want ENOTEMPTY"; exit 1 ;;
esac
rm -rf "$W/nmnt/notempty"

# A throughput number is worthless if the bytes are wrong, and the
# resolution caches this benchmark exists to measure are exactly the kind
# of thing that returns the wrong file quickly. Compare the whole tree
# through the live mount, then again after sealing and remounting, which
# is the only check that what was published matches what was written.
echo
echo "== integrity: the tree read back through the mount =="
mkdir -p "$W/ref"
for c in $(seq 0 $((CHUNKS - 1))); do
  [ -f "$W/chunk$c.tar" ] || continue
  mkdir -p "$W/ref/c$c"; tar -C "$W/ref/c$c" -xf "$W/chunk$c.tar"
done
if diff -r "$W/ref" "$W/nmnt" > "$W/out/diff-live.txt" 2>&1; then
  echo "live mount: $NFILES files byte-exact"
else
  echo "LIVE MOUNT MISMATCH:"; head -20 "$W/out/diff-live.txt"; exit 1
fi

umount "$W/nmnt" 2>/dev/null || umount -l "$W/nmnt" || true
kill "$NFS_PID" 2>/dev/null || true
wait "$NFS_PID" 2>/dev/null || true

echo "== integrity: sealing and reading the published generation back =="
S=$(t0)
/stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 --backend nfs \
  --state-dir "$W/staten" "$PREFIX" "$W/nmnt" -- true >> "$W/out/nfs.log" 2>&1
E=$(t0)
rate "seal + publish" "$S" "$E" "$NFILES"
mkdir -p "$W/ro"
if /stage/pelfs mount-gen --state-dir "$W/statero" "$PREFIX" "$W/ro" -- \
     diff -r "$W/ref" "$W/ro" > "$W/out/diff-sealed.txt" 2>&1; then
  echo "sealed generation: $NFILES files byte-exact"
else
  echo "SEALED GENERATION MISMATCH:"; head -20 "$W/out/diff-sealed.txt"; exit 1
fi

kill "$ORIGIN_PID" 2>/dev/null || true
cp -a "$W/out/." /out/ 2>/dev/null || true
INNER

echo "== running the NFS-vs-FUSE metadata benchmark on a real Linux kernel =="
docker run --rm \
  --privileged \
  --network none \
  -v "$STAGE":/stage:ro \
  -v "$OUT":/out \
  --tmpfs /work:rw,size=4g,exec \
  -e TMPDIR=/work \
  -e SKIP_FUSE="${SKIP_FUSE:-0}" \
  -e PELFS_NFS_NO_DESCENT_CACHE="${PELFS_NFS_NO_DESCENT_CACHE:-}" \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/bench.sh "$FILES" "$DIRS" "$CHUNKS"

echo
echo "profiles and logs in $OUT"
