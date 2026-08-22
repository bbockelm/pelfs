#!/usr/bin/env bash
# The big-tree gate: an untar of tens of thousands of small files through
# BOTH mount frontends, verified byte-for-byte live, then sealed,
# published, cold-remounted, checked, collected, and done again on top of
# itself as a second generation.
#
# This started life as a stopwatch and is now a pass/fail gate. It still
# prints every number it ever printed -- that is the point of running it by
# hand -- but the numbers it measures now have bounds, so a regression
# fails the job instead of leaving a slower line in a log nobody reads.
# What it gates:
#
#   * both frontends produce the tree that was asked for, live (diff -r)
#   * hard links survive as hard links, through both frontends
#   * the untar rate does not DECAY as the tree grows (per-chunk bound)
#   * the NFS frontend's RPCs per created file stay bounded
#   * a seal publishes a generation a COLD mount -- fresh state dir, empty
#     cache -- reads back byte-exact
#   * fsck --deep calls that generation consistent and gc finds nothing
#     unreferenced
#   * a SECOND generation on top (adds, a modify, a delete) does the same
#
# The NFS backend is not a curiosity: it is the only mount a macOS box
# without macFUSE can get (`resolveBackend` picks it there), so it is the
# path the project owner actually runs. Everything runs on a real Linux
# kernel in a container: macOS denies the shell access to its own NFS/FUSE
# mounts, and the repo forbids mounting anywhere near $HOME. The Linux NFS
# client is NOT the macOS one, so the absolute macOS numbers do not
# transfer -- but server-side cost per RPC and RPC count per file do, and
# those are what this measures.
#
# The untar is split into equal chunks that are timed separately. A rate
# that decays chunk over chunk is the signature of a per-op cost that
# scales with how much has already been written, which a single aggregate
# rate hides completely -- so that is the shape the bound is placed on,
# not the aggregate.
#
# Usage: scripts/bench-untar-nfs-docker.sh [files] [dirs] [chunks]
#
# Measured 2026-08-19 at 50000 2500 4 (62,500 files with the hard links),
# Docker on an M-series Mac, ~3.5 minutes end to end:
#
#   FUSE untar      34.1s   1835 files/s   decay 0.97x
#   NFS untar       74.6s    837 files/s   decay 1.46x   5.41 RPCs/file
#   seal + publish   2.7s
#   cold remount + whole-tree diff        11.5s
#   fsck --deep      0.5s
#
# The NFS decay figure is the one with the least headroom against its
# bound, and it is real rather than noise: the last chunk lands on a tree
# that already holds 47,000 files. If it starts failing, look at the write
# path before raising the bound.
#
# Knobs (all optional):
#   SKIP_FUSE=1                 NFS leg only
#   PELFS_MAX_DECAY=2.0         first-chunk / last-chunk rate ratio bound
#   PELFS_MAX_RPC_PER_FILE=12   NFS RPCs per created file bound (measured 5.41)
#   PELFS_GATE_TIMEOUT=2700     hard wall-clock cap, seconds (0 disables)
#   PELFS_BENCH_PPROF=45        also capture an N-second CPU profile
#   PELFS_BENCH_OUT=<dir>       keep profiles and logs here
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
FILES="${1:-8000}"
DIRS="${2:-400}"
CHUNKS="${3:-4}"
STAGE="$(mktemp -d)"
OUT="${PELFS_BENCH_OUT:-$STAGE/out}"
mkdir -p "$OUT"
trap 'rm -rf "$STAGE"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

IMAGE_TAG="pelfs-test-runner:1"
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

# Logs and profiles are written to tmpfs -- a bind mount would put the
# rate files this gate MEASURES on the host filesystem -- so they have to
# be copied out to reach the caller. Copy on EXIT rather than only at the
# end: a gate that fails is the one whose logs somebody wants, and until
# this trap existed the single copy at the bottom was unreachable from
# every failure path. CI's artifact upload then found an empty directory,
# so a failure reproducible ONLY on a shared runner left nothing behind
# to read. A SIGKILL from the outer timeout still loses them; the
# stall sentence on stderr is what covers that case.
trap 'cp -a "$W/out/." /out/ 2>/dev/null || true' EXIT

MAX_DECAY="${PELFS_MAX_DECAY:-2.0}"
MAX_RPC_PER_FILE="${PELFS_MAX_RPC_PER_FILE:-12}"

# Failures are collected rather than thrown, so one run reports every
# problem it found instead of the first. Anything that makes the REST of
# the run meaningless still exits on the spot.
FAILED=0
fail() { echo "GATE FAILURE: $*" >&2; FAILED=1; }

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

# The reference tree is built ONCE, from the same tarballs, and every
# frontend is compared against it -- live and after publishing. A
# throughput number is worthless if the bytes are wrong, and the
# resolution caches this benchmark exists to measure are exactly the kind
# of thing that returns the wrong file quickly.
mkdir -p "$W/ref"
for c in $(seq 0 $((CHUNKS - 1))); do
  [ -f "$W/chunk$c.tar" ] || continue
  mkdir -p "$W/ref/c$c"; tar -C "$W/ref/c$c" -xf "$W/chunk$c.tar"
done

# untar_chunks <label> <dest-root>: extract every chunk into its own
# subdirectory, timing each, then report the aggregate. tar's stderr is
# kept per label: an extraction that "succeeds" while refusing entries is
# the failure mode this benchmark has actually seen. Per-chunk rates are
# written to out/rate-<label> for the decay bound.
untar_chunks() {
  local label="$1" root="$2" c S E TS TE errs="$W/out/untar-$1.err" rates="$W/out/rate-$1"
  : > "$errs"; : > "$rates"
  TS=$(t0)
  for c in $(seq 0 $((CHUNKS - 1))); do
    [ -f "$W/chunk$c.tar" ] || continue
    mkdir -p "$root/c$c"
    S=$(t0); tar -C "$root/c$c" -xf "$W/chunk$c.tar" 2>>"$errs" || true; E=$(t0)
    rate "  $label chunk $c" "$S" "$E" "$PERCHUNK"
    awk -v s="$S" -v e="$E" -v n="$PERCHUNK" 'BEGIN{printf "%.3f\n", n/(e-s)}' >> "$rates"
  done
  TE=$(t0)
  rate "$label TOTAL" "$TS" "$TE" "$NFILES"
  local n
  n=$(grep -c . "$errs" || true)
  if [ "$n" != 0 ]; then
    echo "  $label: $n tar failures:"
    sort "$errs" | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    fail "$label: tar refused $n entries; the tree it was asked to create does not exist"
  fi
}

# check_decay <label>: the first chunk lands on an empty tree, the last on
# a tree with everything else already in it. If per-op cost scales with
# what has already been written, THAT is where it shows, and no aggregate
# rate will ever show it.
check_decay() {
  local label="$1" rates="$W/out/rate-$1" first last ratio
  [ -s "$rates" ] || return 0
  first=$(head -1 "$rates"); last=$(tail -1 "$rates")
  ratio=$(awk -v f="$first" -v l="$last" 'BEGIN{ if (l <= 0) print "inf"; else printf "%.2f", f/l }')
  printf "%-30s %8s  (first %.0f files/s, last %.0f files/s, bound %sx)\n" \
    "  $label rate decay" "${ratio}x" "$first" "$last" "$MAX_DECAY"
  if [ "$ratio" = inf ] || awk -v r="$ratio" -v m="$MAX_DECAY" 'BEGIN{ exit !(r > m) }'; then
    fail "$label: untar rate decayed ${ratio}x across the run (bound ${MAX_DECAY}x) -- per-op cost is scaling with tree size"
  fi
  return 0
}

# check_links <label> <root>: hard links are the entries the NFS frontend
# used to refuse outright, and the entries a published generation could
# most plausibly flatten into two independent copies.
check_links() {
  local label="$1" root="$2" sample orig ln
  sample=$(find "$root" -name '*.link.c' -print -quit)
  [ -n "$sample" ] || { fail "$label: no hard link was extracted at all"; return 0; }
  orig="${sample%.link.c}.c"
  [ -e "$orig" ] || { fail "$label: $sample exists but its partner $orig does not"; return 0; }
  if [ "$(stat -c %i "$sample")" != "$(stat -c %i "$orig")" ]; then
    fail "$label: $sample and $orig are separate inodes, not a hard link"
    return 0
  fi
  ln=$(stat -c %h "$sample")
  [ "$ln" = 2 ] || { fail "$label: $sample has nlink $ln, want 2"; return 0; }
  echo "  $label: hard links intact (a sample pair shares one inode, nlink 2)"
}

# check_tree <label> <mountroot> <reference>: the whole tree, byte for
# byte. This is the check that makes every number above mean something.
check_tree() {
  local label="$1" root="$2" ref="$3" log="$W/out/diff-$1.txt"
  if diff -r "$ref" "$root" > "$log" 2>&1; then
    echo "  $label: $(find "$ref" -type f | wc -l | tr -d ' ') files byte-exact"
  else
    echo "  $label MISMATCH:"; head -20 "$log"
    fail "$label: the tree read back does not match what was written"
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
check_decay "fuse"
# The FUSE leg is a gate too, not just the other half of a comparison: it
# is the frontend CI runs on Linux, and it used to be timed and then
# thrown away unverified.
echo "  == integrity: the tree read back through the live FUSE mount =="
check_links "fuse live" "$W/fmnt"
check_tree "fuse-live" "$W/fmnt" "$W/ref"
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

# A CPU profile is opt-in. It used to be started unconditionally asking
# for 45 seconds and then waited on, so every run -- including a small one
# that finished in eight seconds -- stalled until the profiler's clock ran
# out. A gate does not get to spend 45 seconds sleeping.
PPROF_PID=
if [ -n "${PELFS_BENCH_PPROF:-}" ]; then
  ( /stage/pelfs ctl "$W/staten" pprof "profile?seconds=${PELFS_BENCH_PPROF}" \
      -o "$W/out/nfs-cpu.pprof" > "$W/out/pprof.log" 2>&1 || true ) &
  PPROF_PID=$!
fi

C0=$(cpu_ticks "$NFS_PID")
untar_chunks "nfs" "$W/nmnt"
C1=$(cpu_ticks "$NFS_PID")
awk -v c0="$C0" -v c1="$C1" -v hz="$(getconf CLK_TCK)" -v n="$NFILES" \
  'BEGIN{printf "%-30s %8.2fs  %9.0f us/file of CPU\n", "  nfs server CPU", (c1-c0)/hz, (c1-c0)/hz*1e6/n}'
check_decay "nfs"

mountstats > "$W/out/ms.after"
echo
echo "== NFS RPCs per created file =="
join "$W/out/ms.before" "$W/out/ms.after" | awk -v n="$NFILES" -v outf="$W/out/rpc-per-file" '
  { d = $3 - $2; if (d > 0) { tot += d; printf "  %-14s %8d  %6.2f/file\n", $1, d, d/n } }
  END { printf "  %-14s %8d  %6.2f/file\n", "TOTAL", tot, tot/n
        print tot/n > outf }' | sort -k2 -rn
RPCF=$(cat "$W/out/rpc-per-file" 2>/dev/null || echo 0)
printf "%-30s %8.2f  (bound %s)\n" "  nfs RPCs/file" "$RPCF" "$MAX_RPC_PER_FILE"
if awk -v r="$RPCF" -v m="$MAX_RPC_PER_FILE" 'BEGIN{ exit !(r > m) }'; then
  fail "NFS sent $RPCF RPCs per created file (bound $MAX_RPC_PER_FILE) -- the client is being made to ask more than it should"
fi

if [ -n "$PPROF_PID" ]; then wait "$PPROF_PID" 2>/dev/null || true; fi

echo
echo "== NFS frontend semantics =="
check_links "nfs live" "$W/nmnt"

# rmdir of a non-empty directory used to reach the client as EIO, because
# no handler answered NFS3ERR_NOTEMPTY. Anything that reads the errno --
# `rm -r` deciding whether to recurse, a build system cleaning a tree --
# needs the real one.
mkdir -p "$W/nmnt/notempty" && : > "$W/nmnt/notempty/keep"
RMERR=$(rmdir "$W/nmnt/notempty" 2>&1 || true)
case "$RMERR" in
  *"not empty"*) echo "  rmdir of a non-empty directory: $RMERR" ;;
  *) fail "rmdir of a non-empty directory reported: ${RMERR:-success}, want ENOTEMPTY" ;;
esac
rm -rf "$W/nmnt/notempty"

echo
echo "== integrity: the tree read back through the live NFS mount =="
check_tree "nfs-live" "$W/nmnt" "$W/ref"

umount "$W/nmnt" 2>/dev/null || umount -l "$W/nmnt" || true
kill "$NFS_PID" 2>/dev/null || true
wait "$NFS_PID" 2>/dev/null || true

# --------------------------------------------------- generation 1: seal
# The session above ran --no-seal, so its overlay is still sitting in the
# state dir. Remounting the SAME state dir without --no-seal picks it up
# and publishes it on exit, which is the resume path a killed session
# takes.
echo
echo "== generation 1: seal and publish =="
S=$(t0)
/stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 --backend nfs \
  --state-dir "$W/staten" "$PREFIX" "$W/nmnt" -- true >> "$W/out/nfs.log" 2>&1
E=$(t0)
rate "seal + publish" "$S" "$E" "$NFILES"

# cold_check <label> <state-dir> <reference>: mount the published
# generation with a state dir that has never existed before -- no overlay,
# no gencache, nothing warm -- and diff the whole tree. This is the only
# check that what was PUBLISHED matches what was written, as opposed to
# what some local cache still remembers.
cold_check() {
  local label="$1" state="$2" ref="$3" mnt="$W/ro-$1"
  mkdir -p "$mnt"
  rm -rf "$state"
  S=$(t0)
  if /stage/pelfs mount-gen --state-dir "$state" "$PREFIX" "$mnt" -- \
       diff -r "$ref" "$mnt" > "$W/out/diff-$1.txt" 2>&1; then
    E=$(t0)
    rate "cold remount + diff ($label)" "$S" "$E" "$NFILES"
    echo "  $label: $(find "$ref" -type f | wc -l | tr -d ' ') files byte-exact from a cold state dir"
  else
    echo "  $label MISMATCH:"; head -20 "$W/out/diff-$1.txt"
    fail "$label: the published generation does not match what was written"
  fi
}
cold_check "gen1" "$W/state-cold1" "$W/ref"

# ------------------------------------------------- generation 1: fsck+gc
echo
echo "== generation 1: fsck --deep and gc =="
S=$(t0)
if /stage/pelfs fsck --deep --state-dir "$W/state-fsck" "$PREFIX" > "$W/out/fsck1.log" 2>&1; then
  grep -q "generation is consistent" "$W/out/fsck1.log" \
    || fail "fsck --deep exited 0 without reporting consistency:$(sed 's/^/\n    /' "$W/out/fsck1.log")"
else
  sed 's/^/    /' "$W/out/fsck1.log"
  fail "fsck --deep rejected the generation this run just published"
fi
E=$(t0); rate "fsck --deep (gen 1)" "$S" "$E" "$NFILES"

if /stage/pelfs gc --state-dir "$W/state-gc" "$PREFIX" > "$W/out/gc1.log" 2>&1; then
  grep -Eq "unreferenced: +0 " "$W/out/gc1.log" \
    || { sed 's/^/    /' "$W/out/gc1.log"
         fail "gc found unreferenced objects on a volume that has only ever been written to"; }
  echo "  gc: nothing unreferenced, as expected on a freshly published volume"
else
  sed 's/^/    /' "$W/out/gc1.log"
  fail "gc failed against the generation this run just published"
fi

# ------------------------------------------------------ generation 2
# A second generation ON TOP of the first, with all three kinds of change,
# because a format that publishes one generation correctly and then loses
# the plot on the second is a format that works exactly once. The
# reference tree gets the same edits, so the cold diff below covers the
# adds, the modify AND the delete -- a delete that failed to take would
# show up as an extra file on the mount side.
echo
echo "== generation 2: adds, a modify and a delete on top of generation 1 =="
mkdir -p "$W/gen2src/added"
for i in $(seq 0 199); do
  printf 'second generation %d\n%*s' "$i" 500 '' > "$W/gen2src/added/g$i.c"
done
# -print -quit, not `| head -1`: with pipefail set, head closing the pipe
# after one line makes find die of SIGPIPE and takes the whole run with
# it. That is invisible at 10k -- find finishes inside the pipe buffer --
# and fatal at 50k, which is exactly the kind of bug a gate that only ever
# ran small would ship.
VICTIM=$(cd "$W/ref" && find c0 -name 'f1.c' -print -quit)
[ -n "$VICTIM" ] || { echo "corpus has no f1.c to modify"; exit 1; }
DOOMED=$(cd "$W/ref" && find c0 -name 'f2.c' -print -quit)
[ -n "$DOOMED" ] || { echo "corpus has no f2.c to delete"; exit 1; }

# One script, applied to the reference tree and then to the mount, so the
# two cannot drift apart by editing one and forgetting the other.
cat > "$W/apply-gen2.sh" <<GEN2
set -e
root="\$1"
cp -a "$W/gen2src/added" "\$root/added"
printf 'rewritten in generation 2\n' > "\$root/$VICTIM"
rm -f "\$root/$DOOMED"
GEN2
bash "$W/apply-gen2.sh" "$W/ref"

S=$(t0)
mkdir -p "$W/gen2mnt"
# The same state dir as generation 1, because that is where the volume
# SIGNING KEY lives: a fresh state dir mounts and writes happily and then
# refuses to seal, having nothing to sign with. (Which is the right
# behaviour, and is what a fresh dir gets in cold_check, where the mount
# is read-only and no key is needed.)
if ! /stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 --backend nfs \
     --state-dir "$W/staten" "$PREFIX" "$W/gen2mnt" -- \
     bash "$W/apply-gen2.sh" "$W/gen2mnt" > "$W/out/gen2.log" 2>&1; then
  sed 's/^/    /' "$W/out/gen2.log"
  fail "generation 2 session failed"
fi
E=$(t0)
rate "gen 2 write + seal" "$S" "$E" 201
grep -hE "sealed generation" "$W/out/gen2.log" | sed 's/^/    /' || true

cold_check "gen2" "$W/state-cold2" "$W/ref"

echo
echo "== generation 2: fsck --deep =="
if /stage/pelfs fsck --deep --state-dir "$W/state-fsck2" "$PREFIX" > "$W/out/fsck2.log" 2>&1; then
  grep -q "generation is consistent" "$W/out/fsck2.log" \
    || fail "fsck --deep exited 0 on generation 2 without reporting consistency"
  echo "  fsck --deep: generation 2 is consistent"
else
  sed 's/^/    /' "$W/out/fsck2.log"
  fail "fsck --deep rejected generation 2"
fi

kill "$ORIGIN_PID" 2>/dev/null || true
cp -a "$W/out/." /out/ 2>/dev/null || true

echo
if [ "$FAILED" != 0 ]; then
  echo "== BIG-TREE GATE FAILED (see GATE FAILURE lines above) =="
  exit 1
fi
echo "== big-tree gate passed: $NFILES files through both frontends, two generations =="
INNER

# A hard wall-clock cap. The failure mode this whole punchlist is hunting
# is a STALL, and a stalled container is indistinguishable from a slow one
# until something says otherwise -- so something does. `timeout` is
# coreutils; a host without it (macOS by default) just runs uncapped.
GATE_TIMEOUT="${PELFS_GATE_TIMEOUT:-2700}"
RUNNER=()
if [ "$GATE_TIMEOUT" != 0 ] && command -v timeout >/dev/null 2>&1; then
  RUNNER=(timeout --signal=KILL "$GATE_TIMEOUT")
fi

echo "== running the big-tree gate on a real Linux kernel =="
rc=0
"${RUNNER[@]}" docker run --rm \
  --privileged \
  --network none \
  -v "$STAGE":/stage:ro \
  -v "$OUT":/out \
  --tmpfs /work:rw,size=8g,exec \
  -e TMPDIR=/work \
  -e SKIP_FUSE="${SKIP_FUSE:-0}" \
  -e PELFS_MAX_DECAY="${PELFS_MAX_DECAY:-2.0}" \
  -e PELFS_MAX_RPC_PER_FILE="${PELFS_MAX_RPC_PER_FILE:-12}" \
  -e PELFS_BENCH_PPROF="${PELFS_BENCH_PPROF:-}" \
  -e PELFS_NFS_NO_DESCENT_CACHE="${PELFS_NFS_NO_DESCENT_CACHE:-}" \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/bench.sh "$FILES" "$DIRS" "$CHUNKS" || rc=$?
if [ "$rc" = 137 ] || [ "$rc" = 124 ]; then
  echo "the gate was killed after ${GATE_TIMEOUT}s: it stalled, or it needs a bigger budget" >&2
  exit 1
fi

echo
echo "profiles and logs in $OUT"
exit $rc
