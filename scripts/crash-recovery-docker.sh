#!/usr/bin/env bash
# The crash gate: SIGKILL a read-write mount while it is still flushing,
# remount the same state dir, and hold the recovery to its contract.
#
# This is the first test in the repo that PRODUCES a crash. The memtable's
# own recovery tests construct post-crash state -- they truncate a ring
# file, tear a record tail, write the bytes a half-finished rotation would
# have left -- which checks the recovery reader against a model of what a
# crash does. It does not check that a real kill -9 of a real mount, at a
# moment the process chose rather than the test, leaves state that model
# describes. The write path is default-on, so that gap is the one worth
# closing first.
#
# The contract, from internal/memtable/recover.go and the caller at
# cmd/pelfs/mountgen.go: "Recovery is allowed to lose content -- a mount
# is tied to a job, and a crashed job usually discards its state -- but it
# is never allowed to lose it QUIETLY." So this gate does not assert that
# nothing is lost. It asserts:
#
#   1. the remount says out loud that a recovery happened
#   2. content that was already PUBLISHED reads back byte-exact
#   3. every file that survived is byte-exact -- a lost write may leave
#      the file absent, and must not leave it present and wrong (silently
#      short, or zero-filled, which is the failure a user cannot detect)
#   4. anything genuinely lost is NAMED, with inodes and byte ranges
#   5. fsck --deep passes on the generation the recovered session seals
#
# Docker only: this kills a real FUSE mount on a real kernel, which macOS
# cannot host honestly and which has no business happening on a
# developer's machine.
#
# Usage: scripts/crash-recovery-docker.sh [durable-files] [crash-files]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
DURABLE="${1:-800}"
CRASH="${2:-1500}"
STAGE="$(mktemp -d)"
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

cat > "$STAGE/crash.sh" <<'INNER'
set -euo pipefail
DURABLE="$1"; CRASH="$2"
W=/work
mkdir -p "$W/origin" "$W/out"

FAILED=0
fail() { echo "GATE FAILURE: $*" >&2; FAILED=1; }
ok()   { echo "  ok: $*"; }

unmount_at() {
  fusermount3 -u "$1" 2>/dev/null && return 0
  fusermount3 -uz "$1" 2>/dev/null && return 0
  umount "$1" 2>/dev/null || umount -l "$1" 2>/dev/null || true
}

echo "== corpus =="
# Unique bytes per file, so nothing dedups away and the packer has real
# work to do -- a corpus of identical files would upload almost nothing
# and never build the backlog this test needs.
#
# CRASH_BYTES is not a round number picked for looks. The memtable
# promotes an extent out of its ring and into a pack only once the extent
# has fallen memtable.DefaultPromotionDistance (64 MiB) behind the write
# head, so a session that writes less than that uploads NOTHING and dies
# with everything still in the ring -- which is a crash, but not the
# mid-FLUSH crash this gate is for. At 256 KiB a file, the default 1500
# files is 384 MiB: six promotion distances, so packing and uploading are
# both continuously in flight by the time the kill lands.
CRASH_BYTES=262144
mkdir -p "$W/durablesrc" "$W/crashsrc"
for i in $(seq 0 $((DURABLE - 1))); do
  { printf 'durable %d\n' "$i"; head -c 4096 /dev/urandom; } > "$W/durablesrc/d$i.dat"
done
for i in $(seq 0 $((CRASH - 1))); do
  { printf 'crash %d\n' "$i"; head -c "$CRASH_BYTES" /dev/urandom; } > "$W/crashsrc/c$i.dat"
done
echo "  $DURABLE durable files, $CRASH crash-phase files of $CRASH_BYTES bytes" \
     "($(( CRASH * CRASH_BYTES >> 20 )) MiB, vs a 64 MiB promotion distance)"

echo
echo "== starting fakeorigin (loopback, zero latency) =="
/stage/fakeorigin -listen 127.0.0.1:18999 -root "$W/origin" > "$W/out/origin.log" 2>&1 &
ORIGIN_PID=$!
for _ in $(seq 50); do curl -fsS http://127.0.0.1:18999/ >/dev/null 2>&1 && break; sleep 0.1; done
PREFIX="http://127.0.0.1:18999/vol"

/stage/pelfs shell --state-dir "$W/state" "$PREFIX" -- true > "$W/out/create.log" 2>&1

# ------------------------------------------------- session 1: durable
# A session that exits cleanly, so its content is in a PUBLISHED
# generation before anything is killed. This is the half the crash must
# not be able to touch, and making it a separate clean session is what
# makes that unambiguous -- no dependence on whether a checkpoint timer
# happened to fire.
echo
echo "== session 1: write and seal (this content is durable by construction) =="
mkdir -p "$W/mnt"
/stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 \
  --state-dir "$W/state" "$PREFIX" "$W/mnt" -- \
  cp -a "$W/durablesrc" "$W/mnt/durable" > "$W/out/s1.log" 2>&1
grep -hE "sealed generation" "$W/out/s1.log" | sed 's/^/    /'
grep -q "sealed generation" "$W/out/s1.log" || { echo "session 1 did not seal"; cat "$W/out/s1.log"; exit 1; }
BASE_OBJS=$(find "$W/origin" -type f | wc -l)
echo "  federation holds $BASE_OBJS objects after the clean seal"

# ------------------------------------------------- session 2: crash
# --snapshot-interval 0: no checkpoint will publish anything, so
# EVERYTHING this session writes is unsealed when it dies. That is the
# state recovery exists for.
echo
echo "== session 2: write hard, then SIGKILL mid-flush =="
/stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 \
  --state-dir "$W/state" "$PREFIX" "$W/mnt" > "$W/out/s2.log" 2>&1 &
MOUNT_PID=$!
for _ in $(seq 300); do mountpoint -q "$W/mnt" && break; sleep 0.1; done
mountpoint -q "$W/mnt" || { echo "crash-session mount did not come up"; cat "$W/out/s2.log"; exit 1; }

# The writer runs until it is killed. One file at a time, so the moment of
# the kill lands in the middle of a write rather than between two batches.
mkdir -p "$W/mnt/crashing"
( for i in $(seq 0 $((CRASH - 1))); do
    cp "$W/crashsrc/c$i.dat" "$W/mnt/crashing/c$i.dat" 2>/dev/null || exit 0
  done ) &
WRITER_PID=$!

# Wait for the mount to be genuinely mid-flush: new objects in the
# federation means the packer has cut packs and the uploader is sending
# them, and the writer is still going, so there is more behind them.
# (UploadBacklog itself is not reachable from outside a running mount --
# see C5 -- so this is the observable that stands in for it.)
flushing=0
for _ in $(seq 900); do
  now=$(find "$W/origin" -type f | wc -l)
  wrote=$(find "$W/mnt/crashing" -type f 2>/dev/null | wc -l)
  # Uploads have started AND the writer has not finished: that is a
  # backlog being worked, which is the state to interrupt. If the writer
  # has already exited there is still unflushed content, but the kill is
  # no longer landing mid-write, so insist on both.
  if [ "$now" -gt "$BASE_OBJS" ] && kill -0 "$WRITER_PID" 2>/dev/null; then
    flushing=1
    echo "  mid-flush: $((now - BASE_OBJS)) new objects uploaded, $wrote files written, writer still going"
    break
  fi
  kill -0 "$MOUNT_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$flushing" = 1 ] || {
  echo "never caught the session mid-flush: uploads $(find "$W/origin" -type f | wc -l)"
  echo "(base $BASE_OBJS), writer alive: $(kill -0 "$WRITER_PID" 2>/dev/null && echo yes || echo no)"
  tail -20 "$W/out/s2.log"; exit 1; }

WROTE_AT_KILL=$(find "$W/mnt/crashing" -type f 2>/dev/null | wc -l)
kill -9 "$MOUNT_PID"
kill -9 "$WRITER_PID" 2>/dev/null || true
wait "$MOUNT_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
echo "  SIGKILLed the mount with ~$WROTE_AT_KILL files written into it"
unmount_at "$W/mnt"

# The seal spool a kill -9 strands. The killed session ran with
# --snapshot-interval 0 precisely so that nothing it wrote was sealed, so
# it happens not to have been mid-seal -- which is the interesting case for
# scratch and the one the state directory must survive. It is staged here
# instead, named for the pid of the mount that has just been killed, which
# is exactly the name that mount's own seal would have given it. A second
# spool is named for THIS SHELL, which is running, and must be left alone:
# a sweep that cannot tell those two apart deletes a live seal's packs.
STRANDED="$W/state/publish-$MOUNT_PID-crashed"
LIVE_SPOOL="$W/state/publish-$$-running"
mkdir -p "$STRANDED" "$LIVE_SPOOL"
head -c $((8 * 1024 * 1024)) /dev/urandom > "$STRANDED/p-0001.pack"
head -c 1024 /dev/urandom > "$LIVE_SPOOL/p-0001.pack"
echo "  staged $(du -sh "$STRANDED" | cut -f1) of spool owned by the killed mount (pid $MOUNT_PID)"

# ------------------------------------------------- session 3: recover
echo
echo "== session 3: remount the same state dir =="
/stage/pelfs mount-gen --rw --no-lease --snapshot-interval 0 \
  --state-dir "$W/state" "$PREFIX" "$W/mnt" > "$W/out/s3.log" 2>&1 &
R_PID=$!
for _ in $(seq 300); do mountpoint -q "$W/mnt" && break; sleep 0.1; done
mountpoint -q "$W/mnt" || { echo "the remount did not come up after a crash"; cat "$W/out/s3.log"; exit 1; }

# 1. The recovery must SAY SO. Either form counts -- the WARN when
#    something was lost, the INFO when nothing was -- but silence does
#    not.
echo
echo "== 1. the recovery reports itself =="
LOUD=0
if grep -q "left content that could not be recovered" "$W/out/s3.log"; then
  LOUD=1; LOST=1
  echo "  recovery reported LOSS:"
  sed -n '/left content that could not be recovered/,/^$/p' "$W/out/s3.log" | head -20 | sed 's/^/    /'
elif grep -q "recovered .* extents from the previous session" "$W/out/s3.log"; then
  LOUD=1; LOST=0
  grep -h "recovered .* extents" "$W/out/s3.log" | sed 's/^/    /'
else
  LOST=0
  fail "the remount after a kill -9 said nothing about recovery; a session that silently picks up another session's unsealed state is the one thing the recovery contract forbids"
fi
[ "$LOUD" = 1 ] && ok "the recovery announced itself"

# 4. If content was lost, it must be NAMED -- inodes and byte ranges, not
#    a count. This is the difference between "lost" and "silently absent".
if [ "$LOST" = 1 ]; then
  echo
  echo "== 4. what was lost is named =="
  if grep -q "DATA LOST:" "$W/out/s3.log" && grep -qE "inode [0-9]+: bytes \[[0-9]+,[0-9]+\) are gone" "$W/out/s3.log"; then
    ok "loss is itemised by inode and byte range"
  else
    fail "recovery reported loss without naming the inodes and ranges it lost"
  fi
fi

# 2. The published half is untouchable. A crash in a later session that
#    could damage an already-sealed generation would be a format bug, not
#    a recovery one.
echo
echo "== 2. content that was durable reads back =="
if diff -r "$W/durablesrc" "$W/mnt/durable" > "$W/out/diff-durable.txt" 2>&1; then
  ok "all $DURABLE published files byte-exact after the crash"
else
  head -20 "$W/out/diff-durable.txt"
  fail "a crash damaged content that had already been published"
fi

# 3. The survivors must be RIGHT. This is the assertion that catches the
#    failure a user cannot see: a file that exists at its full length with
#    a hole of zeros where a lost extent used to be. Absence is allowed
#    here; wrongness is not.
echo
echo "== 3. every file that survived the crash is byte-exact, or honestly short =="
# The writer copies c0, c1, ... in order, so the highest-numbered file
# present is the one cp was in the middle of when the kill landed. That
# one is ALLOWED to be short: an interrupted copy leaves a short file on
# ext4 too, and calling that a pelfs bug would be calling POSIX a bug.
#
# What is not allowed is a hole. A file that comes back at some length
# must be a genuine PREFIX of what was written -- if a lost extent in the
# middle were papered over with zeros, the file would read at full length
# with wrong bytes inside it, and nothing a user can run would reveal it.
# So short files are compared over the bytes they do have, and any file
# that is wrong beyond that has to be one recovery NAMED as lost.
INFLIGHT=$(ls "$W/mnt/crashing" 2>/dev/null | sed -n 's/^c\([0-9]*\)\.dat$/\1/p' | sort -n | tail -1)
REPORTED_LOST=$(sed -n 's/.*DATA LOST: [0-9]* extents, [0-9]* bytes, across \([0-9]*\) files.*/\1/p' \
  "$W/out/s3.log" | head -1)
REPORTED_LOST="${REPORTED_LOST:-0}"

present=0; short=0; holed=0
for f in "$W/mnt/crashing"/*.dat; do
  [ -e "$f" ] || continue
  present=$((present + 1))
  src="$W/crashsrc/$(basename "$f")"
  have=$(stat -c %s "$f"); want=$(stat -c %s "$src")
  if [ "$have" = "$want" ]; then
    cmp -s "$f" "$src" && continue
    holed=$((holed + 1))
    [ "$holed" -le 5 ] && echo "    $(basename "$f"): full length, WRONG BYTES"
    continue
  fi
  # Short. Honest only if what is there is the head of what was written.
  if [ "$have" = 0 ] || cmp -s -n "$have" "$f" "$src"; then
    short=$((short + 1))
    idx=$(basename "$f" .dat); idx="${idx#c}"
    if [ "$idx" != "$INFLIGHT" ]; then
      echo "    $(basename "$f"): $have of $want bytes (a clean prefix, but not the in-flight file)"
    fi
  else
    holed=$((holed + 1))
    [ "$holed" -le 5 ] && echo "    $(basename "$f"): $have of $want bytes and NOT a prefix -- a hole, not a truncation"
  fi
done
echo "  $present files survived the kill; $short short, $holed corrupt"
echo "  (cp was in the middle of c$INFLIGHT; recovery named $REPORTED_LOST files as lost)"

if [ "$holed" != 0 ]; then
  fail "$holed surviving files read back at the wrong bytes -- content was lost WITHOUT being reported, which is the silent-loss the contract forbids"
fi
# One short file is the interrupted copy. More than that has to be
# matched by something recovery said it lost.
if [ "$short" -gt $((REPORTED_LOST + 1)) ]; then
  fail "$short files came back short, but recovery named only $REPORTED_LOST as lost (plus the one cp was writing) -- the rest were truncated silently"
else
  ok "no holes; short files are accounted for by the interrupted copy and the recovery report"
fi
# A recovery that dropped everything would pass the checks above
# vacuously, and would also be a recovery that does not work.
if [ "$present" = 0 ]; then
  fail "not one file survived a crash that had already uploaded objects; recovery recovered nothing"
fi

# 4b. The state directory is cleaned up after a crash. Everything a killed
#     session was spooling is unreferenced the moment it dies, and until
#     this sweep existed nothing ever collected it: a state directory
#     accumulated one seal's worth of packs per crash, forever.
echo
echo "== 4b. the mount reclaims the scratch the killed session stranded =="
for _ in $(seq 100); do [ -d "$STRANDED" ] || break; sleep 0.1; done
if [ -d "$STRANDED" ]; then
  ls -la "$W/state" | sed 's/^/    /'
  fail "the spool of the mount that was killed is still in the state directory after a remount"
else
  ok "the killed session's spool was reclaimed"
fi
if [ -d "$LIVE_SPOOL" ]; then
  ok "the spool of a process that is still running was left alone"
else
  fail "the sweep deleted the spool of a LIVE process; a concurrent seal would have lost its packs"
fi
grep -h "reclaimed .* of scratch" "$W/out/s3.log" | sed 's/^/    /' \
  || fail "the sweep reclaimed scratch without saying what it took"
# And nothing else claiming to be scratch survives, including whatever the
# kill really did leave behind rather than what the test staged.
rm -rf "$LIVE_SPOOL"
LEFT=$(find "$W/state" -maxdepth 1 \( -name 'publish-*' -o -name 'snapshot-*' -o -name 'repack*' \) -print)
[ -z "$LEFT" ] || {
  echo "$LEFT" | sed 's/^/    /'
  fail "scratch is still sitting in the state directory after the recovering mount swept it"
}
ok "no scratch of any family is left in the state directory"

# 5. And the volume must still be publishable and verifiable.
echo
echo "== 5. the recovered session seals, and fsck --deep passes =="
unmount_at "$W/mnt"
wait "$R_PID" 2>/dev/null || true
grep -hE "sealed generation" "$W/out/s3.log" | sed 's/^/    /' || true
grep -q "sealed generation" "$W/out/s3.log" \
  || fail "the recovered session could not seal what it recovered"

if /stage/pelfs fsck --deep --state-dir "$W/state-fsck" "$PREFIX" > "$W/out/fsck.log" 2>&1; then
  grep -q "generation is consistent" "$W/out/fsck.log" \
    || fail "fsck --deep exited 0 without reporting consistency"
  ok "fsck --deep: the generation sealed after a crash is consistent"
else
  sed 's/^/    /' "$W/out/fsck.log"
  fail "fsck --deep rejected the generation sealed after a crash"
fi

# The tree the recovered session published must match what is on the
# mount -- a cold reader must see what the recovering writer saw.
mkdir -p "$W/cold"
if /stage/pelfs mount-gen --state-dir "$W/state-cold" "$PREFIX" "$W/cold" -- \
     diff -r "$W/durablesrc" "$W/cold/durable" > "$W/out/diff-cold.txt" 2>&1; then
  ok "the durable tree is byte-exact through a cold mount of the sealed generation"
else
  head -20 "$W/out/diff-cold.txt"
  fail "the generation sealed after a crash does not serve the durable tree"
fi

kill "$ORIGIN_PID" 2>/dev/null || true
cp -a "$W/out/." /out/ 2>/dev/null || true

echo
if [ "$FAILED" != 0 ]; then
  echo "== CRASH GATE FAILED (see GATE FAILURE lines above) =="
  exit 1
fi
echo "== crash gate passed: kill -9 mid-flush, recovered loudly, nothing silently wrong =="
INNER

OUT="${PELFS_CRASH_OUT:-$STAGE/out}"
mkdir -p "$OUT"

GATE_TIMEOUT="${PELFS_GATE_TIMEOUT:-900}"
RUNNER=()
if [ "$GATE_TIMEOUT" != 0 ] && command -v timeout >/dev/null 2>&1; then
  RUNNER=(timeout --signal=KILL "$GATE_TIMEOUT")
fi

echo "== killing a real mount on a real kernel =="
rc=0
"${RUNNER[@]}" docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --network none \
  -v "$STAGE":/stage:ro \
  -v "$OUT":/out \
  --tmpfs /work:rw,size=6g,exec \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/crash.sh "$DURABLE" "$CRASH" || rc=$?
if [ "$rc" = 137 ] || [ "$rc" = 124 ]; then
  echo "the crash gate was killed after ${GATE_TIMEOUT}s: it stalled" >&2
  exit 1
fi
echo
echo "logs in $OUT"
exit $rc
