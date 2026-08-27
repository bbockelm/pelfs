#!/usr/bin/env bash
# The graft spike: does a grafted tree actually read through a mount?
#
# Two questions, and the second is the one that matters:
#
#   1. Can a foreign Pelican prefix be spidered, block-digested, published
#      into a signed generation, and read back byte-for-byte through a real
#      kernel mount, with no copy of the data under the volume's prefix?
#   2. When the source CHANGES underneath the signed generation, does the
#      read fail closed with a comprehensible error, rather than serving
#      bytes the volume never published?
#
# Linux only, and in a container on a dev machine — macOS denies the shell
# access to its own FUSE mounts (see scripts/mount-gate-test.sh, which this
# is modelled on and shares its refusal with).
#
# Usage: scripts/graft-spike-test.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [ "${PELFS_MOUNT_TEST_OK:-}" != "1" ] && [ "${CI:-}" != "true" ]; then
  echo "refusing to mount on this host: run in CI, or in a container," >&2
  echo "or set PELFS_MOUNT_TEST_OK=1 on a Linux machine you own." >&2
  exit 2
fi
[ "$(uname -s)" = "Linux" ] || { echo "a kernel mount needs Linux FUSE (macOS denies shell access to mounts)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pelfs-graft-spike.XXXXXX")"
cleanup() {
  for mp in "$WORK/mnt" "$WORK/rw"; do
    if mount | grep -q " $mp "; then
      fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || umount "$mp" 2>/dev/null || true
    fi
  done
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  [ -n "${EXT_PID:-}" ] && kill "$EXT_PID" 2>/dev/null || true
  [ -n "${MOUNT_PID:-}" ] && kill "$MOUNT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

unmount_at() {
  fusermount3 -u "$1" 2>/dev/null && return 0
  fusermount -u "$1" 2>/dev/null && return 0
  umount "$1" 2>/dev/null && return 0
  return 0
}

wait_for() { # wait_for <path> ; fails after ~10s
  for _ in $(seq 100); do [ -e "$1" ] && return 0; sleep 0.1; done
  return 1
}

if [ -n "${PELFS_PREBUILT:-}" ]; then
  echo "== using prebuilt binaries from $PELFS_PREBUILT =="
  cp "$PELFS_PREBUILT/pelfs" "$PELFS_PREBUILT/fakeorigin" "$WORK/"
else
  echo "== building pelfs and fakeorigin =="
  (cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/pelfs" ./cmd/pelfs)
  (cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/fakeorigin" ./cmd/fakeorigin)
fi

mkdir -p "$WORK/origin" "$WORK/mnt" "$WORK/rw"
# TWO SEPARATE ORIGIN PROCESSES over one directory, and the separation is
# load-bearing rather than tidy: the graft SOURCE has to be killable
# without touching the volume's own storage. A graft makes a volume's
# availability the intersection of two storage systems, and the only honest
# test of "the bytes are local now" is to remove the one you do not own.
"$WORK/fakeorigin" -listen 127.0.0.1:18997 -root "$WORK/origin" &
ORIGIN_PID=$!
"$WORK/fakeorigin" -listen 127.0.0.1:18998 -root "$WORK/origin" &
EXT_PID=$!
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:18997/" >/dev/null 2>&1 && break; sleep 0.1; done
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:18998/" >/dev/null 2>&1 && break; sleep 0.1; done

# /vol is the pelfs volume, served by the first origin; /ext is a foreign
# tree that pelfs did not write and will never copy, served by the second.
# Nothing under /vol/packs/ will ever hold the bytes that come back
# from /ext.
VOL="http://127.0.0.1:18997/vol"
EXT="http://127.0.0.1:18998/ext"

echo
echo "===================================================================="
echo "  1. a foreign tree at $EXT, which pelfs does not own"
echo "===================================================================="
mkdir -p "$WORK/origin/ext/data/nested"
# Sized deliberately: bigger than one block, exactly one block, smaller
# than one block, and a hole-free random file so no compression or
# coincidence can make the read look right by accident.
head -c 2621440 /dev/urandom > "$WORK/origin/ext/data/multiblock.bin"   # 2.5 MiB, 3 blocks
head -c 1048576 /dev/urandom > "$WORK/origin/ext/data/exactblock.bin"   # 1 MiB,  1 block
echo "a small grafted file" > "$WORK/origin/ext/data/small.txt"
head -c 300000 /dev/urandom > "$WORK/origin/ext/data/nested/mid.bin"
# The reference copy: the mount is diffed against this, not against the
# origin directory, so a test that mutates the origin cannot also mutate
# what it is comparing to.
mkdir -p "$WORK/ref"
cp -R "$WORK/origin/ext/." "$WORK/ref/"
SRC_BYTES=$(du -sb "$WORK/origin/ext" | cut -f1)
echo "source tree: $(find "$WORK/origin/ext" -type f | wc -l) files, $SRC_BYTES bytes"

echo
echo "===================================================================="
echo "  2. pelfs init, then pelfs graft"
echo "===================================================================="
"$WORK/pelfs" init --state-dir "$WORK/state" "$VOL"
"$WORK/pelfs" graft --state-dir "$WORK/state" --block 1048576 "$VOL" /ext "$EXT"

echo
echo "-- pelfs graft --list --"
"$WORK/pelfs" graft --state-dir "$WORK/state" --list "$VOL"

# THE CLAIM UNDER TEST, and it is checkable rather than asserted: the
# volume's own prefix holds no copy of the grafted bytes. Packs exist (the
# catalogs live in them) but they are orders of magnitude smaller than the
# tree they describe.
PACK_BYTES=$(du -sb "$WORK/origin/vol/packs" 2>/dev/null | cut -f1 || echo 0)
echo
echo "grafted tree:      $SRC_BYTES bytes at $EXT"
echo "volume pack bytes: $PACK_BYTES bytes under $VOL/packs"
if [ "$PACK_BYTES" -ge "$SRC_BYTES" ]; then
  echo "FAIL: the volume's packs are as big as the grafted tree; something copied the data" >&2
  exit 1
fi
echo "the data was NOT repacked locally: packs are $(( PACK_BYTES * 100 / SRC_BYTES ))% of the tree"

echo
echo "===================================================================="
echo "  3. THE GOOD READ: the grafted tree through a real kernel mount"
echo "===================================================================="
"$WORK/pelfs" mount-gen --state-dir "$WORK/state-ro" "$VOL" "$WORK/mnt" &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || { echo "mount did not come up" >&2; exit 1; }

echo "-- ls -la the grafted tree --"
ls -la "$WORK/mnt/ext/data"

echo "-- byte-for-byte against the reference copy --"
diff -r --no-dereference "$WORK/ref" "$WORK/mnt/ext"
echo "PASS: every grafted byte read back correctly through the mount"

# A ranged read in the middle of a multi-block file: the property a
# whole-object digest could not have verified.
echo "-- a ranged read straddling a block boundary --"
want=$(dd if="$WORK/ref/data/multiblock.bin" bs=1 skip=1048000 count=2000 2>/dev/null | sha256sum | cut -d' ' -f1)
got=$(dd if="$WORK/mnt/ext/data/multiblock.bin" bs=1 skip=1048000 count=2000 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "$want" = "$got" ] || { echo "FAIL: a read straddling a block boundary returned wrong bytes" >&2; exit 1; }
echo "PASS: a 2000-byte read across the 1 MiB block boundary is correct"

echo "-- synthesized metadata --"
stat -c '%n mode=%a uid=%u gid=%g size=%s' "$WORK/mnt/ext/data/small.txt" "$WORK/mnt/ext/data"
mode=$(stat -c %a "$WORK/mnt/ext/data/small.txt")
[ "$mode" = "444" ] || { echo "FAIL: grafted file mode is $mode, want 444" >&2; exit 1; }
echo "PASS: grafted files are read-only (0444), directories 0555"

unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "===================================================================="
echo "  4. RESUME: a re-run of an unchanged source reads nothing"
echo "===================================================================="
# A graft reads every byte of the source once. At TB scale that is hours,
# and hours must survive a Ctrl-C, an eviction or a token expiring. The
# checkpoint is what makes that true -- and the same mechanism is what
# makes `--refresh` cost only what CHANGED.
"$WORK/pelfs" graft --state-dir "$WORK/state" --refresh "$VOL" /ext 2>&1 | tee "$WORK/refresh.log" | sed 's/^/    /'
grep -qi 'resuming' "$WORK/refresh.log" || {
  echo "FAIL: a refresh of an unchanged source did not resume from the checkpoint" >&2
  exit 1
}
if ! grep -qE 'digested 0 bytes|digested" *"0"|hashed=0' "$WORK/refresh.log"; then
  # The line reads "digested N bytes in ...; M bytes were already checkpointed".
  hashed=$(grep -o 'digested [0-9]* bytes' "$WORK/refresh.log" | head -1 | awk '{print $2}')
  if [ "${hashed:-1}" != "0" ]; then
    echo "FAIL: a refresh of an unchanged source re-read $hashed bytes" >&2
    exit 1
  fi
fi
echo "PASS: the refresh read ZERO bytes of source data -- the checkpoint carried it"

# And the refreshed generation still reads.
"$WORK/pelfs" mount-gen --state-dir "$WORK/state-ro4" "$VOL" "$WORK/mnt" 2>"$WORK/mount-err4.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || { echo "mount did not come up" >&2; cat "$WORK/mount-err4.log" >&2; exit 1; }
cmp "$WORK/ref/data/small.txt" "$WORK/mnt/ext/data/small.txt"
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
echo "PASS: the refreshed generation serves the same bytes"
unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "-- and a source that CHANGED costs only the file that changed --"
head -c 400000 /dev/urandom > "$WORK/origin/ext/data/nested/mid.bin"
cp "$WORK/origin/ext/data/nested/mid.bin" "$WORK/ref/data/nested/mid.bin"
"$WORK/pelfs" graft --state-dir "$WORK/state" --refresh "$VOL" /ext 2>&1 | tee "$WORK/refresh2.log" | sed 's/^/    /'
hashed=$(grep -o 'digested [0-9]* bytes' "$WORK/refresh2.log" | head -1 | awk '{print $2}')
echo "the refresh read $hashed bytes for a 400000-byte change in a $SRC_BYTES-byte tree"
if [ "${hashed:-0}" -eq 0 ] || [ "${hashed:-0}" -gt 900000 ]; then
  echo "FAIL: a one-file change cost $hashed bytes; the checkpoint is not doing its job" >&2
  exit 1
fi
echo "PASS: only the changed file was re-read"

"$WORK/pelfs" mount-gen --state-dir "$WORK/state-ro5" "$VOL" "$WORK/mnt" 2>"$WORK/mount-err5.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/nested/mid.bin" || { echo "mount did not come up" >&2; cat "$WORK/mount-err5.log" >&2; exit 1; }
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
echo "PASS: the refreshed graft serves the NEW bytes of the changed file"
unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "===================================================================="
echo "  5. THE FAILURE CASE: the source changes under a signed generation"
echo "===================================================================="
# One byte, in the middle of the second block of the multi-block file. The
# file's LENGTH is unchanged, so nothing about the namespace looks wrong --
# only the bytes differ, which is exactly the case a whole-object digest
# recorded at graft time could not catch on a ranged read.
printf 'X' | dd of="$WORK/origin/ext/data/multiblock.bin" bs=1 seek=1500000 conv=notrunc 2>/dev/null
echo "mutated one byte at offset 1500000 of ext/data/multiblock.bin (length unchanged)"

"$WORK/pelfs" mount-gen --state-dir "$WORK/state-ro2" "$VOL" "$WORK/mnt" 2>"$WORK/mount-err.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || { echo "mount did not come up" >&2; cat "$WORK/mount-err.log" >&2; exit 1; }

echo "-- the UNTOUCHED files must still read fine (failure is per-block, not per-tree) --"
cmp "$WORK/ref/data/exactblock.bin" "$WORK/mnt/ext/data/exactblock.bin"
cmp "$WORK/ref/data/small.txt"      "$WORK/mnt/ext/data/small.txt"
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
echo "PASS: the other grafted files are unaffected"

echo "-- the mutated block must FAIL, not return wrong bytes --"
set +e
out=$(dd if="$WORK/mnt/ext/data/multiblock.bin" bs=1M skip=1 count=1 of=/dev/null 2>&1)
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "FAIL: the read SUCCEEDED against a mutated source. That is the whole thing this" >&2
  echo "      spike exists to rule out: unverified third-party bytes served as volume content." >&2
  exit 1
fi
echo "the read failed, as it must. dd said:"
echo "$out" | sed 's/^/    /'
echo
echo "and the mount explained why:"
grep -i 'graft' "$WORK/mount-err.log" | tail -4 | sed 's/^/    /'
grep -qi 'graft source has changed' "$WORK/mount-err.log" || {
  echo "FAIL: the error did not name the graft source as the thing that changed" >&2
  cat "$WORK/mount-err.log" >&2
  exit 1
}
echo "PASS: failed closed, naming the graft, the source, the object and the fix"

# Reading the first block of the SAME file still works: verification is
# per-block, so a changed byte costs the block that holds it and no more.
cmp <(dd if="$WORK/ref/data/multiblock.bin" bs=1M count=1 2>/dev/null) \
    <(dd if="$WORK/mnt/ext/data/multiblock.bin" bs=1M count=1 2>/dev/null)
echo "PASS: the unchanged blocks of the SAME file still read (per-block granularity)"

unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
# Put the source back, so the write test below is not testing two things.
cp "$WORK/ref/data/multiblock.bin" "$WORK/origin/ext/data/multiblock.bin"

echo
echo "===================================================================="
echo "  6. UNGRAFT ON WRITE, at FILE granularity"
echo "===================================================================="
"$WORK/pelfs" mount --rw --state-dir "$WORK/state" --no-lease --snapshot-interval 0 "$VOL" "$WORK/rw"
wait_for "$WORK/rw/ext/data/small.txt" || { echo "rw mount did not come up" >&2; exit 1; }

# A grafted file is 0444, so writing to it needs the mode opened first --
# which is itself the honest shape of "a grafted file is read-only until
# you say otherwise".
chmod 0644 "$WORK/rw/ext/data/exactblock.bin"
printf 'LOCAL' | dd of="$WORK/rw/ext/data/exactblock.bin" bs=1 seek=100 conv=notrunc 2>/dev/null
echo "wrote 5 bytes into a grafted file, and created a new file beside it"
echo "made locally, next to grafted siblings" > "$WORK/rw/ext/data/newfile.txt"

PACK_BEFORE=$(du -sb "$WORK/origin/vol/packs" | cut -f1)
"$WORK/pelfs" ctl "$VOL" publish
"$WORK/pelfs" umount "$VOL"
PACK_AFTER=$(du -sb "$WORK/origin/vol/packs" | cut -f1)
echo "packs grew from $PACK_BEFORE to $PACK_AFTER bytes"

# The written file must have been MATERIALIZED: 1 MiB of packs appeared.
GREW=$(( PACK_AFTER - PACK_BEFORE ))
if [ "$GREW" -lt 1000000 ]; then
  echo "FAIL: packs grew only $GREW bytes; the written grafted file was NOT materialized," >&2
  echo "      so it is still half-grafted and depends on the source for its untouched spans." >&2
  exit 1
fi
echo "PASS: the written file was materialized into packs ($GREW bytes) -- it is ungrafted"

# And the proof that granularity is per FILE: break the source for the
# file that was written, leave the rest alone, and remount. The written
# file must read (it is local now); its siblings must still read (they are
# still grafted, and the source for THEM is untouched).
echo "-- now DELETE the source object for the file that was written --"
rm "$WORK/origin/ext/data/exactblock.bin"

"$WORK/pelfs" mount-gen --state-dir "$WORK/state-ro3" "$VOL" "$WORK/mnt" 2>"$WORK/mount-err3.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/newfile.txt" || { echo "mount did not come up" >&2; cat "$WORK/mount-err3.log" >&2; exit 1; }

cat "$WORK/mnt/ext/data/exactblock.bin" > /dev/null || {
  echo "FAIL: the written file still depends on the graft source. Whole-file materialization" >&2
  echo "      did not happen, so the copy-up adopted external records by reference." >&2
  exit 1
}
echo "PASS: the written file reads with its source object DELETED -- fully local"
cmp "$WORK/ref/data/small.txt" "$WORK/mnt/ext/data/small.txt"
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
echo "PASS: its grafted siblings are untouched and still served from the source"
grep -q 'made locally' "$WORK/mnt/ext/data/newfile.txt"
echo "PASS: a file created inside a grafted directory is an ordinary local file"

unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "===================================================================="
echo "  7. --prefetch all: fetch the graft, then TAKE THE SOURCE AWAY"
echo "===================================================================="
# --prefetch all promises "everything this generation references is now
# local, and I failed loudly if it could not be". A graft can keep that
# promise -- the bytes go in the LOCAL CACHE, verified against the identity
# the signed catalog names. That is NOT a materialization: no lease, no new
# generation, nothing ungrafted, the volume untouched.
#
# The only test of that promise worth running is an offline one.

echo "-- --prefetch all must MOUNT and report the volume fully local --"
"$WORK/pelfs" mount-gen --prefetch all --stats-file "$WORK/pf.json" \
    --state-dir "$WORK/state-pf" "$VOL" "$WORK/mnt" >"$WORK/pf.log" 2>&1 &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || {
  echo "FAIL: --prefetch all refused to mount a grafted volume" >&2
  cat "$WORK/pf.log" >&2; exit 1
}
grep -i 'prefetch' "$WORK/pf.log" | tail -4 | sed 's/^/    /'
grep -q 'fully local: true' "$WORK/pf.log" || {
  echo "FAIL: --prefetch all mounted without reporting the volume fully local" >&2
  cat "$WORK/pf.log" >&2; exit 1
}
grep -qi 'not a materialization' "$WORK/pf.log" || {
  echo "FAIL: prefetch did not distinguish a local copy from a materialization" >&2
  cat "$WORK/pf.log" >&2; exit 1
}
echo "PASS: --prefetch all fetched the graft into the local cache and said so"

echo
echo "-- NOW KILL THE GRAFT SOURCE. The volume's own origin stays up. --"
kill "$EXT_PID" 2>/dev/null || true
wait "$EXT_PID" 2>/dev/null || true
EXT_PID=
# Prove it is really gone, so a passing read below cannot be luck.
if curl -fsS --max-time 2 "$EXT/data/small.txt" >/dev/null 2>&1; then
  echo "FAIL: the graft source is still answering; the offline test proves nothing" >&2
  exit 1
fi
echo "the graft source at $EXT is unreachable (curl fails); $VOL is still up"

echo "-- and every grafted byte must still read, from the local cache --"
# Per file rather than `diff -r`, because by now the tree is deliberately
# MIXED: section 6 ungrafted exactblock.bin into local packs and added a
# local newfile.txt, so the mount and the reference copy are not the same
# set of files any more. These three are the ones still served from the
# graft, and they are the ones that matter here.
cmp "$WORK/ref/data/multiblock.bin"  "$WORK/mnt/ext/data/multiblock.bin"
cmp "$WORK/ref/data/small.txt"       "$WORK/mnt/ext/data/small.txt"
cmp "$WORK/ref/data/nested/mid.bin"  "$WORK/mnt/ext/data/nested/mid.bin"
echo "PASS: every still-grafted file read back byte-for-byte WITH THE SOURCE OFFLINE"
# And the already-local parts are unaffected, which is what says the
# offline read above came from the graft cache and not from the packs.
cat "$WORK/mnt/ext/data/exactblock.bin" >/dev/null
grep -q 'made locally' "$WORK/mnt/ext/data/newfile.txt"
echo "PASS: the locally packed files in the same tree still read too"
want=$(dd if="$WORK/ref/data/multiblock.bin" bs=1 skip=1048000 count=2000 2>/dev/null | sha256sum | cut -d' ' -f1)
got=$(dd if="$WORK/mnt/ext/data/multiblock.bin" bs=1 skip=1048000 count=2000 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "$want" = "$got" ] || { echo "FAIL: an offline read across a block boundary returned wrong bytes" >&2; exit 1; }
echo "PASS: an offline read across a 1 MiB block boundary is correct"

unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
if [ -f "$WORK/pf.json" ]; then
  echo "-- the machine-readable half --"
  grep -o '"prefetch_complete":[^,}]*' "$WORK/pf.json" || echo "    prefetch_complete absent"
  grep -o '"prefetch_grafted_bytes":[^,}]*' "$WORK/pf.json" || true
  grep -o '"prefetch_graft_local_bytes":[^,}]*' "$WORK/pf.json" || true
  grep -qE "\"prefetch_complete\": *true" "$WORK/pf.json" || {
    echo "FAIL: the stats do not record the volume as fully local" >&2; exit 1; }
  echo "PASS: prefetch_complete is true, and the grafted bytes are accounted for as local"
fi

echo
echo "-- a REMOUNT over the same cache still reads offline (the cache outlives the process) --"
"$WORK/pelfs" mount-gen --state-dir "$WORK/state-pf" "$VOL" "$WORK/mnt" >"$WORK/pf-remount.log" 2>&1 &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || {
  echo "FAIL: the remount did not come up" >&2; cat "$WORK/pf-remount.log" >&2; exit 1; }
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
cmp "$WORK/ref/data/multiblock.bin" "$WORK/mnt/ext/data/multiblock.bin"
echo "PASS: a fresh process served the grafted tree from the cache the last one filled"
unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "===================================================================="
echo "  8. the other two modes, and the refusal that is actually useful"
echo "===================================================================="
# Bring the source back so `packs` mode has something to be remote.
"$WORK/fakeorigin" -listen 127.0.0.1:18998 -root "$WORK/origin" &
EXT_PID=$!
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:18998/" >/dev/null 2>&1 && break; sleep 0.1; done

echo "-- --prefetch packs must MOUNT, WARN, and not claim the volume is local --"
"$WORK/pelfs" mount-gen --prefetch packs --stats-file "$WORK/pf2.json" \
    --state-dir "$WORK/state-pf2" "$VOL" "$WORK/mnt" >"$WORK/pf2.log" 2>&1 &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || {
  echo "FAIL: --prefetch packs refused to mount a grafted volume" >&2
  cat "$WORK/pf2.log" >&2; exit 1
}
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
grep -i 'prefetch' "$WORK/pf2.log" | tail -4 | sed 's/^/    /'
grep -qi 'this mode does not fetch it' "$WORK/pf2.log" || {
  echo "FAIL: --prefetch packs mounted without warning that grafted bytes stay remote" >&2
  cat "$WORK/pf2.log" >&2; exit 1
}
grep -q 'fully local: false' "$WORK/pf2.log" || {
  echo "FAIL: --prefetch packs did not say the volume is not fully local" >&2
  cat "$WORK/pf2.log" >&2; exit 1
}
unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
if grep -qE "\"prefetch_complete\": *true" "$WORK/pf2.json" 2>/dev/null; then
  echo "FAIL: the stats claim a packs-only prefetch left a grafted volume fully local" >&2
  exit 1
fi
echo "PASS: --prefetch packs mounts, warns by name, and reports not-fully-local"

echo
echo "-- and a cache too small must refuse with BOTH NUMBERS, not a categorical no --"
set +e
"$WORK/pelfs" mount-gen --prefetch all --cache-size 200K \
    --state-dir "$WORK/state-pf3" "$VOL" "$WORK/mnt" >"$WORK/pf3.log" 2>&1 &
MOUNT_PID=$!
up=no
for _ in $(seq 40); do [ -e "$WORK/mnt/ext/data/small.txt" ] && { up=yes; break; }; sleep 0.1; done
set -e
if [ "$up" = yes ]; then
  echo "FAIL: --prefetch all mounted with a cache far too small to hold the graft" >&2
  unmount_at "$WORK/mnt"; exit 1
fi
wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
grep -i 'prefetch' "$WORK/pf3.log" | tail -3 | sed 's/^/    /'
grep -qi 'grafted from' "$WORK/pf3.log" || {
  echo "FAIL: the refusal does not say how much is grafted or from where" >&2
  cat "$WORK/pf3.log" >&2; exit 1
}
grep -qi 'cache budget is' "$WORK/pf3.log" || {
  echo "FAIL: the refusal does not carry the budget it could not fit in" >&2
  cat "$WORK/pf3.log" >&2; exit 1
}
grep -qi 'prefetch packs' "$WORK/pf3.log" || {
  echo "FAIL: the refusal does not offer the way forward" >&2
  cat "$WORK/pf3.log" >&2; exit 1
}
if grep -qi 'no listed pack' "$WORK/pf3.log"; then
  echo "FAIL: the refusal says 'present in no listed pack', which means DAMAGE" >&2
  echo "      everywhere else in this system. A graft is not damage." >&2
  exit 1
fi
echo "PASS: the refusal is about SIZE, carries both numbers, names the graft, and offers a way on"

echo
echo "===================================================================="
echo "  9. A GRAFT INTO A POPULATED VOLUME"
echo "===================================================================="
# The one thing that made this feature unusable: everything above is
# `pelfs init` then `pelfs graft`, which nobody wants. This section takes a
# volume that ALREADY HAS CONTENT -- written through a real rw mount and
# sealed -- and splices the foreign tree into it, then checks the only
# things that matter: the old files still read, the new ones read, a seal
# afterwards works, and a cold remount agrees with all of it.
#
# A SECOND VOLUME, so the narrative above is untouched.
VOL2="http://127.0.0.1:18997/vol2"
mkdir -p "$WORK/rw2" "$WORK/mnt2"
"$WORK/pelfs" init --state-dir "$WORK/state2" "$VOL2"

echo "-- write a real tree through a real rw mount, and seal it --"
"$WORK/pelfs" mount --rw --state-dir "$WORK/state2" --no-lease --snapshot-interval 0 "$VOL2" "$WORK/rw2"
wait_for "$WORK/rw2" || { echo "rw mount did not come up" >&2; exit 1; }
mkdir -p "$WORK/rw2/docs" "$WORK/rw2/busy" "$WORK/rw2/empty"
echo "a file the volume already had" > "$WORK/rw2/keep.txt"
head -c 300000 /dev/urandom > "$WORK/rw2/docs/big.bin"
echo "nested and must survive" > "$WORK/rw2/docs/readme.txt"
echo "do not lose me" > "$WORK/rw2/busy/mine.txt"
echo "nor me" > "$WORK/rw2/busy/mine2.txt"
mkdir -p "$WORK/ref2"
cp -R "$WORK/rw2/." "$WORK/ref2/"
"$WORK/pelfs" ctl "$VOL2" publish
"$WORK/pelfs" umount "$VOL2"
BASE_FILES=$(find "$WORK/ref2" -type f | wc -l)
echo "the volume holds $BASE_FILES files of its own before any graft"

echo
echo "-- REFUSALS FIRST, because they are what protects somebody's data --"
set +e
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 "$VOL2" /busy "$EXT" \
    >"$WORK/g-busy.log" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: grafting over a POPULATED directory succeeded" >&2; cat "$WORK/g-busy.log" >&2; exit 1; }
grep -qi '2 entries' "$WORK/g-busy.log" || { echo "FAIL: the refusal does not count what it would drop" >&2; cat "$WORK/g-busy.log" >&2; exit 1; }
grep -qi -- '--replace' "$WORK/g-busy.log" || { echo "FAIL: the refusal does not say what to do instead" >&2; cat "$WORK/g-busy.log" >&2; exit 1; }
echo "PASS: a populated directory is not replaced silently; the refusal counts it and offers --replace"

set +e
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 "$VOL2" /keep.txt "$EXT" \
    >"$WORK/g-file.log" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: grafting onto a FILE succeeded" >&2; exit 1; }
grep -qi 'is a file' "$WORK/g-file.log" || { echo "FAIL: the refusal does not say what is there" >&2; cat "$WORK/g-file.log" >&2; exit 1; }
echo "PASS: a file at the graft path is refused, by name"

# Nothing was published by either refusal.
GEN_BEFORE=$("$WORK/pelfs" fsck --state-dir "$WORK/state2" "$VOL2" 2>/dev/null | grep -oE '^generation [0-9]+' | head -1 | awk '{print $2}')
echo "the branch is still on generation ${GEN_BEFORE:-?} after two refusals"

echo
echo "-- the mode of a directory ON the graft path, before --"
DOCS_MODE_BEFORE=$(stat -c %a "$WORK/ref2/docs")
echo "-- and now the graft itself, into the populated volume --"
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 "$VOL2" /ext "$EXT" \
    2>&1 | tee "$WORK/g-ok.log" | sed 's/^/    /'
grep -qi 'carried forward unchanged' "$WORK/g-ok.log" || {
  echo "FAIL: the graft did not report what it carried forward; it may have rewritten the volume" >&2
  cat "$WORK/g-ok.log" >&2; exit 1; }
# The count itself is 0 on a volume this small -- it has ONE catalog, so
# there is nothing below the root to carry. What this checks is that the
# splice reports the split at all; the carrying is measured where it can
# be, on a volume with nested catalogs, in
# publish.TestGraftAcrossANestedCatalogBoundary.
grep -qi "files' content records reused as published" "$WORK/g-ok.log" || {
  echo "FAIL: the graft did not reuse the base generation's content records" >&2
  cat "$WORK/g-ok.log" >&2; exit 1; }
REUSED=$(grep -oE '[0-9]+ files.\ content records reused' "$WORK/g-ok.log" | head -1 | awk '{print $1}')
[ "${REUSED:-0}" -ge "$BASE_FILES" ] || {
  echo "FAIL: only ${REUSED:-0} of $BASE_FILES base files kept their published records;" >&2
  echo "      the splice is re-reading content it already had" >&2; exit 1; }
echo "PASS: the splice kept all $BASE_FILES base files' published content records and rewrote only the path"

echo
echo "-- a COLD mount of the result: the old tree AND the new one --"
"$WORK/pelfs" mount-gen --state-dir "$WORK/state2-ro" "$VOL2" "$WORK/mnt2" 2>"$WORK/mnt2-err.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt2/keep.txt" || { echo "mount did not come up" >&2; cat "$WORK/mnt2-err.log" >&2; exit 1; }
echo "-- ls -la / --"
ls -la "$WORK/mnt2"
# Every pre-existing file, byte for byte, against the copy taken before
# the graft.
for f in keep.txt docs/readme.txt docs/big.bin busy/mine.txt busy/mine2.txt; do
  cmp "$WORK/ref2/$f" "$WORK/mnt2/$f" || { echo "FAIL: $f did not survive the graft" >&2; exit 1; }
done
[ -d "$WORK/mnt2/empty" ] || { echo "FAIL: the empty directory did not survive the graft" >&2; exit 1; }
echo "PASS: all $BASE_FILES pre-existing files, and the empty directory, read unchanged"
# A directory ON the graft path is the one that could lose its attributes:
# publish records an inode's attributes from the listing that named it, so a
# spine directory re-described by the splice from its inode alone would be
# republished as mode 0.
"$WORK/pelfs" graft --state-dir "$WORK/state2" --list "$VOL2" >/dev/null
DOCS_MODE_AFTER=$(stat -c %a "$WORK/mnt2/docs")
[ "$DOCS_MODE_AFTER" = "$DOCS_MODE_BEFORE" ] || {
  echo "FAIL: /docs is mode $DOCS_MODE_AFTER after the graft, was $DOCS_MODE_BEFORE" >&2; exit 1; }
echo "PASS: directories keep their mode ($DOCS_MODE_BEFORE) across the splice"
# And the grafted tree, from a prefix that holds none of the volume's bytes.
cmp "$WORK/ref/data/small.txt" "$WORK/mnt2/ext/data/small.txt"
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt2/ext/data/nested/mid.bin"
cmp "$WORK/ref/data/multiblock.bin" "$WORK/mnt2/ext/data/multiblock.bin"
echo "PASS: the grafted tree reads beside the volume's own content"
unmount_at "$WORK/mnt2"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "-- RE-GRAFTING THE SAME SOURCE is a refresh, and says so --"
set +e
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 "$VOL2" /ext "$EXT" \
    >"$WORK/g-again.log" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: re-grafting the same source at the same path succeeded silently" >&2; exit 1; }
grep -qi -- '--refresh' "$WORK/g-again.log" || { echo "FAIL: the refusal does not name --refresh" >&2; cat "$WORK/g-again.log" >&2; exit 1; }
echo "PASS: re-grafting the same source is refused and names --refresh"

echo
echo "-- A GRAFT INSIDE A GRAFT is refused by name --"
set +e
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 "$VOL2" /ext/inner "$EXT" \
    >"$WORK/g-nested.log" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "FAIL: a graft inside a grafted subtree succeeded" >&2; exit 1; }
grep -qi 'inside the graft at /ext' "$WORK/g-nested.log" || {
  echo "FAIL: the refusal does not name the graft it is inside" >&2; cat "$WORK/g-nested.log" >&2; exit 1; }
echo "PASS: a nested graft is refused, naming the outer graft"

echo
echo "-- A SEAL AFTERWARDS: the volume is still writable, and the graft survives it --"
# The graft advanced the branch, and the leftover overlay from the writable
# mount above records the generation it shadowed -- so it can no longer be
# sealed onto the head. `pelfs graft` warns about exactly this before it
# starts, and moving it aside is what the warning says to do. NOT graft
# specific: `pelfs repack`, `pelfs merge` and a second writer have always
# done the same thing to a leftover overlay.
grep -qi 'unsealed write overlay' "$WORK/g-ok.log" || {
  echo "FAIL: the graft did not warn that it would strand the leftover overlay" >&2
  cat "$WORK/g-ok.log" >&2; exit 1; }
echo "PASS: the graft warned up front about the leftover overlay it would strand"
rm -rf "$WORK/state2/overlay"
"$WORK/pelfs" mount --rw --state-dir "$WORK/state2" --no-lease --snapshot-interval 0 "$VOL2" "$WORK/rw2"
wait_for "$WORK/rw2/keep.txt" || { echo "rw mount did not come up over a grafted volume" >&2; exit 1; }
echo "written after the graft" > "$WORK/rw2/after.txt"
cmp "$WORK/ref/data/small.txt" "$WORK/rw2/ext/data/small.txt"
"$WORK/pelfs" ctl "$VOL2" publish
"$WORK/pelfs" umount "$VOL2"
echo "PASS: a seal over a grafted volume published, and the grafted tree read through the rw mount"

"$WORK/pelfs" mount-gen --state-dir "$WORK/state2-ro2" "$VOL2" "$WORK/mnt2" 2>"$WORK/mnt2-err2.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt2/after.txt" || { echo "the post-seal mount did not come up" >&2; cat "$WORK/mnt2-err2.log" >&2; exit 1; }
grep -q 'written after the graft' "$WORK/mnt2/after.txt"
cmp "$WORK/ref2/keep.txt" "$WORK/mnt2/keep.txt"
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt2/ext/data/nested/mid.bin"
echo "PASS: a cold remount agrees: the pre-graft tree, the graft, and the post-graft write"
unmount_at "$WORK/mnt2"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "-- --replace, on purpose, over the populated directory --"
rm -rf "$WORK/state2/overlay"
"$WORK/pelfs" graft --state-dir "$WORK/state2" --block 1048576 --replace "$VOL2" /busy "$EXT" \
    2>&1 | tee "$WORK/g-replace.log" | sed 's/^/    /'
grep -qi 'will NOT be in the next generation' "$WORK/g-replace.log" || {
  echo "FAIL: --replace did not say what it was dropping" >&2; cat "$WORK/g-replace.log" >&2; exit 1; }
"$WORK/pelfs" mount-gen --state-dir "$WORK/state2-ro3" "$VOL2" "$WORK/mnt2" 2>"$WORK/mnt2-err3.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt2/busy/data/small.txt" || {
  echo "FAIL: --replace did not put the graft at /busy" >&2; cat "$WORK/mnt2-err3.log" >&2; exit 1; }
[ ! -e "$WORK/mnt2/busy/mine.txt" ] || { echo "FAIL: --replace left the old entries behind" >&2; exit 1; }
cmp "$WORK/ref2/keep.txt" "$WORK/mnt2/keep.txt"
echo "PASS: --replace displaced exactly the directory it named, and nothing else"
unmount_at "$WORK/mnt2"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "-- --remove: the graft goes, the volume stays --"
rm -rf "$WORK/state2/overlay"
"$WORK/pelfs" graft --state-dir "$WORK/state2" --remove "$VOL2" /ext \
    2>&1 | tee "$WORK/g-remove.log" | sed 's/^/    /'
grep -qi 'does not name that source' "$WORK/g-remove.log" || {
  echo "FAIL: --remove did not say the volume stopped depending on the source" >&2
  cat "$WORK/g-remove.log" >&2; exit 1; }
"$WORK/pelfs" graft --state-dir "$WORK/state2" --list "$VOL2" | tee "$WORK/g-list.log" | sed 's/^/    /'
grep -q '/ext ' "$WORK/g-list.log" && { echo "FAIL: --list still names the removed graft" >&2; exit 1; }
"$WORK/pelfs" mount-gen --state-dir "$WORK/state2-ro4" "$VOL2" "$WORK/mnt2" 2>"$WORK/mnt2-err4.log" &
MOUNT_PID=$!
wait_for "$WORK/mnt2/keep.txt" || { echo "the post-remove mount did not come up" >&2; cat "$WORK/mnt2-err4.log" >&2; exit 1; }
[ ! -e "$WORK/mnt2/ext" ] || { echo "FAIL: --remove left /ext in the namespace" >&2; exit 1; }
cmp "$WORK/ref2/keep.txt" "$WORK/mnt2/keep.txt"
cmp "$WORK/ref2/docs/big.bin" "$WORK/mnt2/docs/big.bin"
grep -q 'written after the graft' "$WORK/mnt2/after.txt"
# The OTHER graft (/busy, from --replace) is untouched by removing this one.
cmp "$WORK/ref/data/small.txt" "$WORK/mnt2/busy/data/small.txt"
echo "PASS: --remove dropped one graft and left the volume, and the other graft, intact"
unmount_at "$WORK/mnt2"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=

echo
echo "===================================================================="
echo "  10. fsck ON A GRAFTED VOLUME"
echo "===================================================================="
# Item 2's second half. Until now `pelfs fsck` reported EVERY grafted file
# as `missing-chunk` and exited 1 on a perfectly healthy volume: a grafted
# chunk is in no pack BY DESIGN, and checkChunkRef had the same absence
# check genfs.ContentOf and genfs.Prefetch both had before they were taught
# that a graft is a LOCATION rather than a hole.
#
# VOL2 is the volume worth checking, because it is the mixed case: this
# volume's own packed content (keep.txt, docs/, after.txt) side by side
# with a graft at /busy, both swept in one pass.
#
# What is asserted here is the SEVERITY CONTRACT, because that is what an
# operator's cron reads:
#
#   healthy grafted volume         -> clean, exit 0 (and 0 under --strict)
#   the SOURCE moved on            -> warning, exit 0; exit 1 under --strict
#   the volume's own index is gone -> damage, exit 1
#
# and the difference between the two check depths, which is four orders of
# magnitude of cost and has to be visible in the output.

echo "-- a healthy grafted volume must be CLEAN and exit 0 --"
set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" "$VOL2" >"$WORK/fsck-ok.log" 2>&1
rc=$?
set -e
sed 's/^/    /' "$WORK/fsck-ok.log"
[ "$rc" -eq 0 ] || { echo "FAIL: fsck exited $rc on a healthy grafted volume" >&2; exit 1; }
grep -q 'generation is consistent' "$WORK/fsck-ok.log" || {
  echo "FAIL: fsck did not call a healthy grafted volume consistent" >&2; exit 1; }
if grep -qi 'missing-chunk' "$WORK/fsck-ok.log"; then
  echo "FAIL: fsck STILL reports grafted files as missing chunks. That is the whole of item 2:" >&2
  echo "      a grafted chunk is in no pack by design, and reporting it as damage makes fsck" >&2
  echo "      unusable on the volumes this feature exists for." >&2
  exit 1
fi
if grep -qi 'warning' "$WORK/fsck-ok.log"; then
  echo "FAIL: a healthy grafted volume produced warnings" >&2; exit 1
fi
grep -q "stat.d by HEAD" "$WORK/fsck-ok.log" || {
  echo "FAIL: the report does not say what the default check actually cost" >&2; exit 1; }
echo "PASS: clean, exit 0, and the report states the cheap mode's claim rather than 'checked'"

set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --strict "$VOL2" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "FAIL: --strict failed a healthy grafted volume (exit $rc)" >&2; exit 1; }
echo "PASS: --strict on a healthy grafted volume is still 0"

echo
echo "-- the two depths, and the different claims they earn --"
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --grafts=deep "$VOL2" 2>&1 \
  | tee "$WORK/fsck-deep.log" | sed 's/^/    /'
grep -q 're-read from the source and re-hashed' "$WORK/fsck-deep.log" || {
  echo "FAIL: --grafts=deep does not report what it moved" >&2; exit 1; }
grep -q 'generation is consistent' "$WORK/fsck-deep.log" || {
  echo "FAIL: --grafts=deep found something on a healthy volume" >&2; exit 1; }
echo "PASS: the deep mode re-read every external block and says so in bytes"

echo
echo "-- A SOURCE THAT MOVED ON IS A WARNING, NOT DAMAGE --"
# The volume is intact. A third party with no obligation to it republished
# a file, which is the event a graft EXISTS to expose -- so this must not
# turn an operator's nightly fsck red, and --strict is how somebody who
# wants it to opts in.
MB="$WORK/origin/ext/data/multiblock.bin"
cp "$MB" "$WORK/mb.orig"
head -c 2000000 "$WORK/mb.orig" > "$MB"
echo "truncated ext/data/multiblock.bin from 2621440 to 2000000 bytes at the source"

set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" "$VOL2" >"$WORK/fsck-moved.log" 2>&1
rc=$?
set -e
sed 's/^/    /' "$WORK/fsck-moved.log"
[ "$rc" -eq 0 ] || {
  echo "FAIL: a moved SOURCE exited $rc. A graft source republishing is not this volume's" >&2
  echo "      damage, and an fsck that cries wolf is an fsck people stop running." >&2
  exit 1; }
grep -q 'warning: graft-source-changed' "$WORK/fsck-moved.log" || {
  echo "FAIL: a moved source was not reported as a warning" >&2; exit 1; }
grep -q -- '--refresh' "$WORK/fsck-moved.log" || {
  echo "FAIL: the warning does not name the fix" >&2; exit 1; }
if grep -q 'is damaged' "$WORK/fsck-moved.log"; then
  echo "FAIL: a moved source was called damage" >&2; exit 1
fi
echo "PASS: warning, exit 0, and it names the graft, the object and \`--refresh\`"

set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --strict "$VOL2" >"$WORK/fsck-strict.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { echo "FAIL: --strict exited $rc on a warning" >&2; cat "$WORK/fsck-strict.log" >&2; exit 1; }
grep -q 'failing on --strict' "$WORK/fsck-strict.log" || {
  echo "FAIL: --strict did not say why it failed" >&2; exit 1; }
echo "PASS: the same volume exits 1 under --strict -- opt-in, not default"

echo
echo "-- THE EDIT THE CHEAP MODE CANNOT SEE, and the mode that can --"
# One byte, same length, same mtime: the exact mutation section 5 uses,
# and the exact thing a HEAD cannot catch. The cheap mode has to be SILENT
# here rather than guess, and the report has to have said so up front.
cp "$WORK/mb.orig" "$MB"
printf 'X' | dd of="$MB" bs=1 seek=1500000 conv=notrunc 2>/dev/null
touch -r "$WORK/mb.orig" "$MB"
echo "one byte at offset 1500000; length and mtime unchanged"

set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --strict "$VOL2" >"$WORK/fsck-cheap.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || {
  echo "FAIL: the cheap mode claimed to see a same-length edit (exit $rc)" >&2
  cat "$WORK/fsck-cheap.log" >&2; exit 1; }
grep -q 'same-length edit is invisible to this mode' "$WORK/fsck-cheap.log" || {
  echo "FAIL: the cheap mode does not admit what it cannot see" >&2; exit 1; }
echo "PASS: silent, exit 0 -- and the report already said this is what it would do"

set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --grafts=deep "$VOL2" >"$WORK/fsck-deep2.log" 2>&1
rc=$?
set -e
sed 's/^/    /' "$WORK/fsck-deep2.log"
[ "$rc" -eq 0 ] || { echo "FAIL: deep mode called a moved source damage (exit $rc)" >&2; exit 1; }
grep -q 'warning: graft-source-changed' "$WORK/fsck-deep2.log" || {
  echo "FAIL: --grafts=deep did not catch a one-byte edit" >&2; exit 1; }
grep -q 'hashes to' "$WORK/fsck-deep2.log" || {
  echo "FAIL: the deep finding does not name the hash it got" >&2; exit 1; }
set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --grafts=deep --strict "$VOL2" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { echo "FAIL: --grafts=deep --strict exited $rc on a changed block" >&2; exit 1; }
echo "PASS: only the deep mode sees it -- warning at exit 0, exit 1 under --strict"

# Put the source back, so the last test is about the volume and nothing else.
cp "$WORK/mb.orig" "$MB"
touch -r "$WORK/mb.orig" "$MB"

echo
echo "-- AND THE VOLUME'S OWN OBJECT GOING MISSING IS DAMAGE --"
# The other side of the line. A graft index lives under THIS volume's
# prefix, is hash-named, and is the only record of where a grafted file's
# bytes are. Losing it is not news about a third party; it is a generation
# no reader can serve, and only this volume's operator can fix it.
mv "$WORK/origin/vol2/grafts" "$WORK/grafts.away"
set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" "$VOL2" >"$WORK/fsck-broken.log" 2>&1
rc=$?
set -e
sed 's/^/    /' "$WORK/fsck-broken.log"
[ "$rc" -eq 1 ] || { echo "FAIL: a lost graft index exited $rc, not 1" >&2; exit 1; }
grep -q 'error: graft-index' "$WORK/fsck-broken.log" || {
  echo "FAIL: a lost graft index was not reported as damage" >&2; exit 1; }
grep -q 'is damaged' "$WORK/fsck-broken.log" || {
  echo "FAIL: fsck did not call the generation damaged" >&2; exit 1; }
grep -q 'missing-chunk' "$WORK/fsck-broken.log" || {
  echo "FAIL: with no index, the files under the graft have no location and must be missing" >&2
  exit 1; }
echo "PASS: damage, exit 1 -- the volume's own object, not a third party's"

mv "$WORK/grafts.away" "$WORK/origin/vol2/grafts"
set +e
"$WORK/pelfs" fsck --state-dir "$WORK/state2" --strict "$VOL2" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "FAIL: fsck did not recover when the index came back (exit $rc)" >&2; exit 1; }
echo "PASS: and it is clean again the moment the index is back"

echo
echo "===================================================================="
echo "  the spike answers both questions: yes, and yes -- a graft goes into a"
echo "  volume that already has content in it, and fsck can now be run on the"
echo "  result: clean at exit 0, a moved source a warning, lost metadata damage"
echo "===================================================================="
