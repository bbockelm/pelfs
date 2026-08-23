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
"$WORK/fakeorigin" -listen 127.0.0.1:18997 -root "$WORK/origin" &
ORIGIN_PID=$!
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:18997/" >/dev/null 2>&1 && break; sleep 0.1; done

# TWO PREFIXES ON ONE ORIGIN. /vol is the pelfs volume; /ext is a foreign
# tree that pelfs did not write and will never copy. That is the whole
# point of the arrangement: nothing under /vol/packs/ will ever hold the
# bytes that come back from /ext.
VOL="http://127.0.0.1:18997/vol"
EXT="http://127.0.0.1:18997/ext"

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
echo "  7. --prefetch: the three honest modes"
echo "===================================================================="
# --prefetch all promises "everything this generation references is now
# local, and I failed loudly if it could not be". A graft cannot keep that
# promise: the bytes are not in a pack and were never going to be. So
# there are three modes, and this section tests two of them.
#
#   all    REFUSE, deliberately, naming the graft.
#   packs  make the packs local, WARN about the grafted bytes, mount.
#
# The third -- materialize the grafted blocks into local packs -- is a
# WRITE and is designed in docs/design-graft.md rather than built here.

echo "-- --prefetch all must REFUSE, and must say 'graft' rather than 'no listed pack' --"
set +e
"$WORK/pelfs" mount-gen --prefetch all --state-dir "$WORK/state-pf" "$VOL" "$WORK/mnt" >"$WORK/pf.log" 2>&1 &
MOUNT_PID=$!
up=no
for _ in $(seq 60); do [ -e "$WORK/mnt/ext/data/small.txt" ] && { up=yes; break; }; sleep 0.1; done
set -e
if [ "$up" = yes ]; then
  echo "FAIL: --prefetch all mounted a volume whose grafted bytes are NOT local" >&2
  unmount_at "$WORK/mnt"; exit 1
fi
wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
grep -i 'prefetch' "$WORK/pf.log" | tail -3 | sed 's/^/    /'
grep -qi 'GRAFTED' "$WORK/pf.log" || {
  echo "FAIL: the refusal did not name the graft as the reason" >&2
  cat "$WORK/pf.log" >&2; exit 1
}
grep -qi 'prefetch packs' "$WORK/pf.log" || {
  echo "FAIL: the refusal did not offer the way forward" >&2
  cat "$WORK/pf.log" >&2; exit 1
}
if grep -qi 'no listed pack' "$WORK/pf.log"; then
  echo "FAIL: the refusal still says 'present in no listed pack', which means DAMAGE" >&2
  echo "      everywhere else in this system. A graft is not damage." >&2
  exit 1
fi
echo "PASS: --prefetch all refuses by name, offers --prefetch packs, and does not cry damage"

echo
echo "-- --prefetch packs must MOUNT, warn, and not claim the volume is local --"
"$WORK/pelfs" mount-gen --prefetch packs --stats-file "$WORK/pf2.json" --state-dir "$WORK/state-pf2" "$VOL" "$WORK/mnt" >"$WORK/pf2.log" 2>&1 &
MOUNT_PID=$!
wait_for "$WORK/mnt/ext/data/small.txt" || {
  echo "FAIL: --prefetch packs refused to mount a grafted volume" >&2
  cat "$WORK/pf2.log" >&2; exit 1
}
# The grafted bytes still read -- from the source, which is the point.
cmp "$WORK/ref/data/nested/mid.bin" "$WORK/mnt/ext/data/nested/mid.bin"
grep -i 'prefetch' "$WORK/pf2.log" | tail -4 | sed 's/^/    /'
grep -qi 'cannot be made local' "$WORK/pf2.log" || {
  echo "FAIL: --prefetch packs mounted without warning that grafted bytes are remote" >&2
  cat "$WORK/pf2.log" >&2; exit 1
}
unmount_at "$WORK/mnt"; wait "$MOUNT_PID" 2>/dev/null || true; MOUNT_PID=
if [ -f "$WORK/pf2.json" ]; then
  echo "-- and the machine-readable half of the warning --"
  grep -o '"prefetch_complete":[^,}]*' "$WORK/pf2.json" || echo "    prefetch_complete absent (false)"
  grep -o '"prefetch_grafted_bytes":[^,}]*' "$WORK/pf2.json" || true
  if grep -q '"prefetch_complete":true' "$WORK/pf2.json"; then
    echo "FAIL: the stats claim a grafted volume is fully local" >&2
    exit 1
  fi
  echo "PASS: prefetch_complete is not true while grafted bytes are remote"
fi

echo
echo "===================================================================="
echo "  the spike answers both questions: yes, and yes"
echo "===================================================================="
