#!/usr/bin/env bash
# The mount gate: publish a generation, mount it with `pelfs mount-gen`
# through the catalog-native stack (genfs + raw FUSE), verify the mounted
# tree byte-for-byte against the source, and time the end-to-end
# benchmarks against it.
#
# Linux (or macFUSE) only — this is the coverage a macFUSE-less dev
# machine cannot provide, so CI owns it.
#
# Usage: scripts/mount-gate-test.sh [--bench]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BENCH="${1:-}"

# This script mounts a real filesystem and writes a scratch tree. It runs
# in CI (Linux) or a container — NEVER casually on a developer's machine,
# and never anywhere near $HOME. On macOS it cannot work at all: NFS/FUSE
# mounts come up but the shell is denied access to them, whatever the
# location. Set PELFS_MOUNT_TEST_OK=1 to override on a Linux box you own.
if [ "${PELFS_MOUNT_TEST_OK:-}" != "1" ] && [ "${CI:-}" != "true" ]; then
  echo "refusing to mount on this host: run in CI, or in a container," >&2
  echo "or set PELFS_MOUNT_TEST_OK=1 on a Linux machine you own." >&2
  exit 2
fi
[ "$(uname -s)" = "Linux" ] || { echo "a kernel mount needs Linux FUSE (macOS denies shell access to mounts)" >&2; exit 2; }

# Scratch lives under the repo's own build area, never $HOME.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pelfs-mount-gate.XXXXXX")"
cleanup() {
  if mountpoint -q "$WORK/mnt" 2>/dev/null || mount | grep -q " $WORK/mnt "; then
    fusermount3 -u "$WORK/mnt" 2>/dev/null || fusermount -u "$WORK/mnt" 2>/dev/null || \
      umount "$WORK/mnt" 2>/dev/null || true
  fi
  # The NFS leg is a real kernel mount too, and a leaked one makes the
  # rm -rf below hang on a server that is already dead.
  if mount | grep -q " $WORK/nfsmnt "; then
    umount "$WORK/nfsmnt" 2>/dev/null || umount -l "$WORK/nfsmnt" 2>/dev/null || true
  fi
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  [ -n "${MOUNT_PID:-}" ] && kill "$MOUNT_PID" 2>/dev/null || true
  [ -n "${NFS_PID:-}" ] && kill "$NFS_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT


# unmount_at detaches a mountpoint if anything is mounted there. Repeated
# unmounts are expected in this script (each section remounts), so "not
# mounted" is success, not failure.
unmount_at() {
  local mp="$1"
  fusermount3 -u "$mp" 2>/dev/null && return 0
  fusermount -u "$mp" 2>/dev/null && return 0
  umount "$mp" 2>/dev/null && return 0
  return 0
}

# deletion_gate <label> <writable mount root>
#
# Everything `rm -rf` needs from a filesystem, run against whatever backend
# is mounted at $2. It exists because the property that broke was never
# tested at any size: the gate had one ENOTEMPTY check on a directory of a
# single file, which no amount of paging or symlink resolution can disturb.
#
# The failure it now catches was reported as an undeletable directory —
# three `rm -rf` passes, the same 23 files surviving every one:
#
#     rm: htcondor/src/condor_tests: Directory not empty
#
# Every survivor was a SYMLINK, and all 23 named one target that sorts
# ahead of them. `rm -rf` walks a directory in sorted order, so the target
# went first and every link dangled by the time its own turn came. The NFS
# REMOVE handler stat'ed the object through the link, got ENOENT for a link
# that was plainly there, and answered NFS3ERR_NOENT without unlinking
# anything. rm reads ENOENT on unlink as "already gone" and moves on, so
# the links survived and the rmdir behind them refused — identically, every
# pass, since nothing about it converges.
#
# Sized to run in a couple of seconds. The large directory is here because
# READDIR cookies are positional indices into a listing, so a directory big
# enough to need many READDIR calls is the only one that can expose an
# unlink shifting the entries a client has not been shown yet.
deletion_gate() {
  local label="$1" root="$2"
  local d="$root/deltest"
  local n out

  rm -rf "$d" 2>/dev/null || true
  mkdir -p "$d/links" "$d/keep/realdir" "$d/big"

  # The reported shape first, so a regression prints the user's sentence
  # rather than a proxy for it: one target that sorts ahead of every link
  # to it, and 23 links, deleted in ONE pass. `rm -rf` exits non-zero when
  # it leaves anything, so its own message is captured and shown.
  echo "the target every link names" > "$d/links/aaa_base.run"
  for i in $(seq 1 23); do
    ln -s aaa_base.run "$d/links/lib_eventlog_rotation_$i.run"
  done
  out=$(rm -rf "$d/links" 2>&1 || true)
  [ ! -e "$d/links" ] || {
    echo "$label: one rm -rf pass left a directory of dangling links behind" >&2
    [ -n "$out" ] && echo "$out" | sed 's/^/    /' >&2
    ls -la "$d/links" | sed 's/^/    /' >&2
    exit 1
  }

  # And the individual cases behind it. Removing a symlink takes the LINK,
  # never what it names, and following loses in both directions: a live
  # link's target would be destroyed silently, a dangling one refuses the
  # operation outright.
  echo "must survive" > "$d/keep/realfile"
  echo "also survives" > "$d/keep/realdir/inside"
  ln -s nothing-here "$d/keep/danglink"
  ln -s realfile "$d/keep/livelink"
  ln -s realdir "$d/keep/dirlink"

  rm "$d/keep/danglink" || { echo "$label: rm of a DANGLING symlink failed" >&2; exit 1; }
  [ ! -L "$d/keep/danglink" ] || { echo "$label: the dangling symlink survived rm" >&2; exit 1; }

  rm "$d/keep/livelink" || { echo "$label: rm of a live symlink failed" >&2; exit 1; }
  [ -f "$d/keep/realfile" ] || { echo "$label: rm of a symlink deleted its TARGET" >&2; exit 1; }
  [ ! -L "$d/keep/livelink" ] || { echo "$label: rm reported success and left the symlink" >&2; exit 1; }

  rm "$d/keep/dirlink" || { echo "$label: rm of a symlink to a directory failed" >&2; exit 1; }
  [ -f "$d/keep/realdir/inside" ] || { echo "$label: rm of a symlink emptied the DIRECTORY it named" >&2; exit 1; }
  [ ! -L "$d/keep/dirlink" ] || { echo "$label: rm reported success and left the symlink to a directory" >&2; exit 1; }

  # A large directory: many READDIR round trips with unlinks landing
  # between them. `: >` is a builtin redirect, so this is one open per
  # entry and no forks.
  for i in $(seq 1 3000); do : > "$d/big/f$(printf %04d "$i")"; done
  n=$(ls -U "$d/big" | wc -l)
  [ "$n" = "3000" ] || { echo "$label: enumerating 3000 entries returned $n" >&2; exit 1; }
  out=$(rm -rf "$d/big" 2>&1 || true)
  [ ! -e "$d/big" ] || {
    n=$(ls -U "$d/big" | wc -l)
    echo "$label: one rm -rf pass left $n of 3000 entries behind" >&2
    [ -n "$out" ] && echo "$out" | sed 's/^/    /' >&2
    exit 1
  }

  # ENOTEMPTY still means ENOTEMPTY: the point is a directory that refuses
  # for the right reason, not one that never refuses.
  mkdir -p "$d/notempty" && : > "$d/notempty/child"
  if rmdir "$d/notempty" 2>/dev/null; then
    echo "$label: rmdir removed a non-empty directory" >&2; exit 1
  fi
  case "$(rmdir "$d/notempty" 2>&1 || true)" in
    *"not empty"*) : ;;
    *) echo "$label: rmdir of a non-empty directory reported: $(rmdir "$d/notempty" 2>&1 || true), want ENOTEMPTY" >&2; exit 1 ;;
  esac

  rm -rf "$d"
  [ ! -e "$d" ] || { echo "$label: the scratch tree would not go" >&2; ls -laR "$d" >&2; exit 1; }
  echo "$label: symlinks removed as links, 23 dangling links and 3000 entries each gone in ONE pass"
}

[ -e /dev/fuse ] || { echo "no /dev/fuse; a kernel mount needs FUSE" >&2; exit 1; }

# Binaries are either prebuilt (the container launcher cross-compiles on
# the host, since the test image has no toolchain) or built here.
if [ -n "${PELFS_PREBUILT:-}" ]; then
  echo "== using prebuilt binaries from $PELFS_PREBUILT =="
  cp "$PELFS_PREBUILT/pelfs" "$PELFS_PREBUILT/fakeorigin" "$WORK/"
else
  cd "$REPO"
  echo "== building pelfs and fakeorigin =="
  CGO_ENABLED=0 go build -o "$WORK/pelfs" ./cmd/pelfs
  CGO_ENABLED=0 go build -o "$WORK/fakeorigin" ./cmd/fakeorigin
fi

echo "== starting fakeorigin =="
mkdir -p "$WORK/origin" "$WORK/src" "$WORK/mnt" "$WORK/state"
"$WORK/fakeorigin" -listen 127.0.0.1:18999 -root "$WORK/origin" &
ORIGIN_PID=$!
for _ in $(seq 50); do
  curl -fsS "http://127.0.0.1:18999/" >/dev/null 2>&1 && break
  sleep 0.1
done
PREFIX="http://127.0.0.1:18999/vol"

echo "== building a source tree =="
mkdir -p "$WORK/src/dir/sub"
head -c 3145728 /dev/urandom > "$WORK/src/dir/big.bin"
echo "inline content" > "$WORK/src/dir/small.txt"
head -c 100000 /dev/urandom > "$WORK/src/dir/sub/mid.bin"
ln -s big.bin "$WORK/src/dir/link"
ln "$WORK/src/dir/big.bin" "$WORK/src/dir/hard.bin"

echo "== creating the volume and ingesting the tree through a writable mount =="
"$WORK/pelfs" init --state-dir "$WORK/state" "$PREFIX"
mkdir -p "$WORK/ingest"
"$WORK/pelfs" mount --rw --state-dir "$WORK/state" --no-lease \
  --snapshot-interval 0 "$PREFIX" "$WORK/ingest"
cp -R "$WORK/src/." "$WORK/ingest/"
# cp -R copies a hardlink as an independent file (and cp -a fails on
# backends without xattr support), so make the link inside the mount —
# the point is to publish an inode with nlink > 1.
rm "$WORK/ingest/dir/hard.bin"
ln "$WORK/ingest/dir/big.bin" "$WORK/ingest/dir/hard.bin"

echo "== publishing the ingested tree through the control socket =="
"$WORK/pelfs" ctl "$PREFIX" publish
"$WORK/pelfs" umount "$PREFIX"

echo "== mounting the published generation (catalog-native) =="
"$WORK/pelfs" mount-gen --state-dir "$WORK/state2" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 100); do
  [ -e "$WORK/mnt/dir/small.txt" ] && break
  sleep 0.1
done
[ -e "$WORK/mnt/dir/small.txt" ] || { echo "mount did not come up" >&2; exit 1; }

echo "== verifying the mounted tree against the source =="
diff -r --no-dereference "$WORK/src" "$WORK/mnt"
echo "tree matches"

# Metadata the diff does not cover.
[ -L "$WORK/mnt/dir/link" ] || { echo "symlink lost its type" >&2; exit 1; }
links=$(stat -c %h "$WORK/mnt/dir/big.bin")
[ "$links" -ge 2 ] || { echo "hardlink count is $links, want >= 2" >&2; exit 1; }
echo "symlink + hardlink metadata preserved"

# Read-only enforcement: a mount without --rw refuses writes.
if touch "$WORK/mnt/should-fail" 2>/dev/null; then
  echo "read-only mount accepted a write" >&2
  exit 1
fi
echo "read-only enforced"

echo "== read-write round trip: mount --rw, modify, seal, verify =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

"$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 100); do [ -e "$WORK/mnt/dir/small.txt" ] && break; sleep 0.1; done
[ -e "$WORK/mnt/dir/small.txt" ] || { echo "rw mount did not come up" >&2; exit 1; }

echo "sealed write" > "$WORK/mnt/dir/written.txt"
mkdir -p "$WORK/mnt/newdir"
rm "$WORK/mnt/dir/small.txt"
echo "appended" >> "$WORK/mnt/dir/sub/mid.bin"
[ -f "$WORK/mnt/dir/written.txt" ] || { echo "write not visible in the mount" >&2; exit 1; }

# SPARSE FILES, made with the syscalls rather than through an API. A
# file's LENGTH can run past its last written byte, and a catalog cannot
# say that: its chunk lengths must account for exactly the node's length
# or no reader will open the file ("chunk lengths sum to X, node length is
# Y"). Both ways a program makes one are here:
#
#   - seek past the end and write, which is also what an NFS client
#     produces on its own when it flushes a write train out of order;
#   - grow the file with truncate(1), which sets a length with no bytes
#     behind it at all.
#
# The mount answered both correctly all along — the gap reads as zeros —
# so this belongs where it is CHECKED: against the sealed generation
# below, which is the only place the two representations have to meet.
dd if=/dev/urandom of="$WORK/mnt/sparse-seek.bin" bs=16384 count=1 status=none
dd if=/dev/urandom of="$WORK/mnt/sparse-seek.bin" bs=16384 count=1 seek=2 \
   conv=notrunc status=none
dd if=/dev/urandom of="$WORK/mnt/sparse-tail.bin" bs=16384 count=1 status=none
truncate -s 49152 "$WORK/mnt/sparse-tail.bin"
for f in sparse-seek.bin sparse-tail.bin; do
  [ "$(stat -c %s "$WORK/mnt/$f")" = "49152" ] || {
    echo "$f is $(stat -c %s "$WORK/mnt/$f") bytes in the live mount, want 49152" >&2; exit 1; }
  cp "$WORK/mnt/$f" "$WORK/src/$f"
done

# Unmount seals the overlay into generation 1.
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

echo "== remounting the SEALED generation read-only =="
"$WORK/pelfs" mount-gen --state-dir "$WORK/state4" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 100); do [ -e "$WORK/mnt/dir/written.txt" ] && break; sleep 0.1; done
grep -q "sealed write" "$WORK/mnt/dir/written.txt" || { echo "sealed write missing" >&2; exit 1; }
[ -d "$WORK/mnt/newdir" ] || { echo "sealed mkdir missing" >&2; exit 1; }
[ ! -e "$WORK/mnt/dir/small.txt" ] || { echo "sealed deletion did not stick" >&2; exit 1; }
cmp "$WORK/src/dir/big.bin" "$WORK/mnt/dir/big.bin"
# The sparse pair, read back from the generation rather than from the
# overlay that made them. A short chunk list fails the LENGTH check here
# before cmp ever runs, which is what the sighting looked like.
for f in sparse-seek.bin sparse-tail.bin; do
  [ -e "$WORK/mnt/$f" ] || { echo "$f did not survive the seal" >&2; exit 1; }
  [ "$(stat -c %s "$WORK/mnt/$f")" = "49152" ] || {
    echo "$f is $(stat -c %s "$WORK/mnt/$f") bytes in the sealed generation, want 49152" >&2; exit 1; }
  cmp "$WORK/src/$f" "$WORK/mnt/$f" || { echo "$f does not read back from the sealed generation" >&2; exit 1; }
done
echo "seal round trip verified: writes, mkdir, deletion, sparse files, untouched content"

echo "== subshell workflow: pelfs shell, catalog-native =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true
cat > "$WORK/in-shell.sh" <<'INNER'
set -e
echo "written from the subshell" > shell-made.txt
mkdir -p shell-dir
INNER
SHELL=/bin/sh "$WORK/pelfs" mount-gen --rw --subshell --shell /bin/sh \
  --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" < "$WORK/in-shell.sh" > "$WORK/shell.log" 2>&1 || true
grep -q "sealed generation" "$WORK/shell.log" || { echo "subshell exit did not seal:" >&2; sed 's/^/    /' "$WORK/shell.log" | tail -5; exit 1; }

"$WORK/pelfs" mount-gen --state-dir "$WORK/state10" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/shell-made.txt" ] && break; sleep 0.1; done
grep -q "written from the subshell" "$WORK/mnt/shell-made.txt" || { echo "subshell write did not survive the seal" >&2; exit 1; }
[ -d "$WORK/mnt/shell-dir" ] || { echo "subshell mkdir did not survive" >&2; exit 1; }
echo "subshell workflow verified: work in a shell, exit, changes sealed into the next generation"

echo "== non-interactive form: mount-gen --rw -- <command> =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

# The command runs IN the mount, its writes are sealed on the way out, and
# its exit status is the one pelfs exits with — the property scripts branch
# on. Note this needs NO --subshell: a `--` tail implies it.
set +e
"$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" \
  -- /bin/sh -c 'pwd > cmd-cwd.txt; echo "$PELFS_MOUNT" >> cmd-cwd.txt; echo "written by -- command" > cmd-made.txt; exit 0' \
  > "$WORK/cmd0.log" 2>&1
rc=$?
set -e
[ "$rc" = "0" ] || { echo "successful command exited $rc, want 0:" >&2; sed 's/^/    /' "$WORK/cmd0.log"; exit 1; }
grep -q "sealed generation" "$WORK/cmd0.log" || { echo "the command form did not seal on the way out:" >&2; sed 's/^/    /' "$WORK/cmd0.log"; exit 1; }

# A FAILING command must still get its teardown, and still propagate.
set +e
"$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" \
  -- /bin/sh -c 'echo "written by a failing command" > cmd-failed.txt; exit 42' \
  > "$WORK/cmd42.log" 2>&1
rc=$?
set -e
[ "$rc" = "42" ] || { echo "failing command exited $rc, want 42:" >&2; sed 's/^/    /' "$WORK/cmd42.log"; exit 1; }
grep -q "sealed generation" "$WORK/cmd42.log" || { echo "a failing command skipped the seal:" >&2; sed 's/^/    /' "$WORK/cmd42.log"; exit 1; }

"$WORK/pelfs" mount-gen --state-dir "$WORK/state11" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/cmd-failed.txt" ] && break; sleep 0.1; done
grep -q "written by -- command" "$WORK/mnt/cmd-made.txt" || { echo "the command's writes did not survive the seal" >&2; exit 1; }
grep -q "written by a failing command" "$WORK/mnt/cmd-failed.txt" || { echo "a failing command's writes were not sealed" >&2; exit 1; }
# The command ran with the mount as its cwd and saw the session environment.
grep -qx "$WORK/mnt" "$WORK/mnt/cmd-cwd.txt" || { echo "the command did not run in the mount:" >&2; cat "$WORK/mnt/cmd-cwd.txt"; exit 1; }
echo "-- command verified: runs in the mount, seals on exit, status propagates (0 and 42)"

echo "== SIGINT to the foreground process group (Ctrl+C) =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

# A terminal sends Ctrl+C to the whole foreground process GROUP: pelfs and
# its payload both get it. pelfs must not act on it — the payload owns the
# terminal — but must still tear the mount down once the payload dies.
# `set -m` gives the background job its own process group, which is what
# makes signalling a group here safe (and what a tty would give it).
rm -f "$WORK/sigint-ready"
set -m
"$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" \
  -- /bin/sh -c "echo ready > $WORK/sigint-ready; sleep 60" > "$WORK/sigint.log" 2>&1 &
SIGINT_PID=$!
set +m
for _ in $(seq 300); do [ -e "$WORK/sigint-ready" ] && break; sleep 0.1; done
[ -e "$WORK/sigint-ready" ] || { echo "the interrupt payload never started:" >&2; sed 's/^/    /' "$WORK/sigint.log"; exit 1; }
PGID=$(ps -o pgid= -p "$SIGINT_PID" | tr -d ' ')
[ "$PGID" != "$(ps -o pgid= -p $$ | tr -d ' ')" ] || { echo "the mount shares this script's process group; refusing to signal it" >&2; exit 1; }
kill -INT "-$PGID"
set +e
wait "$SIGINT_PID"
rc=$?
set -e
[ "$rc" = "130" ] || { echo "interrupted command exited $rc, want 130:" >&2; sed 's/^/    /' "$WORK/sigint.log"; exit 1; }
grep -q "nothing changed\|sealed generation" "$WORK/sigint.log" || {
  echo "Ctrl+C tore the mount down without reaching the seal:" >&2; sed 's/^/    /' "$WORK/sigint.log"; exit 1; }
if mountpoint -q "$WORK/mnt" 2>/dev/null; then echo "the mount survived teardown" >&2; exit 1; fi
echo "Ctrl+C verified: payload interrupted (130), pelfs completed its teardown"

echo "== when publication happened: the phase split, from a session's own output =="
# The question this answers is the user's, not ours: "did any of my data
# go out while I was working, or was it all saved for the exit?" Both
# runs below have to answer it from the log and the stats file alone.
#
# Case 1: no cadence, so the ONLY seal is at unmount. The session phase
# must show zero uploaded bytes and teardown must show the payload.
phase_status=0
"$WORK/pelfs" mount-gen --rw --snapshot-interval 0 \
  --stats-file "$WORK/phase-exit.json" --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" \
  -- /bin/sh -c 'head -c 4000000 /dev/urandom > exit-sealed.bin' \
  > "$WORK/phase-exit.log" 2>&1 || phase_status=$?
[ "$phase_status" = "0" ] || { echo "exit-seal session failed ($phase_status):" >&2; sed 's/^/    /' "$WORK/phase-exit.log"; exit 1; }
grep -q "publishing: the first pack is on the wire" "$WORK/phase-exit.log" || {
  echo "the session never announced that publication had started:" >&2
  sed 's/^/    /' "$WORK/phase-exit.log"; exit 1; }
grep -q "first pack on the wire" "$WORK/phase-exit.log" || {
  echo "the seal cost line does not say when the uploads began:" >&2
  sed 's/^/    /' "$WORK/phase-exit.log"; exit 1; }
# The log this reads is redirected, so it is the stamped prose format: the
# numbers are in the sentence, not in a tail of key=value fields.
grep -Eq "uploaded 0 B during the session and [1-9][0-9.]* [KMG]iB after it exited \(0 seals while mounted, 1 seal at exit\)" "$WORK/phase-exit.log" || {
  echo "the phase split does not show an exit-only seal:" >&2
  grep "during the session and" "$WORK/phase-exit.log" | sed 's/^/    /'; exit 1; }
# The same answer survives in the file a supervisor reads afterwards:
# session_phase carries no put bytes at all (the key is omitted when zero)
# and teardown_phase carries them.
flat=$(tr -d ' \n' < "$WORK/phase-exit.json")
echo "$flat" | grep -q '"pelfs_stats_version":2' || { echo "stats file is not version 2" >&2; exit 1; }
echo "$flat" | grep -Eq '"session_phase":\{"get":\{[^}]*\},"put":\{"ops":[0-9]+,"errors":0\},' || {
  echo "session_phase reports uploaded bytes for a session that sealed only at exit:" >&2
  echo "$flat" | sed 's/^/    /'; exit 1; }
echo "$flat" | grep -Eq '"teardown_phase":\{"get":\{[^}]*\},"put":\{"ops":[0-9]+,"errors":0,"bytes":[1-9]' || {
  echo "teardown_phase reports no uploaded bytes though the exit seal published:" >&2
  echo "$flat" | sed 's/^/    /'; exit 1; }

# Case 2: a cadence short enough to fire while the payload is still
# running. The same two numbers must now come out the other way round.
#
# The payload WAITS FOR THE CHECKPOINT rather than sleeping a fixed six
# seconds. The old form raced: a checkpoint here costs 0.5-1.2s of
# publish, but on a loaded machine — another gate running, a fuzzer
# saturating the CPU — it stretches past 4s, and if it has not COMPLETED
# when the payload exits the session reads "0 seals while mounted" and
# the gate fails on a machine rather than on a defect. Waiting for the
# event it is actually asserting makes it deterministic, and faster in
# the common case than the sleep it replaces.
phase_status=0
"$WORK/pelfs" mount-gen --rw --snapshot-interval 1s \
  --stats-file "$WORK/phase-ckpt.json" --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" \
  -- /bin/sh -c "head -c 4000000 /dev/urandom > checkpointed.bin; \
    for _ in \$(seq 300); do grep -q 'checkpoint: sealed generatio[n]' '$WORK/phase-ckpt.log' && break; sleep 0.1; done" \
  > "$WORK/phase-ckpt.log" 2>&1 || phase_status=$?
[ "$phase_status" = "0" ] || { echo "checkpointing session failed ($phase_status):" >&2; sed 's/^/    /' "$WORK/phase-ckpt.log"; exit 1; }
grep -q "checkpoint started: publishing what this session has written so far" "$WORK/phase-ckpt.log" || {
  echo "a mid-session checkpoint never announced itself:" >&2
  sed 's/^/    /' "$WORK/phase-ckpt.log"; exit 1; }
grep -Eq "uploaded [1-9][0-9.]* [KMG]iB during the session and .*\([1-9][0-9]* seals? while mounted" "$WORK/phase-ckpt.log" || {
  echo "a checkpointed session did not credit its uploads to the session phase:" >&2
  grep "during the session and" "$WORK/phase-ckpt.log" | sed 's/^/    /'; exit 1; }
# Print the lines a user would actually read. Half of what is being
# gated here is that they stay legible, which no grep can assert.
#
# The seal-cost and phase-breakdown lines go out too, because this is the
# only place in the gate where a CHECKPOINT's cost is visible at all. A
# checkpoint publishes while the user is still working, so where its time
# goes — freeze against publish — is the number that decides whether the
# mount goes unresponsive, and it belongs in the transcript of every run
# rather than only in the wreckage of a failing one.
grep -h "publishing: the first pack\|checkpoint started\|during the session and\|seal took\|sealed in " \
  "$WORK/phase-exit.log" "$WORK/phase-ckpt.log" | sed 's/^/    /'
echo "phase split verified: exit-only seal reads 0 during the session; a checkpoint reads the reverse"

# Every log in this gate is a redirected one, which is exactly the case a
# person hits with `pelfs mount 2>>pelfs.log`. A {placeholder} reaching one
# of them means the sentence was left for the reader to reassemble.
leaked=$(grep -lE '\{[a-z][a-z_]*\}' "$WORK"/*.log 2>/dev/null || true)
[ -z "$leaked" ] || {
  echo "a redirected log carries an unexpanded placeholder:" >&2
  grep -hE '\{[a-z][a-z_]*\}' $leaked | sed 's/^/    /' >&2; exit 1; }

"$WORK/pelfs" mount-gen --state-dir "$WORK/state12" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/cmd-made.txt" ] && break; sleep 0.1; done

echo "== pelfs shell on an EMPTY prefix creates a volume =="
"$WORK/fakeorigin" -listen 127.0.0.1:18998 -root "$WORK/origin2" &
ORIGIN2_PID=$!
mkdir -p "$WORK/origin2"
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:18998/" >/dev/null 2>&1 && break; sleep 0.1; done
NEWPREFIX="http://127.0.0.1:18998/fresh"
# `set -e` aborts the script the moment this command fails, so capturing
# $? on the next line never runs and CI reports a bare "exit 1" with no
# reason. Take the status inline instead.
fresh_status=0
"$WORK/pelfs" shell --state-dir "$WORK/state-fresh" "$NEWPREFIX" -- \
  sh -c 'echo hello > greeting.txt; mkdir -p sub' > "$WORK/fresh.log" 2>&1 || fresh_status=$?
[ "$fresh_status" = "0" ] || { echo "shell on empty prefix failed ($fresh_status):" >&2; sed 's/^/    /' "$WORK/fresh.log" | tail -8; exit 1; }
grep -q "created volume" "$WORK/fresh.log" || { echo "shell did not CREATE a volume:" >&2; sed 's/^/    /' "$WORK/fresh.log" | tail -8; exit 1; }
grep -q "catalog-native" "$WORK/fresh.log" || { echo "new volume was not served natively:" >&2; sed 's/^/    /' "$WORK/fresh.log" | tail -8; exit 1; }
# The federation must hold refs + packs and nothing else of substance.
[ -f "$WORK/origin2/fresh/refs/main" ] || { echo "no ref created" >&2; ls -R "$WORK/origin2" | head; exit 1; }
# meta/ may exist for the advisory write leases (meta/lease-<branch>.json,
# one per branch, plus v0.1.0's meta/lease.json on an old volume); nothing
# else belongs under it. A stray object here is not untidiness — it is what
# `pelfs shell` reads as a retired block-and-snapshot volume, and it makes
# the prefix refuse to mount.
if [ -d "$WORK/origin2/fresh/meta" ]; then
  extra=$(ls -A "$WORK/origin2/fresh/meta" | grep -Ev '^lease(-.*)?\.json$' || true)
  [ -z "$extra" ] || { echo "unexpected metadata objects appeared: $extra" >&2; exit 1; }
fi
"$WORK/pelfs" mount-gen --state-dir "$WORK/state-fresh2" "$NEWPREFIX" "$WORK/mnt2" &
FRESH_PID=$!
mkdir -p "$WORK/mnt2"
for _ in $(seq 200); do [ -e "$WORK/mnt2/greeting.txt" ] && break; sleep 0.1; done
grep -q hello "$WORK/mnt2/greeting.txt" || { echo "fresh-volume write did not survive" >&2; exit 1; }
unmount_at "$WORK/mnt2"; wait "$FRESH_PID" 2>/dev/null || true
kill "$ORIGIN2_PID" 2>/dev/null || true
echo "empty-prefix verified: volume created, content sealed and re-readable"

echo "== pelfs shell serves an existing volume =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true
"$WORK/pelfs" shell --state-dir "$WORK/state" "$PREFIX" -- \
  sh -c 'echo "written by pelfs shell" > from-shell.txt; ls dir/big.bin >/dev/null' \
  > "$WORK/shell-native.log" 2>&1
shell_status=$?
[ "$shell_status" = "0" ] || { echo "pelfs shell failed ($shell_status):" >&2; sed 's/^/    /' "$WORK/shell-native.log" | tail -8; exit 1; }
grep -q "catalog-native" "$WORK/shell-native.log" || {
  echo "pelfs shell did NOT mount the volume:" >&2
  sed 's/^/    /' "$WORK/shell-native.log" | tail -8; exit 1; }
grep -q "sealed generation" "$WORK/shell-native.log" || {
  echo "pelfs shell did not seal on exit:" >&2; sed 's/^/    /' "$WORK/shell-native.log" | tail -8; exit 1; }

# The write must be in the next generation, readable by a fresh mount.
"$WORK/pelfs" mount-gen --state-dir "$WORK/state11" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/from-shell.txt" ] && break; sleep 0.1; done
grep -q "written by pelfs shell" "$WORK/mnt/from-shell.txt" || { echo "shell write did not survive the seal" >&2; exit 1; }
echo "pelfs shell verified: mounted, sealed on exit, write survives"

echo "== strict prefetch: everything local before serving =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true
"$WORK/pelfs" mount-gen --prefetch all --state-dir "$WORK/state9" "$PREFIX" "$WORK/mnt" 2>"$WORK/pf.log" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/dir/big.bin" ] && break; sleep 0.1; done
[ -e "$WORK/mnt/dir/big.bin" ] || { echo "prefetch mount did not come up" >&2; sed 's/^/    /' "$WORK/pf.log"; exit 1; }
grep -q "prefetched" "$WORK/pf.log" || { echo "no prefetch report" >&2; sed 's/^/    /' "$WORK/pf.log"; exit 1; }
sed -n 's/^/    /p' "$WORK/pf.log" | grep prefetched
cmp "$WORK/src/dir/big.bin" "$WORK/mnt/dir/big.bin"
echo "strict prefetch verified: generation warmed, content byte-exact"

echo "== NFS backend: the same stack, no FUSE in the data path =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true
# No soft skip here. This script already refuses to run anywhere but
# Linux, and the NFS backend is not a curiosity: it is the mount a macOS
# box without macFUSE gets, so it is the path the project is developed on.
#
# The old guard asked `command -v mount.nfs || command -v mount`, and
# /bin/mount exists in every image ever built — so the condition was
# always true, the real requirement (mount.nfs, from nfs-common) went
# unchecked, and when the client was absent the mount simply failed to
# come up and the leg printed a note and PASSED. A gate that reports
# success when it tested nothing is worse than no gate at all.
command -v mount.nfs >/dev/null 2>&1 || {
  echo "no mount.nfs on this host: the NFS leg needs a kernel NFS client" >&2
  echo "(Debian/Ubuntu: nfs-common). scripts/mount-gate-docker.sh builds" >&2
  echo "an image that has one — run the gate through that." >&2
  exit 1
}
mkdir -p "$WORK/nfsmnt"
"$WORK/pelfs" mount-gen --backend nfs --state-dir "$WORK/state8" "$PREFIX" "$WORK/nfsmnt" 2>"$WORK/nfs.log" &
NFS_PID=$!
up=0
for _ in $(seq 100); do
  [ -e "$WORK/nfsmnt/dir/written.txt" ] && { up=1; break; }
  # A server that has already exited will never come up: say so now rather
  # than after ten more seconds of polling a dead process.
  kill -0 "$NFS_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$up" = "1" ] || {
  echo "NFS backend did not come up:" >&2
  sed 's/^/    /' "$WORK/nfs.log" >&2
  kill "$NFS_PID" 2>/dev/null || true
  exit 1
}
grep -q "sealed write" "$WORK/nfsmnt/dir/written.txt"
cmp "$WORK/src/dir/big.bin" "$WORK/nfsmnt/dir/big.bin"
# The sparse pair through the OS NFS client, which is the backend a macOS
# box without macFUSE gets and the one the sighting came from.
for f in sparse-seek.bin sparse-tail.bin; do
  cmp "$WORK/src/$f" "$WORK/nfsmnt/$f" || { echo "$f does not read back over NFS" >&2; exit 1; }
done
echo "NFS backend verified: content byte-exact through the OS NFS client"
unmount_at "$WORK/nfsmnt"
kill "$NFS_PID" 2>/dev/null || true
wait "$NFS_PID" 2>/dev/null || true
NFS_PID=

echo "== deletion: rm -rf empties a directory in ONE pass, on BOTH backends =="
# NFS first. It is where the defect was found, and the only backend whose
# REMOVE goes through a protocol handler that can form its own opinion
# about what the name resolves to.
"$WORK/pelfs" mount-gen --rw --no-seal --backend nfs --state-dir "$WORK/state-del-nfs" \
  "$PREFIX" "$WORK/nfsmnt" 2>"$WORK/nfs-del.log" &
NFS_PID=$!
up=0
for _ in $(seq 100); do
  [ -d "$WORK/nfsmnt/dir" ] && { up=1; break; }
  kill -0 "$NFS_PID" 2>/dev/null || break
  sleep 0.1
done
[ "$up" = "1" ] || {
  echo "the writable NFS mount did not come up:" >&2
  sed 's/^/    /' "$WORK/nfs-del.log" >&2
  exit 1
}
deletion_gate "nfs" "$WORK/nfsmnt"
unmount_at "$WORK/nfsmnt"
kill "$NFS_PID" 2>/dev/null || true
wait "$NFS_PID" 2>/dev/null || true
NFS_PID=

# And FUSE, which unlinks by (parent inode, name) and never resolves a
# path at all — so it ought to be immune to the symlink half by
# construction. This leg is what turns "ought to be" into a fact, and what
# says which layer a future regression is in.
"$WORK/pelfs" mount-gen --rw --no-seal --state-dir "$WORK/state-del-fuse" \
  "$PREFIX" "$WORK/mnt" 2>"$WORK/fuse-del.log" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -d "$WORK/mnt/dir" ] && break; sleep 0.1; done
[ -d "$WORK/mnt/dir" ] || {
  echo "the writable FUSE mount did not come up:" >&2
  sed 's/^/    /' "$WORK/fuse-del.log" >&2
  exit 1
}
deletion_gate "fuse" "$WORK/mnt"

echo "== live refresh: a read-only mount follows the branch =="
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

"$WORK/pelfs" mount-gen --poll 1s --state-dir "$WORK/state6" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 100); do [ -e "$WORK/mnt/dir/written.txt" ] && break; sleep 0.1; done
[ -e "$WORK/mnt/dir/written.txt" ] || { echo "polling mount did not come up" >&2; exit 1; }
# Read it once so the kernel caches the inode: the swap must invalidate it.
cat "$WORK/mnt/dir/written.txt" > /dev/null
[ ! -e "$WORK/mnt/live.txt" ] || { echo "live.txt exists before it was published" >&2; exit 1; }

# A SECOND, independent writer publishes a new generation.
"$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/writer" &
WRITER_PID=$!
mkdir -p "$WORK/writer"
for _ in $(seq 100); do [ -d "$WORK/writer/dir" ] && break; sleep 0.1; done
echo "published while mounted" > "$WORK/writer/live.txt"
echo "changed by the other writer" > "$WORK/writer/dir/written.txt"
unmount_at "$WORK/writer"
wait "$WRITER_PID" 2>/dev/null || true

# The reader must pick it up WITHOUT remounting.
found=0
for _ in $(seq 60); do
  if [ -e "$WORK/mnt/live.txt" ] && grep -q "changed by the other writer" "$WORK/mnt/dir/written.txt" 2>/dev/null; then
    found=1; break
  fi
  sleep 0.5
done
[ "$found" = "1" ] || { echo "read-only mount did not pick up the new generation" >&2; ls "$WORK/mnt"; exit 1; }
grep -q "published while mounted" "$WORK/mnt/live.txt"
echo "live refresh verified: new file appeared and changed content updated, no remount"

if [ "$BENCH" = "--bench" ]; then
  echo "== end-to-end benchmarks on a real kernel =="
  unmount_at "$WORK/mnt"
  wait "$MOUNT_PID" 2>/dev/null || true

  # Writable mount, so the workload can untar and delete like a real one.
  "$WORK/pelfs" mount-gen --rw --no-seal --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" &
  MOUNT_PID=$!
  for _ in $(seq 100); do [ -d "$WORK/mnt/dir" ] && break; sleep 0.1; done
  [ -d "$WORK/mnt/dir" ] || { echo "bench mount did not come up" >&2; exit 1; }

  bench() { # bench <label> <cmd...>
    local label="$1"; shift
    local start end
    start=$(date +%s.%N)
    "$@" >/dev/null 2>&1 || true
    end=$(date +%s.%N)
    awk -v l="$label" -v s="$start" -v e="$end" 'BEGIN{printf "  %-22s %7.2fs\n", l, e-s}'
  }

  echo "  building a 2000-file corpus..."
  mkdir -p "$WORK/corpus"
  for d in $(seq 0 39); do
    mkdir -p "$WORK/corpus/d$d"
    for f in $(seq 0 49); do
      head -c $(( (d * 50 + f) % 6000 + 300 )) /dev/urandom > "$WORK/corpus/d$d/f$f.bin"
    done
  done
  tar -C "$WORK" -cf "$WORK/corpus.tar" corpus

  echo "  A. WRITABLE mount (overlay; every inode dirty => zero TTLs):"
  bench "untar 2000 files"   tar -C "$WORK/mnt" -xf "$WORK/corpus.tar"
  bench "stat walk (cold)"   find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "stat walk (again)"  find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "read all"           tar -C "$WORK/mnt" -cf /dev/null corpus

  # Seal the corpus, then serve it read-only: now every inode is CLEAN and
  # immutable, so the binding hands the kernel infinite TTLs. The gap
  # between these two stat walks IS the immutability dividend.
  echo "  sealing the corpus into the next generation..."
  unmount_at "$WORK/mnt"
  wait "$MOUNT_PID" 2>/dev/null || true
  "$WORK/pelfs" mount-gen --rw --state-dir "$WORK/state" "$PREFIX" "$WORK/mnt" >/dev/null 2>&1 &
  MOUNT_PID=$!
  for _ in $(seq 200); do [ -d "$WORK/mnt/corpus" ] && break; sleep 0.1; done
  unmount_at "$WORK/mnt"
  wait "$MOUNT_PID" 2>/dev/null || true

  "$WORK/pelfs" mount-gen --state-dir "$WORK/state5" "$PREFIX" "$WORK/mnt" >/dev/null 2>&1 &
  MOUNT_PID=$!
  for _ in $(seq 200); do [ -d "$WORK/mnt/corpus" ] && break; sleep 0.1; done
  [ -d "$WORK/mnt/corpus" ] || { echo "sealed corpus mount did not come up" >&2; exit 1; }

  echo "  B. READ-ONLY mount of the sealed generation (clean => infinite TTLs):"
  bench "stat walk (cold)"   find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "stat walk (warm)"   find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "read all"           tar -C "$WORK/mnt" -cf /dev/null corpus
  bench "read all (warm)"    tar -C "$WORK/mnt" -cf /dev/null corpus

  # C is the common real case: a WRITABLE mount over a large tree whose
  # content is almost entirely clean. Every lookup asks "is this inode
  # dirty?" to pick a TTL, so this is where that answer's cost shows.
  echo "  C. WRITABLE mount over the sealed (clean) corpus:"
  unmount_at "$WORK/mnt"
  wait "$MOUNT_PID" 2>/dev/null || true
  "$WORK/pelfs" mount-gen --rw --no-seal --state-dir "$WORK/state7" "$PREFIX" "$WORK/mnt" >/dev/null 2>&1 &
  MOUNT_PID=$!
  for _ in $(seq 200); do [ -d "$WORK/mnt/corpus" ] && break; sleep 0.1; done
  [ -d "$WORK/mnt/corpus" ] || { echo "clean-writable mount did not come up" >&2; exit 1; }
  bench "stat walk (cold)"   find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "stat walk (warm)"   find "$WORK/mnt/corpus" -type f -exec stat -c%s {} +
  bench "read all"           tar -C "$WORK/mnt" -cf /dev/null corpus

  echo "  local disk baseline (same workload):"
  mkdir -p "$WORK/baseline"
  bench "untar 2000 files"   tar -C "$WORK/baseline" -xf "$WORK/corpus.tar"
  bench "stat walk"          find "$WORK/baseline/corpus" -type f -exec stat -c%s {} +
  bench "read all"           tar -C "$WORK/baseline" -cf /dev/null corpus
  bench "rm -rf"             rm -rf "$WORK/baseline/corpus"
fi

echo "== PASS: catalog-native mount verified =="
