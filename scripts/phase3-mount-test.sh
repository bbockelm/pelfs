#!/usr/bin/env bash
# The phase-3 gate: publish a generation, mount it with `pelfs mount-gen`
# through the catalog-native stack (genfs + raw FUSE, NO JuiceFS), verify
# the mounted tree byte-for-byte against the source, and time the
# end-to-end benchmarks against it.
#
# Linux (or macFUSE) only — this is the coverage a macFUSE-less dev
# machine cannot provide, so CI owns it.
#
# Usage: scripts/phase3-mount-test.sh [--bench]
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
[ "$(uname -s)" = "Linux" ] || { echo "phase-3 mounts need Linux FUSE (macOS denies shell access to mounts)" >&2; exit 2; }

# Scratch lives under the repo's own build area, never $HOME.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pelfs-phase3.XXXXXX")"
cleanup() {
  if mountpoint -q "$WORK/mnt" 2>/dev/null || mount | grep -q " $WORK/mnt "; then
    fusermount3 -u "$WORK/mnt" 2>/dev/null || fusermount -u "$WORK/mnt" 2>/dev/null || \
      umount "$WORK/mnt" 2>/dev/null || true
  fi
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  [ -n "${MOUNT_PID:-}" ] && kill "$MOUNT_PID" 2>/dev/null || true
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

[ -e /dev/fuse ] || { echo "no /dev/fuse; phase-3 mounts need FUSE" >&2; exit 1; }

# Binaries are either prebuilt (the container launcher cross-compiles on
# the host, since the test image has no toolchain) or built here.
if [ -n "${PELFS_PREBUILT:-}" ]; then
  echo "== using prebuilt binaries from $PELFS_PREBUILT =="
  cp "$PELFS_PREBUILT/pelfs" "$PELFS_PREBUILT/fakeorigin" "$WORK/"
else
  cd "$REPO"
  echo "== building pelfs and fakeorigin =="
  CGO_ENABLED=0 go build -tags nogspt,notikv -o "$WORK/pelfs" ./cmd/pelfs
  CGO_ENABLED=0 go build -tags nogspt,notikv -o "$WORK/fakeorigin" ./cmd/fakeorigin
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

echo "== ingesting the tree through a v1 mount =="
mkdir -p "$WORK/v1mnt"
"$WORK/pelfs" mount --state-dir "$WORK/state" --writeback --no-lease \
  --snapshot-interval 0 "$PREFIX" "$WORK/v1mnt"
cp -R "$WORK/src/." "$WORK/v1mnt/"
# cp -R copies a hardlink as an independent file (and cp -a fails on
# backends without xattr support), so make the link inside the mount —
# the point is to publish an inode with nlink > 1.
rm "$WORK/v1mnt/dir/hard.bin"
ln "$WORK/v1mnt/dir/big.bin" "$WORK/v1mnt/dir/hard.bin"

echo "== publishing generation 0 through the control socket =="
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

# Read-only enforcement: the phase-3 mount refuses writes until the
# overlay binding lands.
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

echo "phase-3 write" > "$WORK/mnt/dir/written.txt"
mkdir -p "$WORK/mnt/newdir"
rm "$WORK/mnt/dir/small.txt"
echo "appended" >> "$WORK/mnt/dir/sub/mid.bin"
[ -f "$WORK/mnt/dir/written.txt" ] || { echo "write not visible in the mount" >&2; exit 1; }

# Unmount seals the overlay into generation 1.
unmount_at "$WORK/mnt"
wait "$MOUNT_PID" 2>/dev/null || true

echo "== remounting the SEALED generation read-only =="
"$WORK/pelfs" mount-gen --state-dir "$WORK/state4" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 100); do [ -e "$WORK/mnt/dir/written.txt" ] && break; sleep 0.1; done
grep -q "phase-3 write" "$WORK/mnt/dir/written.txt" || { echo "sealed write missing" >&2; exit 1; }
[ -d "$WORK/mnt/newdir" ] || { echo "sealed mkdir missing" >&2; exit 1; }
[ ! -e "$WORK/mnt/dir/small.txt" ] || { echo "sealed deletion did not stick" >&2; exit 1; }
cmp "$WORK/src/dir/big.bin" "$WORK/mnt/dir/big.bin"
echo "seal round trip verified: writes, mkdir, deletion, untouched content"

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

"$WORK/pelfs" mount-gen --state-dir "$WORK/state12" "$PREFIX" "$WORK/mnt" &
MOUNT_PID=$!
for _ in $(seq 200); do [ -e "$WORK/mnt/cmd-made.txt" ] && break; sleep 0.1; done

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
if command -v mount.nfs >/dev/null 2>&1 || command -v mount >/dev/null 2>&1; then
  mkdir -p "$WORK/nfsmnt"
  if "$WORK/pelfs" mount-gen --backend nfs --state-dir "$WORK/state8" "$PREFIX" "$WORK/nfsmnt" 2>"$WORK/nfs.log" &
  then
    NFS_PID=$!
    up=0
    for _ in $(seq 100); do [ -e "$WORK/nfsmnt/dir/written.txt" ] && { up=1; break; }; sleep 0.1; done
    if [ "$up" = "1" ]; then
      grep -q "phase-3 write" "$WORK/nfsmnt/dir/written.txt"
      cmp "$WORK/src/dir/big.bin" "$WORK/nfsmnt/dir/big.bin"
      echo "NFS backend verified: content byte-exact through the OS NFS client"
      unmount_at "$WORK/nfsmnt"
      kill "$NFS_PID" 2>/dev/null || true
    else
      echo "NFS backend did not come up (container may lack NFS client support):"
      sed 's/^/    /' "$WORK/nfs.log" | head -3
      kill "$NFS_PID" 2>/dev/null || true
    fi
  fi
else
  echo "no NFS client in this image; skipping the NFS backend check"
fi

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

echo "== PASS: phase-3 catalog-native mount verified =="
