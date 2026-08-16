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

[ -e /dev/fuse ] || { echo "no /dev/fuse; phase-3 mounts need FUSE" >&2; exit 1; }

cd "$REPO"
echo "== building pelfs and fakeorigin =="
CGO_ENABLED=0 go build -tags nogspt,notikv -o "$WORK/pelfs" ./cmd/pelfs
CGO_ENABLED=0 go build -tags nogspt,notikv -o "$WORK/fakeorigin" ./cmd/fakeorigin

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

if [ "$BENCH" = "--bench" ]; then
  echo "== end-to-end benchmarks against the phase-3 mount (read-only subset) =="
  time (find "$WORK/mnt" -type f -exec cat {} + > /dev/null)
  time (tar -C "$WORK/mnt" -cf /dev/null .)
fi

echo "== PASS: phase-3 catalog-native mount verified =="
