#!/bin/sh
# The unprivileged smoke test, run INSIDE the container by
# scripts/unprivileged-docker.sh. See that file for what the sandbox does
# and does not prove.
#
# It is deliberately /bin/sh and not bash: a stripped host may not have
# bash, and this script is a stand-in for what a user types.
set -eu

say() { echo "== $* =="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

say "who am I"
id
[ "$(id -u)" != "0" ] || fail "this test is meaningless as root"
mkdir -p "$HOME"

# Nothing writable outside the scratch: if pelfs needs a system directory
# it will fail here rather than on someone's login node.
if touch /usr/local/pelfs-probe 2>/dev/null; then
  rm -f /usr/local/pelfs-probe
  fail "the sandbox is writable outside the scratch; it is not modelling an unprivileged host"
fi

say "the binary runs at all"
/stage/pelfs version || fail "pelfs version"

say "a federation stand-in on loopback"
/stage/fakeorigin --root /work/origin --listen 127.0.0.1:18991 &
ORIGIN=$!
trap 'kill $ORIGIN 2>/dev/null || true' EXIT
i=0
while [ $i -lt 100 ]; do
  if /stage/pelfs version >/dev/null 2>&1 && [ -d /work/origin ]; then break; fi
  i=$((i + 1))
  sleep 0.1
done
PREFIX="http://127.0.0.1:18991/ns"

say "pelfs shell, out of the box"
# No --state-dir, no --backend, no flags at all beyond the prefix: the
# scenario is a user who types one command. Everything it needs -- state
# directory, signing key, caches -- it must create under HOME itself.
/stage/pelfs shell "$PREFIX" -- /bin/sh -c '
  set -eu
  echo "hello from an unprivileged mount" > greeting.txt
  mkdir -p sub
  head -c 300000 /dev/urandom > sub/blob.bin
  cat greeting.txt
' > /work/shell.log 2>&1 || { echo "--- shell.log ---"; cat /work/shell.log; fail "pelfs shell"; }
grep -q "hello from an unprivileged mount" /work/shell.log || {
  cat /work/shell.log; fail "the payload did not run inside the mount"; }
grep -qi "fuse" /work/shell.log && echo "   (backend chatter above is informational)"
echo "   wrote and read a file inside the mount"

say "the state directory is under HOME, and nowhere else"
[ -d "$HOME/.local/state/pelfs" ] || fail "no state directory under HOME: $(ls -a "$HOME" 2>&1)"
find "$HOME/.local/state/pelfs" -name 'v2-signing.key' | grep -q . || fail "no signing key was created"

say "the tree survives the unmount"
/stage/pelfs shell --ro "$PREFIX" -- /bin/sh -c '
  set -eu
  cat greeting.txt
  test -s sub/blob.bin
' > /work/reread.log 2>&1 || { echo "--- reread.log ---"; cat /work/reread.log; fail "re-mount"; }
grep -q "hello from an unprivileged mount" /work/reread.log || {
  cat /work/reread.log; fail "the sealed generation lost the file"; }
echo "   a second mount read back what the first sealed"

say "maintenance works unprivileged too"
/stage/pelfs fsck --deep "$PREFIX" > /work/fsck.log 2>&1 || { cat /work/fsck.log; fail "fsck"; }
grep -q "generation is consistent" /work/fsck.log || { cat /work/fsck.log; fail "fsck consistency"; }
/stage/pelfs gc "$PREFIX" > /work/gc.log 2>&1 || { cat /work/gc.log; fail "gc"; }
/stage/pelfs repack "$PREFIX" > /work/repack.log 2>&1 || { cat /work/repack.log; fail "repack"; }
echo "   fsck --deep, gc and repack all ran as an ordinary user"

say "PASS: linux/$(uname -m) as uid $(id -u), no privileges, no setup"
