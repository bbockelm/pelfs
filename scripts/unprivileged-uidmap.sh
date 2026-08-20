#!/bin/sh
# Phase run by scripts/unprivileged-docker.sh, twice, as two different
# uids against one shared volume.
#
# This is the failure a user actually hit: a volume created on a laptop,
# mounted on a cluster login node where the same person has a different
# uid, and every write in the root denied --
#
#   fatal: could not create work tree dir 'htcondor': Permission denied
#
# The root directory is mode 0755 owned by whoever ran init, the mount
# asks for default_permissions, and the kernel enforces a number recorded
# on another machine.
#
# $1 is "create" or "use".
set -eu
fail() { echo "FAIL: $*" >&2; exit 1; }
PREFIX="http://127.0.0.1:18992/ns"
mkdir -p "$HOME"

# A federation stand-in, per phase, over the SHARED origin directory --
# which is what makes the two phases the same volume.
/stage/fakeorigin --root /shared/origin --listen 127.0.0.1:18992 &
ORIGIN=$!
trap 'kill $ORIGIN 2>/dev/null || true' EXIT
sleep 0.5

case "$1" in
create)
  echo "   creating the volume as uid $(id -u)"
  /stage/pelfs shell "$PREFIX" -- /bin/sh -c '
    set -eu
    mkdir -p made-by-the-owner
    echo "written by the creating uid" > made-by-the-owner/note.txt
  ' > /work/create.log 2>&1 || { cat /work/create.log; fail "create"; }
  # The volume signing key is per-VOLUME, not per-machine, so a second
  # machine has to import it -- the same scp a user would do. Without it
  # the second uid mounts and reads and writes fine, and then cannot
  # SEAL, which is a different problem from the one this tests.
  KEY=$(find "$HOME/.local/state/pelfs" -name v2-signing.key | head -1)
  [ -n "$KEY" ] || fail "no signing key to hand to the second uid"
  cp "$KEY" /shared/key
  # 0640, group-readable only: the two phases share a group precisely so
  # this does not have to be world-readable. On a real second machine this
  # is an scp of a 0600 file, which is what the destination gets below.
  chmod 0640 /shared/key
  # The state directory is per-prefix, so the path is the same on both
  # machines below HOME. Recording it is the stand-in for "scp the key to
  # the same place on the other host", which is what a user does --
  # `pelfs shell` has no --signing-key of its own to point at it with.
  basename "$(dirname "$KEY")" > /shared/voldir
  chmod 0640 /shared/voldir
  ;;
use)
  echo "   mounting as uid $(id -u), which did NOT create it"
  # The reproduction, verb for verb: make a directory in the root, then
  # write inside it, exactly as `git clone` does.
  [ -s /shared/key ] || fail "the creating phase left no signing key"
  VOLDIR=$(cat /shared/voldir)
  mkdir -p "$HOME/.local/state/pelfs/$VOLDIR"
  cp /shared/key "$HOME/.local/state/pelfs/$VOLDIR/v2-signing.key"
  chmod 0600 "$HOME/.local/state/pelfs/$VOLDIR/v2-signing.key"
  /stage/pelfs shell "$PREFIX" -- /bin/sh -c '
    set -eu
    mkdir htcondor
    echo "cloned" > htcondor/README
    cat made-by-the-owner/note.txt
    # The other uid'"'"'s content must be writable too, not merely readable:
    # this is one person, not two.
    echo "appended by the second uid" >> made-by-the-owner/note.txt
  ' > /work/use.log 2>&1 || {
    echo "--- use.log ---"; sed 's/^/    /' /work/use.log
    fail "a second uid could not write to its own volume"; }
  grep -q "written by the creating uid" /work/use.log \
    || { cat /work/use.log; fail "the second uid could not read what the first wrote"; }
  # Sealing matters as much as writing: a mount that lets you work and
  # then cannot publish has moved the failure rather than fixed it.
  grep -q "sealed generation" /work/use.log \
    || { sed 's/^/    /' /work/use.log; fail "the second uid could not seal its work"; }
  echo "   made a directory in the root, wrote in it, appended to the first uid's file, and sealed"
  ;;
*) fail "unknown phase $1" ;;
esac
