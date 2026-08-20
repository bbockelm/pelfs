#!/bin/sh
# What a locked-down host looks like: no /dev/fuse at all.
#
# pelfs cannot mount here and never will be able to. The only thing worth
# gating is therefore the DIAGNOSIS, because it is the whole of the user's
# experience: a wrong or vague message costs an afternoon, and the two
# wrong messages that are easy to emit are "install FUSE" (they cannot,
# they have no root, and it may already be installed) and "use --backend
# nfs" (that mounts with mount(2), which needs root, so it is a second
# failure with a worse message).
set -eu
fail() { echo "FAIL: $*" >&2; exit 1; }

[ ! -e /dev/fuse ] || fail "this container HAS /dev/fuse; it is not modelling a locked-down host"
mkdir -p "$HOME"

if /stage/pelfs shell http://127.0.0.1:1/ns -- /bin/true > /work/nofuse.log 2>&1; then
  cat /work/nofuse.log; fail "pelfs mounted on a host with no /dev/fuse"
fi
cat /work/nofuse.log | sed 's/^/    /'

grep -q "/dev/fuse does not exist" /work/nofuse.log \
  || fail "the message does not say WHICH thing is missing"
grep -q "requires root" /work/nofuse.log \
  || fail "the message does not explain why there is no fallback"
grep -qi "use --backend nfs" /work/nofuse.log \
  && fail "the message still sends an unprivileged Linux user to a backend that needs root"

echo "== diagnosis is specific and does not send the user somewhere worse =="
