#!/bin/sh
# pelfs-fusemount.sh — mount a pelfs volume INSIDE a container, as an
# apptainer `--fusemount` driver. No pelfs on the host, nothing for a site
# to install beyond apptainer itself.
#
# In an HTCondor job (the shape this exists for): ship the pelfs binary and
# this script into the scratch directory, then
#
#   apptainer exec \
#     --fusemount "host:$_CONDOR_SCRATCH_DIR/pelfs-fusemount.sh \
#                  pelican://<federation>/<prefix> \
#                  $_CONDOR_SCRATCH_DIR/pelfs-work /data" \
#     mypipeline.sif ./payload
#
# and the volume is at /data inside the container. `container:` works
# identically but resolves this script inside the IMAGE, so it needs pelfs
# and this file baked in or bound in; `host:` is the right form for a
# binary condor just delivered.
#
# ---------------------------------------------------------------------
# WHAT APPTAINER DOES TO US, WHICH IS WHY THIS FILE EXISTS
#
# 1. It replaces the mountpoint in the spec with a /dev/fuse descriptor it
#    has already opened AND ALREADY MOUNTED, and appends -f:
#
#        pelfs-fusemount.sh <prefix> <workdir> /dev/fd/3 -f
#
#    So the last two arguments are apptainer's, not the caller's, and
#    everything this script needs must come before them. `/data` never
#    reaches us at all — apptainer keeps that end.
#
# 2. It SCRUBS the environment. $HOME, $BEARER_TOKEN_FILE, $TMPDIR,
#    $PELFS_* — none of it survives, so anything the mount needs is
#    spelled out below rather than inherited. That is the whole reason a
#    wrapper is needed instead of putting `pelfs mount-gen` in the
#    --fusemount string directly.
#
# 3. It waits on this process and treats its exit as the mount going away,
#    so the driver must stay in the FOREGROUND. `pelfs mount-gen` always
#    does (`pelfs mount` is the one that daemonizes), and it accepts the
#    -f apptainer passes as a no-op.
#
# 4. WITH --rw, THE PAYLOAD MUST TOUCH THE MOUNTPOINT BEFORE ITS FIRST
#    WRITE — `ls -ld /data`, `test -d /data`, anything that stats it. This
#    one is the kernel's, not pelfs's: the root inode the kernel created at
#    mount(2) carries placeholder attributes owned by uid 0, apptainer
#    mounted inside a user namespace that does not map uid 0, and
#    inode_permission then refuses every MAY_WRITE with EACCES
#    (HAS_UNMAPPED_ID) before any request reaches this process at all. One
#    stat replaces those attributes with the ones pelfs reports. Reads are
#    unaffected, so a read-only mount never sees it. Measured, with the
#    protocol trace, in docs/design-apptainer.md.
# ---------------------------------------------------------------------
#
# Usage:
#   pelfs-fusemount.sh [--rw] [--token FILE] [--branch NAME] \
#                      [--signing-key FILE] [--debug] \
#                      <prefix> <workdir> <mountpoint>
#
#   --rw           mount read-write and SEAL a new generation when the
#                  container exits — including when it is killed
#   --token FILE   bearer token; default $workdir/token if it exists
#   --branch NAME  a branch other than main
#   --signing-key FILE
#                  the VOLUME's signing key. Required with --rw whenever
#                  the work directory is fresh, which in a job it always
#                  is: a new generation has to be signed by the key the
#                  volume's earlier generations were signed by, and
#                  <workdir>/state does not have it. Reading needs no key.
#                  Ship it with the job (condor transfer_input_files) the
#                  same way the binary is shipped.
#   --debug        the FUSE protocol trace, on stderr — which apptainer
#                  routes to its own, so `apptainer -d exec` shows it
#   <prefix>       pelican://<federation>/<prefix>
#   <workdir>      a WRITABLE directory on a filesystem the job owns: the
#                  state directory (pack cache, decoded-chunk arena,
#                  signing key), $HOME and the overlay all go under it. In
#                  a job, $_CONDOR_SCRATCH_DIR/something.
#   <mountpoint>   what apptainer replaces with /dev/fd/N
#
# Options go on the COMMAND LINE and not in the environment because the
# environment does not survive (point 2 above). PELFS_BIN, PELFS_RW,
# PELFS_TOKEN, PELFS_BRANCH, PELFS_SIGNING_KEY and PELFS_DEBUG are honored
# as well, for running this by hand.
set -eu

RW=${PELFS_RW:-}
TOKEN=${PELFS_TOKEN:-}
BRANCH=${PELFS_BRANCH:-}
DEBUG=${PELFS_DEBUG:-}
SIGNKEY=${PELFS_SIGNING_KEY:-}
while :; do
  case ${1:-} in
    --rw) RW=1; shift ;;
    --ro) RW=; shift ;;
    --token) TOKEN=${2:?--token needs a file}; shift 2 ;;
    --branch) BRANCH=${2:?--branch needs a name}; shift 2 ;;
    --debug) DEBUG=1; shift ;;
    --signing-key) SIGNKEY=${2:?--signing-key needs a file}; shift 2 ;;
    *) break ;;
  esac
done

if [ $# -lt 3 ]; then
  echo "usage: $0 [--rw] [--token FILE] [--branch NAME] [--signing-key FILE] [--debug] <prefix> <workdir> <mountpoint>" >&2
  echo "  (apptainer supplies the mountpoint and a -f: --fusemount \"host:$0 <prefix> <workdir> /mnt/where\")" >&2
  exit 2
fi

PREFIX=$1
WORK=$2
MOUNTPOINT=$3

PELFS=${PELFS_BIN:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/pelfs}
[ -x "$PELFS" ] || { echo "$0: no pelfs binary at $PELFS (set PELFS_BIN)" >&2; exit 2; }

# Everything under one directory the job owns, because none of the usual
# places are reachable: $HOME is unset, and pelfs would otherwise put its
# state under a home directory that does not exist.
export HOME="$WORK/home"
export TMPDIR="$WORK/tmp"
mkdir -p "$HOME" "$TMPDIR" "$WORK/state"

set -- --state-dir "$WORK/state" --stats-file "$WORK/pelfs-stats.json"
if [ -n "$RW" ]; then
  # Writable: the overlay lives in the state directory and the exit seals
  # it into a new generation. A container that is killed still seals — the
  # fuse connection dies with it, which is the driver's signal to finish.
  set -- "$@" --rw
else
  set -- "$@" --ro
fi
[ -n "$TOKEN" ] || TOKEN=$WORK/token
if [ -f "$TOKEN" ]; then
  set -- "$@" --token "$TOKEN"
fi
if [ -n "$BRANCH" ]; then
  set -- "$@" --branch "$BRANCH"
fi
if [ -n "$DEBUG" ]; then
  set -- "$@" --debug
fi
if [ -n "$SIGNKEY" ]; then
  set -- "$@" --signing-key "$SIGNKEY"
elif [ -n "$RW" ] && [ ! -f "$WORK/state/v2-signing.key" ]; then
  # Said now rather than at the seal, which is after the job has finished
  # and everything it wrote is riding on it.
  echo "$0: WARNING: --rw with no signing key. $WORK/state/v2-signing.key" >&2
  echo "  does not exist, so the seal at exit will have nothing to sign the new" >&2
  echo "  generation with and the writes will be left in the overlay. Pass" >&2
  echo "  --signing-key <file> with the volume's key." >&2
fi

# exec, not a subshell: apptainer signals and waits on the pid it started.
exec "$PELFS" mount-gen "$@" "$PREFIX" "$MOUNTPOINT"
