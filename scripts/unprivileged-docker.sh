#!/usr/bin/env bash
# Smoke test: a linux/amd64 binary, copied to a host, run by a user with
# NO privileges, mounts and works.
#
# The scenario this stands in for is the real one: build here, scp the
# binary to a login node or a batch worker, and run `pelfs shell` as
# yourself. No root, no sudo, no package install, no setup step.
#
# WHAT THE CONTAINER CAN AND CANNOT PROVE. Docker gives the container
# --cap-add SYS_ADMIN and --device /dev/fuse, because a container without
# them cannot mount FUSE at all — not even as root. Those two stand in for
# "the host kernel permits FUSE", which is a property of the host, not of
# the user. What is actually tested is the half that is about privilege:
# the process runs as an UNPRIVILEGED UID with an empty supplementary
# group set, no setuid helper it is allowed to gain anything from, no
# writable system directories, and no HOME it did not make itself.
#
# So: this proves pelfs needs nothing from root. It does not prove a given
# host permits FUSE for its users — nothing running on this laptop can.
#
# Usage: scripts/unprivileged-docker.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
# amd64 on purpose and not the host's arch: this is the artifact the
# scenario ships, and a Mac that only ever tested arm64 would not have
# tested it.
ARCH="${PELFS_UNPRIV_ARCH:-amd64}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

IMAGE_TAG="pelfs-unpriv-runner:2"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the test image (once) =="
  # fuse3 only. Deliberately NO nfs-common and NO curl: the point is what
  # a bare host gives an unprivileged user, and every package added here
  # is a dependency the scenario would have to install with root.
  docker build -q -t "$IMAGE_TAG" --platform "linux/$ARCH" - <<DOCKERFILE
FROM --platform=linux/$ARCH ${IMAGE}
RUN apt-get -qq update && apt-get -qq install -y fuse3 \
 && rm -rf /var/lib/apt/lists/*
# Two ordinary users, because fusermount3 refuses to mount for a uid it
# cannot map to a name ("could not determine username") -- which a real
# login node always can, and a bare container cannot.
RUN useradd -m -u 1001 first-user && useradd -m -u 1002 second-user
DOCKERFILE
fi

echo "== cross-compiling for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
cp "$REPO/scripts/unprivileged-test.sh" "$STAGE/test.sh"
cp "$REPO/scripts/unprivileged-nofuse.sh" "$STAGE/nofuse.sh"
cp "$REPO/scripts/unprivileged-uidmap.sh" "$STAGE/uidmap.sh"
chmod 0755 "$STAGE"/pelfs "$STAGE"/fakeorigin "$STAGE"/test.sh "$STAGE"/nofuse.sh "$STAGE"/uidmap.sh

# The DIAGNOSIS half, in a container with no /dev/fuse at all. This is
# what a locked-down host looks like, and the message it produces is the
# only thing standing between a user and an afternoon of guessing.
echo "== running with no /dev/fuse, to check the diagnosis =="
docker run --rm \
  --user 1001:1001 \
  --network none \
  --platform "linux/$ARCH" \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=64m,exec,uid=1001,gid=1001 \
  -e HOME=/work/home \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  /bin/sh /stage/nofuse.sh

# One volume, two uids: created by 1001 and then mounted and written by
# 1002. The origin is a shared bind mount because that is what makes them
# the same volume rather than two.
SHARED="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$SHARED"' EXIT
chmod 0770 "$SHARED"
# Owned by the shared group, so both phases can reach it without it being
# open to the world.
chgrp 1001 "$SHARED" 2>/dev/null || chmod 0777 "$SHARED"
# $1 uid, $2 gid, $3 phase. The two uids share a GROUP so that the volume
# signing key can be handed over at 0640 rather than world-readable: this
# script is the worked example of moving a volume between machines, and a
# private key at 0644 is not the habit to model.
uidphase() {
  docker run --rm \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    --user "$1:$2" \
    --network none \
    --platform "linux/$ARCH" \
    -v "$STAGE":/stage:ro \
    -v "$SHARED":/shared \
    --tmpfs /work:rw,size=256m,exec,uid=$1,gid=$2 \
    -e HOME=/work/home \
    -e TMPDIR=/work \
    -w /work \
    "$IMAGE_TAG" \
    /bin/sh /stage/uidmap.sh "$3"
}
echo "== one volume, two uids: the cluster-vs-laptop case =="
uidphase 1001 1001 create
uidphase 1002 1001 use

echo "== running as uid 1001 with no privileges =="
exec docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --user 1001:1001 \
  --network none \
  --platform "linux/$ARCH" \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=1g,exec,uid=1001,gid=1001 \
  -e HOME=/work/home \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  /bin/sh /stage/test.sh
