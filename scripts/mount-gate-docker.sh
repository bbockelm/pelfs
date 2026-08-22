#!/usr/bin/env bash
# Run the kernel-mount gate inside a Linux container.
#
# This is how a macOS host gets REAL kernel mileage on the catalog-native
# stack: macOS denies the shell access to its own FUSE/NFS mounts, so the
# only honest local test is a Linux kernel in a container. Same shape as
# the op-fuzzer launcher — binaries are cross-compiled on the host, and
# the container gets /dev/fuse plus a tmpfs scratch, nothing else of the
# developer's machine.
#
# Usage: scripts/mount-gate-docker.sh [--bench]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
BENCH="${1:-}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
# The gate drops CAP_DAC_OVERRIDE (the permission checks it now asserts are
# unfalsifiable while root can bypass mode bits), so root inside the
# container is an ORDINARY reader of this directory: mktemp -d makes it
# 0700 owned by the invoking user, and root cannot traverse that without
# the capability. A macOS host hides this — Docker Desktop's file sharing
# virtualizes ownership on the bind mount — so it fails only on a Linux
# host, i.e. only in CI. hostile-docker.sh, which drops the same
# capability, has always chmod'd its stage for this reason.
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

# A tiny image with FUSE baked in, built once and cached. Building it up
# front means the test itself runs with NO network: it only ever talks to
# a fakeorigin on its own loopback.
IMAGE_TAG="pelfs-test-runner:1"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the test image (once) =="
  docker build -q -t "$IMAGE_TAG" - <<DOCKERFILE
FROM ${IMAGE}
RUN apt-get -qq update && apt-get -qq install -y fuse3 curl nfs-common \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

echo "== cross-compiling for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
cp "$REPO/scripts/mount-gate-test.sh" "$STAGE/test.sh"
# Same reason as the chmod on $STAGE: an ordinary reader must be able to
# read what it is asked to run, whatever umask the host builds with.
chmod -R a+rX "$STAGE"

echo "== running the mount gate on a real Linux kernel =="
# CAP_DAC_OVERRIDE is DROPPED, and permission_gate is why. The container
# runs as root, and root WITH that capability may write a 0444 file --
# which makes every mode-bit question in the gate answer "yes" whatever the
# frontend does, so a gate that kept it could not tell a correct permission
# answer from a missing one. Dropped, the process is refused by the kernel
# exactly as an ordinary user would be, which is the same identity the
# hostile container models (scripts/hostile-docker.sh) and the identity the
# mode-bits finding was reported under. Everything else in the gate owns
# the tree it touches and does not notice.
exec docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --cap-drop DAC_OVERRIDE \
  --security-opt apparmor=unconfined \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=2g,exec \
  -e PELFS_MOUNT_TEST_OK=1 \
  -e PELFS_PREBUILT=/stage \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/test.sh $BENCH
