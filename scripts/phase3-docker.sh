#!/usr/bin/env bash
# Run the phase-3 kernel-mount gate inside a Linux container.
#
# This is how a macOS host gets REAL kernel mileage on the catalog-native
# stack: macOS denies the shell access to its own FUSE/NFS mounts, so the
# only honest local test is a Linux kernel in a container. Same shape as
# the op-fuzzer launcher — binaries are cross-compiled on the host, and
# the container gets /dev/fuse plus a tmpfs scratch, nothing else of the
# developer's machine.
#
# Usage: scripts/phase3-docker.sh [--bench]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_PHASE3_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_PHASE3_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
BENCH="${1:-}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

# A tiny image with FUSE baked in, built once and cached. Building it up
# front means the test itself runs with NO network: it only ever talks to
# a fakeorigin on its own loopback.
IMAGE_TAG="pelfs-phase3-runner:1"
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
cp "$REPO/scripts/phase3-mount-test.sh" "$STAGE/test.sh"

echo "== running the mount gate on a real Linux kernel =="
exec docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
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
