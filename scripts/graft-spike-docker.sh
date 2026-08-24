#!/usr/bin/env bash
# Run the graft spike inside a Linux container.
#
# Same shape as scripts/mount-gate-docker.sh, and for the same reason:
# macOS denies the shell access to its own FUSE mounts, so the only honest
# local test of a grafted READ is a Linux kernel in a container. Binaries
# are cross-compiled on the host; the container gets /dev/fuse and a tmpfs
# scratch and nothing else of the developer's machine.
#
# Usage: scripts/graft-spike-docker.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

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
cp "$REPO/scripts/graft-spike-test.sh" "$STAGE/test.sh"
chmod -R a+rX "$STAGE"

echo "== running the graft spike on a real Linux kernel =="
# CAP_DAC_OVERRIDE is NOT dropped here, unlike the mount gate. The spike
# writes into a 0444 grafted file on purpose (that is the ungraft test),
# and it chmods it first, so the mode bits are exercised honestly without
# needing the capability question the gate is about.
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
  bash /stage/test.sh
