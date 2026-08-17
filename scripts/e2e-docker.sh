#!/usr/bin/env bash
# Run the end-to-end workflow gate inside a Linux container.
#
# The gate mounts a real filesystem, which a macOS host cannot give an
# honest answer about: the mounts come up but the shell is denied access
# to them. So binaries are cross-compiled on the host and the container
# gets /dev/fuse plus a tmpfs scratch, nothing else of the developer's
# machine — and no network, since it only ever talks to a fakeorigin on
# its own loopback.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PELFS_E2E_IMAGE:-debian:stable-slim}"
ARCH="${PELFS_E2E_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

IMAGE_TAG="pelfs-e2e-runner:1"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the test image (once) =="
  docker build -q -t "$IMAGE_TAG" - <<DOCKERFILE
FROM ${IMAGE}
RUN apt-get -qq update && apt-get -qq install -y fuse3 curl python3 openssl \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

echo "== cross-compiling for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
cp "$REPO/scripts/e2e-test.sh" "$STAGE/test.sh"

echo "== running the end-to-end gate on a real Linux kernel =="
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
