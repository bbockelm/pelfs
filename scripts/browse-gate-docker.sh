#!/usr/bin/env bash
#
# Run the `pelfs browse` end-to-end gate inside a Linux container.
#
# Two things force a container and neither is optional. The gate MOUNTS a
# real filesystem to verify the federation (a macOS host brings the mount up
# and then denies the shell access to it), and it drives REAL Cyberduck —
# `duck`, Cyberduck's own CLI and the same DAVSession, the same
# OAuth2RequestInterceptor, the same
# BrowserOAuth2AuthorizationCodeProvider — which comes from Cyberduck's own
# apt repository.
#
# Binaries are cross-compiled on the host, because the image carries no Go
# toolchain, and the run has NO NETWORK: everything it talks to is a
# fakeorigin and a pelfs on its own loopback. Only the first image build
# needs the network.
#
# Usage: scripts/browse-gate-docker.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${PELFS_BROWSE_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

IMAGE_TAG="pelfs-browse-gate:1"
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the gate image (once: fuse3, duck, curl, python3) =="
  # duck comes from Cyberduck's own repository -- debian's `duck' package is
  # a different program entirely (a URL checker). The repository's
  # advertised GPG key URL 404s, hence [trusted=yes]: acceptable for a
  # throwaway probe image and not for anything a user runs. See
  # scripts/webdav-clients-docker.sh, which made the same call.
  docker build -q -t "$IMAGE_TAG" - <<'DOCKERFILE'
FROM debian:stable-slim
RUN apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends \
      fuse3 curl python3 openssl ca-certificates \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && echo "deb [trusted=yes] https://s3.amazonaws.com/repo.deb.cyberduck.io stable main" \
      > /etc/apt/sources.list.d/cyberduck.list \
 && apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends duck \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

echo "== cross-compiling pelfs and fakeorigin for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
cp "$REPO/scripts/browse-gate.sh" "$STAGE/gate.sh"
chmod -R a+rX "$STAGE"

echo
echo "== pelfs browse, end to end, with real duck and a real mount =="
status=0
docker run --rm \
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
  bash /stage/gate.sh 2>&1 | tee "$STAGE/out" || status=$?

echo
echo "== summary =="
grep -E '^(ok|FAIL|== summary)' "$STAGE/out" || true
exit "$status"
