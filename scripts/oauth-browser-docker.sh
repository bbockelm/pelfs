#!/usr/bin/env bash
#
# A REAL BROWSER AND REAL CYBERDUCK, ON THE SAME FLOW, AT THE SAME TIME.
#
# THE GAP THIS EXISTS TO CLOSE, because it cost the feature entirely. Every
# other gate on `pelfs browse`'s OAuth path -- scripts/oauth-cyberduck-docker.sh
# and scripts/browse-gate.sh -- says of itself that it plays "a real browser's
# ROLE by curl". Their consent() functions fetch the authorization screen,
# scrape the ticket out of it, and POST the Authorize button with
# `-H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin'` supplied BY HAND.
# That satisfies internal/httpguard's checks by construction, and it means the
# authorize navigation had never once been made by something that implements
# the Fetch standard or Content Security Policy. Two bugs lived in that gap,
# both of them fatal to every connection, and both invisible to curl:
#
#   1. `Referrer-Policy: no-referrer` (internal/httpguard's securityHeaders,
#      on every response) makes a browser send `Origin: null` on a form
#      submission -- Fetch, "append a request `Origin` header", the
#      `no-referrer` case -- and `Origin: null` was answered
#      `403 origin refused`. curl sent the real Origin because the script
#      typed it in.
#
#   2. `form-action 'self'` on the consent page (internal/localoauth's
#      consentCSP) is enforced by Chromium on the REDIRECTS of a form
#      submission, and the one thing a successful authorization does is 303
#      the POST to the client's own loopback listener -- a different origin.
#      So the code was minted, the consent was recorded, and the browser
#      stopped dead with "Sending form data ... violates ... form-action
#      'self'" in a console nobody was reading. curl does not implement CSP
#      at all.
#
# So: this gate drives the authorize navigation and the consent click in a
# REAL Chromium, through playwright-core, while the WebDAV client half is REAL
# `duck` -- Cyberduck's own CLI, the same DAVSession, the same
# OAuth2RequestInterceptor, the same LoopbackOAuth2AuthorizationCodeProvider.
# Neither half is a stand-in. It asserts on the BYTES the browser sent at each
# step, so a regression in either fix names itself instead of being reported
# as "Cyberduck will not connect".
#
# WHY DEBIAN'S CHROMIUM RATHER THAN PLAYWRIGHT'S OWN. `playwright install
# chromium` wants a download at run time and a distro on its supported list;
# this image is Debian and the run is `--network none`. Debian's `chromium`
# package is a real browser of a real version, and playwright-core drives it
# through `executablePath` -- the pinned-revision property that
# scripts/webui-playwright.sh gets from `playwright install` is the right
# trade for a browser gate about rendering, and the wrong one for this gate,
# whose subject is HTTP semantics that no Chromium of any revision differs on.
# playwright-core itself is copied from the repo's own node_modules, so the
# version is the one webui/frontend/package.json pins.
#
# `--no-sandbox`: a container without user namespaces cannot start Chromium's
# zygote sandbox. The page it loads comes from a server in the same container
# on loopback with no network, so the sandbox is protecting nothing here.
#
# Needs network on FIRST BUILD only. The run is `--network none`.
#
# Usage: scripts/oauth-browser-docker.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
IMAGE_TAG="pelfs-oauth-browser:1"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the browser+duck image (once: chromium, nodejs, duck) =="
  # duck comes from Cyberduck's own repository -- debian's `duck' package is a
  # different program entirely (a URL checker). The repository's advertised
  # GPG key URL 404s, hence [trusted=yes]: acceptable for a throwaway probe
  # image and not for anything a user runs. See
  # scripts/webdav-clients-docker.sh, which made the same call.
  docker build -q -t "$IMAGE_TAG" - <<'DOCKERFILE'
FROM debian:stable-slim
RUN apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends \
      chromium nodejs curl openssl ca-certificates fonts-dejavu-core \
 && echo "deb [trusted=yes] https://s3.amazonaws.com/repo.deb.cyberduck.io stable main" \
      > /etc/apt/sources.list.d/cyberduck.list \
 && apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends duck \
 && rm -rf /var/lib/apt/lists/*
RUN { duck --version 2>&1 | head -1; chromium --version; node --version; } > /versions
DOCKERFILE
fi

echo "== cross-compiling the authorization server's gate binary for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go test -c -o "$STAGE/localoauth.test" ./internal/localoauth)

# playwright-core out of the repo's own node_modules: pure JavaScript, so the
# host's copy runs unchanged in the container. If it is not installed, say
# which command installs it rather than failing inside docker.
PW="$REPO/webui/frontend/node_modules/.pnpm/playwright-core@1.60.0/node_modules/playwright-core"
if [ ! -d "$PW" ]; then
  echo "no playwright-core at $PW" >&2
  echo "run: (cd webui/frontend && pnpm install --frozen-lockfile)" >&2
  exit 2
fi
mkdir -p "$STAGE/node_modules"
cp -R "$PW" "$STAGE/node_modules/playwright-core"

cp "$REPO/scripts/oauth-browser-drive.mjs" "$STAGE/drive.mjs"
cp "$REPO/scripts/oauth-browser-probe.sh" "$STAGE/probe.sh"
chmod +x "$STAGE/probe.sh"
chmod -R a+rX "$STAGE"

echo
echo "== a real Chromium and real duck against internal/localoauth =="
status=0
docker run --rm \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=1g,exec \
  --shm-size=512m \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/probe.sh 2>&1 | tee "$STAGE/out" || status=$?

echo
echo "== summary =="
grep -E '^(ok|FAIL|== summary)' "$STAGE/out" || true
exit "$status"
