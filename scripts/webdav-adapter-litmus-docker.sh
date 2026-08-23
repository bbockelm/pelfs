#!/usr/bin/env bash
#
# litmus against THE PELFS ADAPTER -- the second half of
# scripts/webdav-litmus-docker.sh, which measured the CEILING and said so:
# "Re-run this ... with the pelfs adapter substituted for memFS -- a NEW
# failure in `basic', `copymove' or `props' is the adapter's, and is the
# signal this script exists to give."
#
# This is that run. Same suite, same version, same container discipline; the
# server is internal/vfsdav over internal/vfsbilly over a REAL volume
# (signed superblock, real packs, a write overlay), reached over HTTP Basic
# at /dav/.
#
# THE CEILING, measured 2026-08-23 by webdav-litmus-docker.sh against
# x/net/webdav's own memFS example server (x/net v0.56.0, litmus 0.13):
#
#   basic     16/16   100.0%
#   copymove  13/13   100.0%
#   props     30/30   100.0%
#   locks     32/34    94.1%   (lock_shared: LOCK -> 501; fail_complex_cond_put)
#
# AND THE SAME SUITE AGAINST THE ADAPTER, measured 2026-08-23 (vfsdav-agent):
#
#   basic     16/16   100.0%
#   copymove  13/13   100.0%
#   props     29/30    96.7%   (propfind_invalid2 -- see below; NOT the adapter)
#   locks     32/34    94.1%   (the same two: lock_shared, fail_complex_cond_put)
#
# ONE CORRECTION TO THE CEILING, and it is the only difference in the table.
# `props 30/30' is not a property of x/net's handler: the example server the
# ceiling was measured against PASSES propfind_invalid2 BY HARD-CODING IT.
# From x/net@v0.56.0/webdav/litmus_test_server.go, verbatim:
#
#   // Thus, we assume that the propfind_invalid2 test is obsolete, and
#   // hard-code the 400 Bad Request response that the test expects.
#   http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
#           if r.Header.Get("X-Litmus") == "props: 3 (propfind_invalid2)" {
#                   http.Error(w, "400 Bad Request", http.StatusBadRequest)
#
# The test requires a 400 for an XML body carrying an empty namespace prefix
# declaration (`xmlns:bar=""'). Go's encoding/xml accepts one -- golang/go#8068
# -- and the upstream comment argues the prohibition was dropped between the
# 2006 edition of XML Names and the current one. VERIFIED here rather than
# taken on trust: the same request against the unmodified handler over memFS,
# by hand, answers 207 as well.
#
# So the honest ceiling for a REAL server is props 29/30, and the adapter
# holds it. pelfs does not reproduce the hard-code: a server that inspected
# X-Litmus would be lying to one client about one test, and the alternative
# (pre-validating every PROPFIND body against the 2006 grammar) buys a number
# rather than a user.
#
# `make check' therefore exits NONZERO on a clean run -- three known failures,
# none of them the adapter's. The numbers to watch are the per-suite lines.
#
# HOW THE SERVER GETS INTO THE CONTAINER, and why there is no `cmd/'. The
# WebDAV endpoint a user will run is `pelfs browse` (work item U3), which
# does not exist yet, and a shipped command that exists only to be tested is
# a permanent liability. So the server is a TEST:
# internal/vfsdav.TestServeForClientGates, cross-compiled with `go test -c`
# on the host (the container carries no toolchain, as every other harness
# here works) and run with -test.run. It is skipped by `go test ./...`
# because it needs PELFS_DAV_TCP to do anything.
#
# Needs network on FIRST BUILD only, for the base image, three apt packages
# and the 2011 litmus tarball. The RUN is `--network none`: the server, the
# client and the suite are all in the container, so a green run cannot be one
# that reached anything else.
#
# Usage: scripts/webdav-adapter-litmus-docker.sh [suite ...]   (default: all four)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
IMAGE_TAG="pelfs-litmus-suite:1"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

# The suite, built once and cached. litmus 0.13 is from 2011: its configure
# probe for -lsocket compiles a program with implicit declarations, which
# modern gcc rejects by default, and it then concludes the C library has no
# sockets.
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the litmus image (once) =="
  docker build -q -t "$IMAGE_TAG" - <<'DOCKERFILE'
FROM debian:stable-slim
RUN apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends build-essential ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /litmus
RUN curl -fsSL http://www.webdav.org/neon/litmus/litmus-0.13.tar.gz | tar xz --strip-components=1 \
 && CFLAGS="-O2 -std=gnu17 -Wno-implicit-function-declaration -Wno-int-conversion" ./configure \
 && make
DOCKERFILE
fi

echo "== cross-compiling the adapter's test server for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go test -c -o "$STAGE/vfsdav.test" ./internal/vfsdav)

SUITES="${*:-}"
cat > "$STAGE/run.sh" <<'SH'
#!/usr/bin/env bash
# Not `set -e`: three known failures are expected (see the launcher's
# header), and the per-suite report is what this script is for.
set -uo pipefail
user=pelfs
pass=probe-secret
export PELFS_DAV_TCP=127.0.0.1:9999 PELFS_DAV_USER="$user" PELFS_DAV_PASS="$pass"
export PELFS_DAV_TTL=25m TMPDIR=/work

# -test.timeout 0: the server is meant to outlive Go's default 10-minute
# deadline, and PELFS_DAV_TTL is the bound that actually applies.
/stage/vfsdav.test -test.run TestServeForClientGates -test.v -test.timeout 0 \
  >/work/davsrv.log 2>&1 &
pid=$!

# A bind poll on the server's own "ready" line, not a sleep: docs/TODO.md's
# "no sleep-based test sync" applies to the launchers too.
for _ in $(seq 300); do grep -q '^ready' /work/davsrv.log && break; sleep 0.1; done
if ! grep -q '^ready' /work/davsrv.log; then
  echo "the adapter's server never bound:"; cat /work/davsrv.log; exit 2
fi
sed -n '/^ready/p;/^credential/p' /work/davsrv.log

cd /litmus
# ONE SUITE PER INVOCATION, not `make check'. The Makefile stops at the first
# suite that exits nonzero, so a known failure in `props' would hide `locks'
# entirely -- which is exactly what happened on the first run of this script.
# Every suite is independent; each one's summary is reported.
#
# The arguments are litmus's own: URL, then the username and password neon
# answers the 401 challenge with. So this run also proves the Basic path
# against a real HTTP client stack (neon 0.29.6), not only against Go.
status=0
for suite in ${SUITES:-basic copymove props locks}; do
  ./"$suite" http://127.0.0.1:9999/dav/ "$user" "$pass" || status=1
done

kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
echo
echo "== the adapter's own log =="
grep -v '^=== \|^--- \|^ok  \|^PASS' /work/davsrv.log | tail -20
exit $status
SH
chmod +x "$STAGE/run.sh"
chmod -R a+rX "$STAGE"

echo
echo "== litmus against internal/vfsdav over a real pelfs volume =="
status=0
docker run --rm \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=1g,exec \
  -e TMPDIR=/work \
  -e SUITES="$SUITES" \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/run.sh 2>&1 | tee "$STAGE/out" || status=$?

echo
echo "== summary =="
grep -E '^(-> running|<- summary|-> [0-9]+ (tests|warning))|FAIL' "$STAGE/out" || true
echo
echo "(expected: basic 16/16, copymove 13/13, props 29/30, locks 32/34. All three"
echo " known failures are upstream -- memLS's shared locks, and one obsolete"
echo " props test the upstream example server passes by hard-coding it.)"
exit "$status"
