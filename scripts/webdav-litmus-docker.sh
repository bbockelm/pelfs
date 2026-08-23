#!/usr/bin/env bash
#
# What this establishes, and why it exists before any pelfs code does.
#
# docs/design-windows.md proposes a WebDAV frontend built on
# golang.org/x/net/webdav: `webdav.Handler` over an adapter that wraps
# internal/vfsbilly, so a Windows (or macOS) client can mount a pelfs volume
# with no FUSE. Everything in that plan rests on one unmeasured assumption --
# that the upstream handler is protocol-correct enough for a real client to
# trust it. This script measures that, WITHOUT any pelfs code: it runs the
# `litmus` WebDAV compliance suite (http://www.webdav.org/neon/litmus/)
# against x/net/webdav's OWN example server -- `litmus_test_server.go`, which
# ships inside the module and serves `webdav.NewMemFS()` with
# `webdav.NewMemLS()`.
#
# The number it prints is therefore the CEILING for a pelfs WebDAV frontend
# and the floor a pelfs adapter must not fall below. Measured 2026-08-23,
# x/net v0.56.0, litmus 0.13:
#
#   basic     16/16   100.0%
#   copymove  13/13   100.0%
#   props     30/30   100.0%
#   locks     32/34    94.1%   (lock_shared: LOCK -> 501; fail_complex_cond_put)
#
# So `make check` exits NONZERO on a clean run. That is the baseline, not a
# regression: memLS implements exclusive locks only, and the Windows
# redirector takes exclusive write locks, so neither failure is on the path
# this design needs. Re-run this when x/net moves, and again with the pelfs
# adapter substituted for memFS -- a NEW failure in `basic`, `copymove` or
# `props` is the adapter's, and is the signal this script exists to give.
#
# THE ADAPTER RUN NOW EXISTS: scripts/webdav-adapter-litmus-docker.sh, which
# holds this table with ONE CORRECTION TO IT (vfsdav-agent, 2026-08-23).
#
# `props 30/30` above is NOT a property of x/net's handler. The example server
# this script runs passes propfind_invalid2 by HARD-CODING it -- from
# litmus_test_server.go, verbatim:
#
#   // Thus, we assume that the propfind_invalid2 test is obsolete, and
#   // hard-code the 400 Bad Request response that the test expects.
#   if r.Header.Get("X-Litmus") == "props: 3 (propfind_invalid2)" {
#           http.Error(w, "400 Bad Request", http.StatusBadRequest)
#
# The test wants a 400 for an XML body with an empty namespace prefix
# declaration; Go's encoding/xml accepts one (golang/go#8068). Verified by
# hand against this very server with the hard-code path avoided: it answers
# 207. So the honest ceiling for a real server is `props 29/30`, and that is
# the number the adapter is held to. Nothing in this script changed -- the
# table above is what IT measures, and the sentence you would otherwise draw
# from it ("a 30th failure is the adapter's fault") is the one that is wrong.
#
# Everything runs in Docker (litmus is a 2011 C tarball that does not build
# against a modern glibc without the CFLAGS below, and nothing about it
# belongs on a laptop). Needs network on first build: the litmus tarball and
# the x/net module. No pelfs build, no mount, nothing written outside the
# build context and Docker.
#
# Usage: scripts/webdav-litmus-docker.sh [x/net version]   (default: go.mod's)
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ver=${1:-$(awk '$1=="golang.org/x/net"{print $2; exit}' "$repo/go.mod")}
[ -n "$ver" ] || { echo "cannot determine golang.org/x/net version" >&2; exit 2; }

src="$(go env GOMODCACHE)/golang.org/x/net@$ver/webdav/litmus_test_server.go"
[ -r "$src" ] || { echo "no $src -- run 'go mod download golang.org/x/net' first" >&2; exit 2; }

ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT

# The upstream file is `//go:build ignore`d so `go test ./...` skips it; drop
# that line and it is an ordinary main package.
grep -v '^//go:build ignore' "$src" > "$ctx/server.go"

cat > "$ctx/Dockerfile" <<EOF
FROM golang:1.26-trixie
RUN apt-get update \\
 && apt-get install -y --no-install-recommends build-essential ca-certificates curl \\
 && rm -rf /var/lib/apt/lists/*
WORKDIR /litmus
# litmus 0.13 is from 2011: its configure probe for -lsocket compiles a
# program with implicit declarations, which gcc 14 rejects by default, and
# then it concludes the C library has no sockets.
RUN curl -fsSL http://www.webdav.org/neon/litmus/litmus-0.13.tar.gz | tar xz --strip-components=1 \\
 && CFLAGS="-O2 -std=gnu17 -Wno-implicit-function-declaration -Wno-int-conversion" ./configure \\
 && make
WORKDIR /srv
COPY server.go .
RUN go mod init litmusprobe && go get golang.org/x/net@$ver \\
 && go build -o /usr/local/bin/davsrv server.go
# The wait is curl and not bash's /dev/tcp: the CMD shell is dash, which has
# no /dev/tcp, and the loop spins forever instead of failing loudly.
CMD ["/bin/sh","-c","/usr/local/bin/davsrv -port 9999 >/tmp/davsrv.log 2>&1 & \\
      for i in \$(seq 50); do curl -fsS -o /dev/null http://127.0.0.1:9999/ && break; sleep 0.1; done; \\
      cd /litmus && make URL=http://127.0.0.1:9999/ check"]
EOF

echo "== building probe image (x/net $ver, litmus 0.13) =="
docker build -t pelfs-litmus-probe "$ctx"

echo
echo "== litmus against x/net/webdav's own memFS server (no pelfs code) =="
# --network none: the server, the client and the suite are all in the
# container, so a green run cannot be one that reached anything else.
status=0
docker run --rm --network none pelfs-litmus-probe 2>&1 | tee "$ctx/out" || status=$?
echo
echo "== summary =="
grep -E '^(<- summary|-> [0-9]+ (tests|warning))|FAIL' "$ctx/out" || true
echo
echo "(2 known failures in \`locks' are the upstream baseline -- see this script's header)"
exit "$status"
