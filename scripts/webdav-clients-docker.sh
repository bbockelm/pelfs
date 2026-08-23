#!/usr/bin/env bash
#
# THREE REAL WEBDAV CLIENTS AGAINST THE PELFS ADAPTER, over both transports.
#
# This is the client half of work item U9 (docs/design-webui.md); litmus is
# the protocol half and lives in scripts/webdav-adapter-litmus-docker.sh.
# litmus proves the protocol; this proves that the programs a person will
# actually point at a pelfs volume can list, download, upload, create and
# delete -- and that the credential and the scope behave the way the threat
# model says.
#
# The clients, and why these three:
#
#   duck    Cyberduck's CLI -- THE SAME PROTOCOL STACK as Cyberduck and
#           Mountain Duck, which docs/design-guiclients.md names as the
#           primary GUI clients and docs/design-webui.md builds the whole
#           OAuth path (U7) for. If duck can do it, the GUI can.
#   rclone  an independent Go implementation of the client side, and the
#           only one of the three that can dial a UNIX SOCKET
#           (--webdav-unix-socket) and present a Bearer token
#           (--webdav-bearer-token).
#   curl    libcurl, a third independent stack, used for the checks that
#           need exact statuses and headers rather than a file transfer.
#
# BOTH TRANSPORTS, AND THE TRAP THAT MAKES IT NECESSARY. docs/design-webui.md:
# "a run over a unix socket has no meaningful Host header and therefore does
# not exercise the Host allowlist ... A green socket-only run would prove the
# adapter and silently skip the security layer." So every transferring client
# runs over 127.0.0.1 as well. One honest note about what that does and does
# not prove HERE: internal/vfsdav has no Host allowlist of its own and must
# not grow one -- the guard belongs to internal/httpguard in front of it (work
# item U1) -- so the TCP leg exercises the adapter's own credential path over
# a real socket with a real Host header, and it is U1's gate that will assert
# the allowlist. What this script would catch is an adapter that only worked
# when there was no Host header at all.
#
# MEASURED 2026-08-23 (vfsdav-agent), duck 9.5.3 (45464), rclone v1.75.0,
# curl 8.14.1, on debian:stable-slim, aarch64 -- 0 failing checks:
#
#   ok   duck:list             hello.txt, sub/, wide/, link-to-hello; and NOT
#                              a.fifo, link-dangling or link-to-sub -- the three
#                              shapes WebDAV cannot represent (internal/vfsdav)
#   ok   duck:download         26 bytes, byte-for-byte
#   ok   duck:upload           1,000,000 bytes up and back, byte-for-byte
#   ok   duck:mkdir-delete     collection created, listed, deleted
#   ok   duck:big-68497408     a 68,497,408-byte file -- the owner's own SIF
#                              size, which the Windows redirector REFUSES --
#                              downloaded, size-exact
#   ok   rclone:lsl-tcp        500 of 500 entries in one directory, with mtimes
#   ok   rclone:copy-check-tcp copy then check clean, 68 MB file included
#   ok   rclone:bearer-tcp     the U7 seam: a Bearer token and no password
#   ok   rclone:lsl-unix       the same listing over a 0600 unix socket
#   ok   rclone:copy-check-unix copy then check clean over the socket
#   ok   curl:propfind-unix    207 over the socket, a third client stack
#   ok   curl:range-tcp        206 and the exact bytes for `Range: bytes=N-M'
#   ok   auth:401-no-cred      401 + a Basic challenge, on both transports
#   ok   auth:401-bad-pass     401
#   ok   auth:401-session      X-Pelfs-Session alone is NOT a DAV credential
#   ok   cors:none             no Access-Control-Allow-* on any verb, with Origin
#   ok   ro:403-on-write       a read-only grant: reads work, PUT is 403
#
# The server is internal/vfsdav.TestServeForClientGates, cross-compiled with
# `go test -c` on the host -- see webdav-adapter-litmus-docker.sh's header for
# why the test server is a test and not a `cmd/'.
#
# Needs network on FIRST BUILD only (base image, the Cyberduck apt repo, the
# rclone zip). The RUN is `--network none`: two servers, three clients and a
# 68 MB payload, all inside the container.
#
# ONE NOTE ON THE IMAGE: the Cyberduck apt repository's advertised GPG key URL
# 404s (verified 2026-08-23), so the line is [trusted=yes] over HTTPS. That is
# acceptable for a throwaway probe image and would not be for anything a user
# runs; it is the same posture as this repo's litmus image, which fetches a
# 2011 tarball over plain HTTP.
#
# Usage: scripts/webdav-clients-docker.sh [--wide N] [--big BYTES]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
IMAGE_TAG="pelfs-webdav-clients:1"
WIDE=500
BIG=68497408
while [ $# -gt 0 ]; do
  case "$1" in
    --wide) WIDE="$2"; shift 2;;
    --big)  BIG="$2";  shift 2;;
    *) echo "usage: $0 [--wide N] [--big BYTES]" >&2; exit 2;;
  esac
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the client image (once: duck, rclone, curl) =="
  docker build -q -t "$IMAGE_TAG" --build-arg "RCLONE_ARCH=$ARCH" - <<'DOCKERFILE'
FROM debian:stable-slim
ARG RCLONE_ARCH=arm64
# duck comes from Cyberduck's own repository -- debian's `duck' package is a
# different program entirely (a URL checker). See the header on [trusted=yes].
RUN apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends curl unzip ca-certificates \
 && echo "deb [trusted=yes] https://s3.amazonaws.com/repo.deb.cyberduck.io stable main" \
      > /etc/apt/sources.list.d/cyberduck.list \
 && apt-get -qq update \
 && apt-get -qq install -y --no-install-recommends duck \
 && cd /tmp \
 && curl -fsSL -o rclone.zip "https://downloads.rclone.org/rclone-current-linux-${RCLONE_ARCH}.zip" \
 && unzip -q rclone.zip && mv rclone-*/rclone /usr/local/bin/rclone \
 && chmod 755 /usr/local/bin/rclone \
 && rm -rf /tmp/rclone* /var/lib/apt/lists/*
# debian's rclone is 1.60, which has no --webdav-unix-socket (added upstream in
# 1.63) -- and the socket leg is half of what this script exists to run.
RUN { duck --version 2>&1 | head -1; rclone version | head -1; curl --version | head -1; } > /versions
DOCKERFILE
fi

echo "== cross-compiling the adapter's test server for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go test -c -o "$STAGE/vfsdav.test" ./internal/vfsdav)

cat > "$STAGE/probe.sh" <<'SH'
#!/usr/bin/env bash
# Not `set -e`: every check runs and is reported, so one failure cannot hide
# the ones after it (the discipline scripts/sftp-clients-docker.sh established).
set -uo pipefail
fails=0
ck() { if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails+1)); fi; }

# Cyberduck is a Java program and log4j calls InetAddress.getLocalHost() at
# class-init time. With --network none there is no resolver, so it prints a
# stack trace over the first command's output. One line of /etc/hosts, and
# nothing else, fixes it.
echo "127.0.0.1 $(hostname)" >> /etc/hosts

user=pelfs
pass=probe-secret
token=bearer-token-for-the-u7-seam
sock=/work/dav.sock

export TMPDIR=/work PELFS_DAV_TTL=25m
export PELFS_DAV_USER="$user" PELFS_DAV_PASS="$pass" PELFS_DAV_BEARER="$token"
export PELFS_DAV_SEED=1 PELFS_DAV_WIDE="$WIDE" PELFS_DAV_BIG="$BIG"

# The writable server: TCP and the unix socket at once, one namespace.
PELFS_DAV_TCP=127.0.0.1:9999 PELFS_DAV_UNIX="$sock" \
  /stage/vfsdav.test -test.run TestServeForClientGates -test.timeout 0 \
  >/work/rw.log 2>&1 &
rw=$!
# And a second, READ-ONLY one -- the `pelfs browse` default, and the shape a
# `pelfs.read' Bearer token will have (vfsdav.Grant).
PELFS_DAV_TCP=127.0.0.1:9998 PELFS_DAV_RO=1 PELFS_DAV_SEED=1 PELFS_DAV_WIDE=3 PELFS_DAV_BIG=0 \
  /stage/vfsdav.test -test.run TestServeForClientGates -test.timeout 0 \
  >/work/ro.log 2>&1 &
ro=$!

for log in /work/rw.log /work/ro.log; do
  for _ in $(seq 600); do grep -q '^ready' "$log" && break; sleep 0.1; done
  if ! grep -q '^ready' "$log"; then echo "server never bound:"; cat "$log"; exit 2; fi
done
cat /versions
grep -h -E '^ready|^seeded' /work/rw.log /work/ro.log
echo

U="dav://127.0.0.1:9999/dav/"
D="duck --username $user --password $pass --assumeyes --quiet"
# Trailing slashes on collections: it is duck's own convention, and without
# them `--mkdir'/`--delete' report a not-found on a directory they created.
cd /work || exit 2

# 1. The listing a GUI renders, and the three shapes it must NOT show.
# duck writes its "Password will be sent in plaintext" advice to stdout, so
# the listing is filtered rather than taken raw. The advice is correct and is
# why the credential is a per-client secret and the listener is loopback.
$D --list "$U" 2>/work/list.err | grep -v 'plaintext\|^$' > /work/list.txt
have() { grep -qx "$1" /work/list.txt; }
if have hello.txt && have sub && have wide && have link-to-hello \
   && ! grep -q 'a.fifo\|link-dangling\|link-to-sub' /work/list.txt; then r=0; else r=1; fi
ck $r "duck:list              $(tr '\n' ' ' < /work/list.txt)"

# 2. Download, byte-for-byte.
rm -f got-hello.txt
$D --download "${U}hello.txt" /work/got-hello.txt >/dev/null 2>&1
printf 'hello from a pelfs volume\n' > want-hello.txt
cmp -s want-hello.txt got-hello.txt
ck $? "duck:download          26 bytes, byte-for-byte"

# 3. Upload, and read it back through the same client.
head -c 1000000 /dev/urandom > up.bin
$D --upload "$U" /work/up.bin >/dev/null 2>&1
rm -f back.bin && $D --download "${U}up.bin" /work/back.bin >/dev/null 2>&1
cmp -s up.bin back.bin
ck $? "duck:upload            1,000,000 bytes up and back, byte-for-byte"

# 4. MKCOL and DELETE, which is what a "New Folder" in the GUI is.
$D --mkdir "${U}newcoll/" >/dev/null 2>&1
$D --list "$U" 2>/dev/null | grep -qx newcoll && made=0 || made=1
$D --delete "${U}newcoll/" >/dev/null 2>&1
$D --list "$U" 2>/dev/null | grep -qx newcoll && gone=1 || gone=0
[ "$made" = 0 ] && [ "$gone" = 0 ]
ck $? "duck:mkdir-delete      collection created, listed, deleted"

# 5. THE SIZE THE DRIVE LETTER REFUSES. 68,497,408 bytes is the owner's own
#    SIF (docs/design-apptainer.md); the WebDAV redirector's
#    FileSizeLimitInBytes default rejects anything over 50,000,000
#    (docs/design-windows.md row 1). Cyberduck has no such cap, and this is
#    the check that says so about pelfs's own server.
if [ "$BIG" -gt 0 ]; then
  rm -f got-big.bin
  $D --download "${U}big.bin" /work/got-big.bin >/dev/null 2>&1
  [ "$(stat -c %s got-big.bin 2>/dev/null || echo 0)" = "$BIG" ]
  ck $? "duck:big-$BIG   $(stat -c %s got-big.bin 2>/dev/null || echo 0) bytes downloaded, size-exact"
fi

# 6-10. rclone, over TCP and over the socket.
export RCLONE_CONFIG=/dev/null
obscured=$(rclone obscure "$pass")
RC="--webdav-vendor other --webdav-user $user --webdav-pass $obscured --retries 1 --low-level-retries 1 --timeout 60s"
TCP="--webdav-url http://127.0.0.1:9999/dav/ $RC"
# The URL still has to be a URL over a socket; the host in it is never
# resolved, which is exactly the property that makes the run hermetic -- and
# the reason a socket-only gate would not exercise the Host header at all.
UNIX="--webdav-url http://localhost/dav/ --webdav-unix-socket $sock $RC"

rclone $TCP lsl :webdav:/wide >/work/wide-tcp.txt 2>&1
[ "$(grep -c . /work/wide-tcp.txt)" = "$WIDE" ]
ck $? "rclone:lsl-tcp         listed $(grep -c . /work/wide-tcp.txt) of $WIDE entries with mtimes"

mkdir -p tosync && cp up.bin tosync/ && { [ "$BIG" -gt 0 ] && cp got-big.bin tosync/ || true; }
rclone $TCP copy tosync :webdav:/rc-tcp >/work/rc-tcp.log 2>&1 \
  && rclone $TCP check tosync :webdav:/rc-tcp >>/work/rc-tcp.log 2>&1
ck $? "rclone:copy-check-tcp  copy then check clean$([ "$BIG" -gt 0 ] && echo ' (68 MB included)')"

# THE U7 SEAM, through a real client: a Bearer token and no password at all.
# internal/localoauth will supply the verifier; the acceptance path is this.
rclone --webdav-url http://127.0.0.1:9999/dav/ --webdav-vendor other \
  --webdav-bearer-token "$token" --retries 1 lsl :webdav:/sub >/work/bearer.txt 2>&1 \
  && grep -q nested.txt /work/bearer.txt
ck $? "rclone:bearer-tcp      Authorization: Bearer, no password"

rclone $UNIX lsl :webdav:/wide >/work/wide-unix.txt 2>&1
[ "$(grep -c . /work/wide-unix.txt)" = "$WIDE" ]
ck $? "rclone:lsl-unix        listed $(grep -c . /work/wide-unix.txt) of $WIDE over a 0600 socket"

rclone $UNIX copy tosync :webdav:/rc-unix >/work/rc-unix.log 2>&1 \
  && rclone $UNIX check tosync :webdav:/rc-unix >>/work/rc-unix.log 2>&1
ck $? "rclone:copy-check-unix copy then check clean over the socket"

# 11. A third stack over the socket.
code=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$sock" -u "$user:$pass" \
  -X PROPFIND -H 'Depth: 1' http://localhost/dav/)
[ "$code" = 207 ]
ck $? "curl:propfind-unix     $code over the socket"

# 12. A RANGED GET from a real client. docs/design-webui.md claims Range works
#     for free because handleGetHeadPost calls http.ServeContent; this is that
#     claim against libcurl rather than against Go's own client.
if [ "$BIG" -gt 0 ]; then
  curl -s -u "$user:$pass" -r 1000000-1000015 -o /work/range.bin \
    -w '%{http_code}\n' http://127.0.0.1:9999/dav/big.bin > /work/range.code
  dd if=got-big.bin of=/work/range.want bs=1 skip=1000000 count=16 status=none
  [ "$(cat /work/range.code)" = 206 ] && cmp -s /work/range.bin /work/range.want
  ck $? "curl:range-tcp         $(cat /work/range.code) and 16 bytes at offset 1000000, exact"
fi

# 13-14. The credential. A 401 with a challenge is what makes a GUI ask for a
#        password instead of showing an error.
h=$(curl -s -D - -o /dev/null --unix-socket "$sock" -X PROPFIND http://localhost/dav/)
echo "$h" | grep -q '^HTTP/1.1 401' && echo "$h" | grep -qi '^www-authenticate: Basic'
ck $? "auth:401-no-cred-unix  401 + Basic challenge"
h=$(curl -s -D - -o /dev/null -X PROPFIND http://127.0.0.1:9999/dav/)
echo "$h" | grep -q '^HTTP/1.1 401' && echo "$h" | grep -qi '^www-authenticate: Basic'
ck $? "auth:401-no-cred-tcp   401 + Basic challenge"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$user:wrong" -X PROPFIND http://127.0.0.1:9999/dav/)
[ "$code" = 401 ]
ck $? "auth:401-bad-pass      $code"
# THE SESSION TOKEN IS NOT A DAV CREDENTIAL (docs/design-webui.md, A7).
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Pelfs-Session: any-session-token' \
  -X PROPFIND http://127.0.0.1:9999/dav/)
[ "$code" = 401 ]
ck $? "auth:401-session       $code for X-Pelfs-Session alone"

# 15. No CORS header, from a client that would show one. The whole WebDAV
#     write surface is unreachable cross-origin BECAUSE this is missing.
acao=0
for m in OPTIONS PROPFIND GET PUT MKCOL DELETE; do
  curl -s -D - -o /dev/null -u "$user:$pass" -H 'Origin: http://evil.example' \
    -X "$m" http://127.0.0.1:9999/dav/hello.txt | grep -qi '^access-control-allow' && acao=1
done
[ "$acao" = 0 ]
ck $? "cors:none              no Access-Control-Allow-* on 6 verbs, with Origin"

# 16. The scope seam end to end: the read-only server reads and refuses.
RO="--webdav-url http://127.0.0.1:9998/dav/ $RC"
rclone $RO lsl :webdav: >/work/ro-lsl.txt 2>&1 && grep -q hello.txt /work/ro-lsl.txt
readable=$?
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$user:$pass" -T /work/want-hello.txt \
  http://127.0.0.1:9998/dav/nope.txt)
[ "$readable" = 0 ] && [ "$code" = 403 ]
ck $? "ro:403-on-write        read-only grant reads, PUT answers $code"

kill "$rw" "$ro" 2>/dev/null
wait "$rw" "$ro" 2>/dev/null
echo
echo "== what the adapter hid from these clients (occurrences, not entries) =="
grep -h '^hidden' /work/rw.log /work/ro.log || true
echo
echo "== summary: $fails failing check(s) =="
exit $fails
SH
chmod +x "$STAGE/probe.sh"
chmod -R a+rX "$STAGE"

echo
echo "== duck + rclone + curl against internal/vfsdav, over TCP and a unix socket =="
status=0
docker run --rm \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=3g,exec \
  -e TMPDIR=/work \
  -e WIDE="$WIDE" \
  -e BIG="$BIG" \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/probe.sh 2>&1 | tee "$STAGE/out" || status=$?

echo
echo "== summary =="
grep -E '^(ok|FAIL|hidden|== summary)' "$STAGE/out" || true
exit "$status"
