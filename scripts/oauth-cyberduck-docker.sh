#!/usr/bin/env bash
#
# THE REAL CYBERDUCK STACK AGAINST PELFS'S OWN AUTHORIZATION SERVER.
#
# This is the gate for work items U7 (internal/localoauth) and U8
# (internal/davprofile) of docs/design-webui.md. A golden file proves we
# wrote the profile we meant to write; only this proves the profile
# CONNECTS -- and "a profile that cannot connect" is the failure mode the
# whole of verification 2 exists to avoid, because it fails with nothing
# useful in any UI.
#
# `duck` is Cyberduck's CLI and THE SAME PROTOCOL STACK as Cyberduck and
# Mountain Duck: the same DAVSession, the same OAuth2RequestInterceptor, the
# same BrowserOAuth2AuthorizationCodeProvider. If duck completes the flow,
# the GUI does.
#
# HOW A HEADLESS BOX COMPLETES A BROWSER FLOW. It turns out duck does not
# need a browser at all: it PRINTS the authorization URL and then waits on
# its own loopback listener. So the probe reads the URL out of duck's
# output and drives the consent screen with curl -- fetch the page, take
# the consent ticket out of it, POST the Authorize button with the headers
# a browser sends for a same-origin form submit, and follow the 303 to
# Cyberduck's callback. That is a real browser's ROLE played by curl, not a
# mock: every byte on the wire is the real client's and the real server's.
#
# MEASURED 2026-08-23 (oauth-agent), duck 9.5.3 (45464), curl 8.14.1, on
# debian:stable-slim, aarch64 -- 22 checks, 0 failing:
#
#   ok   duck:oauth-list         hello.txt sub, over a profile and a click
#   ok   auth:no-password-path   authenticated as anonymous, no password anywhere
#   ok   pkce:s256-by-default    Cyberduck sent code_challenge_method=S256 unprompted
#   ok   redirect:explicit-port  the profile's exact callback, port and all
#   ok   client:per-download-id  the profile's client_id, verbatim
#   ok   scopes:array-to-scope   the plist <array> arrived as a scope parameter
#   ok   auth:oauth-selected     the profile switched the session to OAuth
#   ok   redirect:loopback-prov  Cyberduck chose the loopback provider
#   ok   duck:oauth-download     26 bytes over Authorization: Bearer
#   ok   token:back-channel      the form-encoded exchange a Java client sends
#   ok   token:expires_in        3600, without which Cyberduck never refreshes
#   ok   token:refresh_token     present
#   ok   ro:403-on-write         a read-only token answers 403, not 401
#   ok   bearer:propfind         207
#   ok   consent:get-no-redirect a GET of /authorize emitted no Location
#   ok   challenge:narrowed      a refused Bearer is not offered Basic
#   ok   refuse:redirect-uri     a callback off by one port answers 400
#   ok   refuse:client-id        an unknown client_id answers 400
#   ok   refuse:no-pkce          an authorization with no S256 challenge answers 400
#   ok   dav:bearer-only         one challenge, and it is Bearer -- there is no
#                                password path left to fall back to
#   ok   server:consent-recorded a human's click minted every grant
#   ok   server:counters         the three refusals were counted, no replays
#
# and four of the claims below were in docs/design-webui.md's "could not be
# verified" list until this run:
#
#   * `duck --profile <file>` registers a generated profile and
#     `dav://127.0.0.1:PORT/dav/` resolves to it:
#     "Register profile Profile{parent=dav, vendor=org.pelicanplatform.pelfs.local.9997}"
#   * A NON-BLANK `OAuth Client ID` IS THE SWITCH. The session went
#     straight to "Start new OAuth flow" with credentials
#     `user='anonymous', password=''` -- no password prompt, no password
#     field, nothing typed.
#   * PKCE S256 IS SENT BY DEFAULT. The URL Cyberduck built carries
#     `code_challenge_method=S256`, so REQUIRING it costs the primary
#     client nothing.
#   * THE LOOPBACK PROVIDER IS SELECTED for this redirect shape:
#     "Evaluate redirect URI http://127.0.0.1:52001/pelfs/oauth/callback"
#     then "Started OAuth callback server ... Await callback".
#   * The `redirect_uri` Cyberduck sends is the profile's string verbatim,
#     which is what makes an exact-string allowlist workable.
#   * `Scopes` as a plist <array> arrives as a space-delimited `scope`.
#
# Needs network on FIRST BUILD only (the base image and the Cyberduck apt
# repo). The run is `--network none`.
#
# Usage: scripts/oauth-cyberduck-docker.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
# The same image the WebDAV client gate builds, so the two share one layer
# cache; duck and curl are all this probe needs from it.
IMAGE_TAG="pelfs-webdav-clients:1"

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
# different program entirely (a URL checker). The repository's advertised GPG
# key URL 404s, hence [trusted=yes]: acceptable for a throwaway probe image
# and not for anything a user runs. See scripts/webdav-clients-docker.sh.
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
RUN { duck --version 2>&1 | head -1; rclone version | head -1; curl --version | head -1; } > /versions
DOCKERFILE
fi

echo "== cross-compiling the authorization server's gate binary for linux/$ARCH =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go test -c -o "$STAGE/localoauth.test" ./internal/localoauth)

cat > "$STAGE/probe.sh" <<'SH'
#!/usr/bin/env bash
# Not `set -e`: every check runs and is reported, so one failure cannot hide
# the ones after it.
set -uo pipefail
fails=0
ck() { if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails+1)); fi; }

# log4j calls InetAddress.getLocalHost() at class-init time and there is no
# resolver under --network none. One line of /etc/hosts fixes it.
echo "127.0.0.1 $(hostname)" >> /etc/hosts
export TMPDIR=/work
mkdir -p /work/gen

PORT=9997
CALLBACK=52001
ORIGIN="http://127.0.0.1:$PORT"

PELFS_OAUTH_TCP=127.0.0.1:$PORT PELFS_OAUTH_CALLBACK=$CALLBACK \
  PELFS_OAUTH_DIR=/work/gen PELFS_OAUTH_TTL=10m \
  /stage/localoauth.test -test.run TestServeForCyberduckGate -test.timeout 0 \
  >/work/server.log 2>&1 &
srv=$!
for _ in $(seq 600); do grep -q '^ready' /work/server.log && break; sleep 0.1; done
if ! grep -q '^ready' /work/server.log; then echo "server never bound:"; cat /work/server.log; exit 2; fi
cat /versions
head -3 /work/server.log
. /work/gen/creds.env
echo

# ---------------------------------------------------------------- the flow
#
# consent() plays the browser: fetch the authorization screen, take the
# ticket out of it, press Authorize with the headers a browser sends for a
# same-origin form POST, and hand the 303 to Cyberduck's own listener.
#
# WHAT THIS GATE CANNOT SEE, and it is not a small list. curl is not a
# browser: it implements neither the Fetch standard's Origin rules nor
# Content Security Policy. Two bugs that broke EVERY Cyberduck connection
# lived exactly there and passed here green --
#
#   * a real browser sends `Origin: null` on this form POST, because
#     `Referrer-Policy: no-referrer` makes it (Fetch, "append a request
#     `Origin` header"), and the guard answered `403 origin refused`. The
#     line below types the correct Origin in by hand, so this gate never
#     saw it.
#   * Chromium enforces `form-action` on the REDIRECTS of a form
#     submission, so the 303 that used to hand the code to Cyberduck was
#     blocked by the consent page's own CSP. curl has no CSP at all.
#
# scripts/oauth-browser-docker.sh is the gate that drives this navigation
# in a real Chromium with real duck as the client, and it is the one to
# extend when the question is about what a BROWSER does. This gate's job
# is the protocol and the server's own refusals, which it does in a
# fraction of the time.
#
# ONE THING CHANGED SHAPE. The consent POST used to answer 303 straight to
# Cyberduck's loopback listener -- which answers by closing the connection, so
# a real user's tab died at the moment the flow succeeded. It answers a
# SUCCESS PAGE now, and the authorization is delivered from one hidden frame
# on it. So the delivery URL is read out of the page, and `&amp;` is
# unescaped because it lives in an HTML attribute.
consent() {
  url="$1"
  curl -sS -o /work/consent.html -w '%{http_code}' \
    -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' "$url" > /work/consent.code
  ticket=$(grep -o 'name="consent_ticket" value="[^"]*"' /work/consent.html \
           | head -1 | sed 's/.*value="//; s/"$//')
  [ -n "$ticket" ] || { echo "no consent ticket in the page"; return 1; }
  curl -sS -o /work/connected.html \
    -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' \
    --data-urlencode "consent_ticket=$ticket" --data-urlencode "decision=allow" \
    "$ORIGIN/oauth/authorize" >/dev/null
  loc=$(sed -n 's/.*<iframe class="deliver" src="\([^"]*\)".*/\1/p' /work/connected.html \
        | head -1 | sed 's/&amp;/\&/g')
  [ -n "$loc" ] || { echo "no delivery frame on the page the consent POST answered"; return 1; }
  # Cyberduck's loopback HttpServer takes it from here. It answers by
  # closing the connection rather than by writing a response, so curl's
  # "empty reply" is the expected outcome and not an error. In a real browser
  # this request is the hidden frame's.
  curl -s -o /dev/null "$loc" || true
}

# duck prints the authorization URL and then waits on its callback server,
# so the probe reads the URL out of duck's own output rather than needing a
# browser at all. Two modes: `plain` puts the URL on a line of its own and
# leaves the listing readable, `debug` adds the log that says WHICH provider
# Cyberduck chose -- which is the evidence half of this gate.
run_duck() {
  mode="$1"; shift
  : > /work/duck.out
  extra=""
  [ "$mode" = debug ] && extra="--debug"
  ( timeout 120 duck --profile /work/gen/pelfs.cyberduckprofile --assumeyes $extra \
      "$@" < /dev/null > /work/duck.out 2>&1 ; echo $? > /work/duck.rc ) &
  duckpid=$!
  url=""
  for _ in $(seq 900); do
    if [ "$mode" = debug ]; then
      url=$(grep -m1 -o 'Open browser with URL http[^ ]*$' /work/duck.out 2>/dev/null \
            | sed 's/^Open browser with URL //')
    else
      url=$(grep -m1 -E "^http://127\.0\.0\.1:$PORT/oauth/authorize\?" /work/duck.out 2>/dev/null \
            | tr -d '\r')
    fi
    [ -n "$url" ] && break
    kill -0 $duckpid 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$url" ]; then
    echo "duck never asked for an authorization"; wait $duckpid 2>/dev/null; return 1
  fi
  echo "$url" > /work/authorize.url
  consent "$url" || return 1
  wait $duckpid 2>/dev/null
  [ "$(cat /work/duck.rc)" = 0 ]
}

# 1. THE DOUBLE-CLICK: one generated profile, one OAuth flow, one listing.
run_duck plain --list "dav://127.0.0.1:$PORT/dav/"
rc=$?
grep -E '^(hello\.txt|sub)$' /work/duck.out > /work/list.txt 2>/dev/null
if [ "$rc" = 0 ] && grep -qx hello.txt /work/list.txt && grep -qx sub /work/list.txt; then r=0; else r=1; fi
ck $r "duck:oauth-list        $(tr '\n' ' ' < /work/list.txt)"

# NO PASSWORD ANYWHERE, checked on the run with no debug noise in it:
# `Password Configurable false` plus a non-blank client id must mean nothing
# is ever asked for and nothing is ever sent.
if grep -q 'Authenticating as anonymous' /work/duck.out \
   && grep -q 'Login successful' /work/duck.out \
   && ! grep -qi 'password' /work/duck.out; then r=0; else r=1; fi
ck $r "auth:no-password-path  authenticated as anonymous, no password anywhere"

# The evidence run: the same flow again, with the log that names the
# machinery Cyberduck chose.
run_duck debug --list "dav://127.0.0.1:$PORT/dav/" >/dev/null 2>&1

# 2. THE URL CYBERDUCK BUILT, which is where four of the design's
#    "could not be verified" claims are actually settled.
url=$(cat /work/authorize.url 2>/dev/null || echo)
case "$url" in *code_challenge_method=S256*) r=0;; *) r=1;; esac
ck $r "pkce:s256-by-default   Cyberduck sent code_challenge_method=S256 unprompted"
case "$url" in *"redirect_uri=http://127.0.0.1:$CALLBACK/pelfs/oauth/callback"*) r=0;; *) r=1;; esac
ck $r "redirect:explicit-port the profile's exact callback, port and all"
case "$url" in *"client_id=$PELFS_CLIENT_ID"*) r=0;; *) r=1;; esac
ck $r "client:per-download-id the profile's client_id, verbatim"
case "$url" in *scope=pelfs.read*) r=0;; *) r=1;; esac
ck $r "scopes:array-to-scope  the plist <array> arrived as a scope parameter"

# 3. WHAT CYBERDUCK'S OWN LOG SAYS IT DID.
grep -q "Start new OAuth flow" /work/duck.out && r=0 || r=1
ck $r "auth:oauth-selected    the profile switched the session to OAuth"
grep -q "LoopbackOAuth2AuthorizationCodeProvider - Started OAuth callback server" /work/duck.out && r=0 || r=1
ck $r "redirect:loopback-prov Cyberduck chose the loopback provider"

# 4. A DOWNLOAD OVER THE BEARER TOKEN, byte for byte.
rm -f /work/got-hello.txt
run_duck plain --download "dav://127.0.0.1:$PORT/dav/hello.txt" /work/got-hello.txt
printf 'hello from a pelfs volume\n' > /work/want-hello.txt
cmp -s /work/want-hello.txt /work/got-hello.txt
ck $? "duck:oauth-download    26 bytes over Authorization: Bearer"

# 5. THE READ-ONLY GRANT REFUSES A WRITE, and answers 403 rather than 401 --
#    a 401 would send the client back to ask for a password it has no field
#    for. The token is taken from the flow the probe just drove.
verifier="pelfs-probe-verifier-0123456789-abcdefghijk"
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
curl -sS -o /work/c.html -H 'Sec-Fetch-Site: none' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$PELFS_CLIENT_ID&redirect_uri=$PELFS_REDIRECT&scope=pelfs.read&state=probe&code_challenge=$challenge&code_challenge_method=S256"
ticket=$(grep -o 'name="consent_ticket" value="[^"]*"' /work/c.html | head -1 | sed 's/.*value="//; s/"$//')
loc=$(curl -sS -o /dev/null -D - -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "consent_ticket=$ticket" --data-urlencode "decision=allow" \
  "$ORIGIN/oauth/authorize" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: *//')
code=$(echo "$loc" | sed 's/.*[?&]code=//; s/&.*//')
curl -sS -o /work/token.json -X POST "$ORIGIN/oauth/token" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$code" \
  --data-urlencode "code_verifier=$verifier" --data-urlencode "redirect_uri=$PELFS_REDIRECT" \
  --data-urlencode "client_id=$PELFS_CLIENT_ID"
tok=$(grep -o '"access_token":"[^"]*"' /work/token.json | sed 's/.*://; s/"//g')
[ -n "$tok" ]
ck $? "token:back-channel     the form-encoded exchange a Java client sends"
grep -q '"expires_in":3600' /work/token.json 2>/dev/null
ck $? "token:expires_in       present and non-zero (or Cyberduck never refreshes)"
grep -q '"refresh_token":"' /work/token.json 2>/dev/null
ck $? "token:refresh_token    present (reconnect without a second consent)"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" \
  -X PUT --data-binary 'nope' "$ORIGIN/dav/refused.txt")
[ "$code" = 403 ]
ck $? "ro:403-on-write        a read-only token answers $code, not 401"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" \
  -X PROPFIND -H 'Depth: 1' "$ORIGIN/dav/")
[ "$code" = 207 ]
ck $? "bearer:propfind        $code"

# 6. THE CONSENT GESTURE. A GET alone must mint nothing, and the 401
#    challenge must not offer Basic to a client that tried Bearer.
loc=$(curl -s -o /dev/null -D - -H 'Sec-Fetch-Site: none' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$PELFS_CLIENT_ID&redirect_uri=$PELFS_REDIRECT&scope=pelfs.read&state=x&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256" \
  | grep -ci '^location:')
[ "$loc" = 0 ]
ck $? "consent:get-no-redirect a GET of /authorize emitted no Location"

h=$(curl -s -D - -o /dev/null -H 'Authorization: Bearer not-a-token' -X PROPFIND "$ORIGIN/dav/")
echo "$h" | grep -qi '^www-authenticate: Bearer' && ! echo "$h" | grep -qi '^www-authenticate: Basic'
ck $? "challenge:narrowed     a refused Bearer is not offered Basic"

# 7. THE REFUSALS, each of which must not redirect anywhere.
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: none' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$PELFS_CLIENT_ID&redirect_uri=http://127.0.0.1:52002/pelfs/oauth/callback&scope=pelfs.read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
[ "$code" = 400 ]
ck $? "refuse:redirect-uri    a callback off by one port answers $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: none' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=not-a-client&redirect_uri=$PELFS_REDIRECT&scope=pelfs.read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
[ "$code" = 400 ]
ck $? "refuse:client-id       an unknown client_id answers $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: none' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$PELFS_CLIENT_ID&redirect_uri=$PELFS_REDIRECT&scope=pelfs.read")
[ "$code" = 400 ]
ck $? "refuse:no-pkce         an authorization with no S256 challenge answers $code"

# 8. THERE IS NO CONTINGENCY ANY MORE, and that is the check.
#    This step used to run `duck --username --password` against the built-in
#    WebDAV protocol, with no --profile, as the path for a client that
#    cannot do OAuth. The per-client Basic credential is gone: /dav/* accepts
#    a Bearer token and nothing else. So the assertion inverted -- an
#    anonymous request must be offered ONE challenge, Bearer, because a Basic
#    challenge is what talks a client into a password prompt for a profile
#    with no password field (verification 2d(iii)).
hdr=$(curl -sS -o /dev/null -D - -X PROPFIND -H 'Depth: 0' "$ORIGIN/dav/" | tr -d '\r')
n=$(echo "$hdr" | grep -ci '^www-authenticate:')
if [ "$n" = 1 ] && echo "$hdr" | grep -qi '^www-authenticate: *bearer'; then r=0; else r=1; fi
ck $r "dav:bearer-only        one challenge on an anonymous PROPFIND, and it is Bearer"

# 9. AND THE COUNTERS, which are the server's own account of what happened.
kill -TERM "$srv" 2>/dev/null
wait "$srv" 2>/dev/null
echo
grep -E '^(counts|grant|client) ' /work/server.log
grep -q 'consented=true' /work/server.log
ck $? "server:consent-recorded a human's click is what minted every grant"
grep -qE 'counts .*replays=0 retries=0 redirect-mismatch=1 unknown-client=1 missing-pkce=1' /work/server.log
ck $? "server:counters        the three refusals above were counted, no replays"

echo
echo "== the authorization URL Cyberduck built =="
sed 's/client_id=[^&]*/client_id=<redacted>/' /work/authorize.url
echo
echo "== summary: $fails failing check(s) =="
exit $fails
SH
chmod +x "$STAGE/probe.sh"
chmod -R a+rX "$STAGE"

echo
echo "== duck against internal/localoauth + internal/davprofile + internal/vfsdav =="
status=0
docker run --rm \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=1g,exec \
  -e TMPDIR=/work \
  -w /work \
  "$IMAGE_TAG" \
  bash /stage/probe.sh 2>&1 | tee "$STAGE/out" || status=$?

echo
echo "== summary =="
grep -E '^(ok|FAIL|counts|grant|client|== summary)' "$STAGE/out" || true
exit "$status"
