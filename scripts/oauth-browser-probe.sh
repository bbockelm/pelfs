#!/usr/bin/env bash
#
# The in-container half of scripts/oauth-browser-docker.sh. See that file for
# what this gate is and which two bugs it exists to keep fixed.
#
# Not `set -e`: every check runs and is reported, so one failure cannot hide
# the ones after it.
set -uo pipefail
fails=0
ck() { if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails+1)); fi; }

# The driver writes `ck <0|1> <name>` lines; replay them through ck so the
# browser's checks and the shell's checks land in one report and one count.
replay() {
  while IFS= read -r line; do
    case "$line" in
      "ck "*) rc=${line#ck }; ck "${rc%% *}" "${rc#* }" ;;
      "## "*) echo "     ${line#\#\# }" ;;
      *) echo "$line" ;;
    esac
  done
}

# log4j calls InetAddress.getLocalHost() at class-init time and there is no
# resolver under --network none. One line of /etc/hosts fixes it, and duck
# does not start without it.
echo "127.0.0.1 $(hostname)" >> /etc/hosts
export TMPDIR=/work
export NODE_PATH=/stage/node_modules
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
if ! grep -q '^ready' /work/server.log; then
  echo "server never bound:"; cat /work/server.log; exit 2
fi
cat /versions
. /work/gen/creds.env
echo

# ---------------------------------------------------------------- the flow
#
# duck PRINTS the authorization URL and then waits on its own loopback
# listener, so the shell reads the URL out of duck's own output and hands it
# to the browser. That is the real division of labour: Cyberduck decides what
# the URL is, the browser decides what happens when it is opened, and neither
# is being imitated by the other.
run_duck() {
  : > /work/duck.out
  ( timeout 180 duck --profile /work/gen/pelfs.cyberduckprofile --assumeyes "$@" \
      < /dev/null > /work/duck.out 2>&1 ; echo $? > /work/duck.rc ) &
  duckpid=$!
  url=""
  for _ in $(seq 900); do
    url=$(grep -m1 -E "^http://127\.0\.0\.1:$PORT/oauth/authorize\?" /work/duck.out 2>/dev/null | tr -d '\r')
    [ -n "$url" ] && break
    if ! kill -0 $duckpid 2>/dev/null; then
      # A second connection reuses the refresh token and never revisits
      # /authorize, which is the property that makes one consent enough.
      wait $duckpid 2>/dev/null
      return "$(cat /work/duck.rc)"
    fi
    sleep 0.1
  done
  if [ -z "$url" ]; then
    echo "duck never asked for an authorization"; wait $duckpid 2>/dev/null; return 1
  fi
  echo "$url" > /work/authorize.url
  node /stage/drive.mjs consent "$url" > /work/browser.out 2>/work/browser.err
  brc=$?
  replay < /work/browser.out
  if [ -s /work/browser.err ]; then echo "--- browser stderr ---"; head -20 /work/browser.err; fi
  fails=$((fails+brc))
  wait $duckpid 2>/dev/null
  return "$(cat /work/duck.rc)"
}

echo "== a real Chromium drives the consent screen; real duck is the client =="
run_duck --list "dav://127.0.0.1:$PORT/dav/"
rc=$?
grep -E '^(hello\.txt|sub)$' /work/duck.out > /work/list.txt 2>/dev/null
if [ "$rc" = 0 ] && grep -qx hello.txt /work/list.txt && grep -qx sub /work/list.txt; then r=0; else r=1; fi
ck $r "duck:browser-oauth-list $(tr '\n' ' ' < /work/list.txt)"

# THE CHECK THIS WHOLE GATE IS FOR, stated as one line: a real browser
# completed the flow and the real client got a usable credential out of it.
# Before the two fixes this was 0 for 1 in every browser and 1 for 1 in curl.
grep -q 'Login successful' /work/duck.out && r=0 || r=1
ck $r "duck:login-successful  Cyberduck authenticated on what the browser authorized"

rm -f /work/got-hello.txt
run_duck --download "dav://127.0.0.1:$PORT/dav/hello.txt" /work/got-hello.txt
printf 'hello from a pelfs volume\n' > /work/want-hello.txt
cmp -s /work/want-hello.txt /work/got-hello.txt
ck $? "duck:browser-download  26 bytes over the Bearer token a click minted"

# ---------------------------------------------------------------- refusals
echo
echo "== the refusal pages, as a browser renders them =="
challenge=$(printf %s 'pelfs-probe-verifier-0123456789-abcdefghijk' \
  | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
node /stage/drive.mjs refusals "$ORIGIN" "$PELFS_CLIENT_ID" "$PELFS_REDIRECT" "$challenge" \
  > /work/refusals.out 2>/work/refusals.err
rrc=$?
replay < /work/refusals.out
if [ -s /work/refusals.err ]; then echo "--- browser stderr ---"; head -20 /work/refusals.err; fi
fails=$((fails+rrc))

# ------------------------------------------------------- the response headers
#
# Checked on the wire as well as in the browser, because these two header
# values ARE the two bug fixes and a Go test that asserts them can be deleted
# by the same edit that breaks them.
hdr=$(curl -sS -D - -o /dev/null -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$PELFS_CLIENT_ID&redirect_uri=$PELFS_REDIRECT&scope=pelfs.read&code_challenge=$challenge&code_challenge_method=S256" \
  | tr -d '\r')
echo "$hdr" | grep -qi '^referrer-policy: same-origin'
ck $? "hdr:referrer-policy    the consent page does not send no-referrer (which nulls the Origin)"
echo "$hdr" | grep -qi "^content-security-policy:.*form-action 'self' $PELFS_REDIRECT"
ck $? "hdr:form-action        the CSP names the client's callback, so the 303 is not blocked"

# ---------------------------------------------------------------- counters
kill -TERM "$srv" 2>/dev/null
wait "$srv" 2>/dev/null
echo
grep -E '^(counts|grant|client) ' /work/server.log
grep -q 'consented=true' /work/server.log
ck $? "server:consent-recorded a human's click in a real browser minted the grant"
grep -qE 'counts .*replays=0 ' /work/server.log
ck $? "server:no-replays      no code was exchanged twice"

echo
echo "== the authorization URL Cyberduck built =="
sed 's/client_id=[^&]*/client_id=<redacted>/' /work/authorize.url
echo
echo "== summary: $fails failing check(s) =="
exit $fails
