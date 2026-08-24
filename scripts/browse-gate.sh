#!/usr/bin/env bash
#
# THE WHOLE OF `pelfs browse`, END TO END, WITH NOTHING MOCKED.
#
# Every other gate proves one layer. internal/webapi replays a recorded
# SVAR contract, internal/localoauth drives its own authorization server
# over a memfs, scripts/oauth-cyberduck-docker.sh drives REAL Cyberduck
# against a hand-built test stack, and cmd/pelfs's unit tests exercise the
# route table against a fakeorigin-backed volume in-process. None of them
# runs the shipped binary. This does:
#
#   fakeorigin  ->  pelfs init  ->  pelfs browse --rw  ->  a browser
#   (curl)      ->  a WebDAV client (real duck)        ->  publish
#   ->  A SECOND, FRESH pelfs THAT HAS NEVER SEEN THE OVERLAY
#
# and it is that last step that makes this a durability gate rather than an
# HTTP one. A green publish status is a claim; `pelfs shell --ro` from an
# empty state directory reading the bytes back out of the federation is the
# fact. Everything before it can pass with a broken seal.
#
# The ten things it proves, in order:
#
#   1. the bootstrap token in the launch URL's fragment buys a session
#   2. GET /api/v1/files lists, POST /api/v1/upload writes  (U11)
#   3. POST /api/v1/download + GET /d/<ticket> serves bytes with NO
#      credential on the request, once, and 404s on replay          (U2)
#   4. POST /api/v1/credentials generates a .cyberduckprofile        (U8)
#   5. REAL duck completes the OAuth flow against it and lists, downloads
#      and uploads over the Bearer token it got                  (U6/U7)
#   6. POST /api/v1/publish reaches `done`
#   7. a fresh `pelfs shell --ro`, new state directory, reads every one of
#      those files out of the federation, byte for byte
#   8. A SECOND `pelfs browse` OVER THE SAME STATE DIRECTORY, and the
#      profile from step 4 -- NOT REGENERATED, the same bytes on disk --
#      reconnects WITH NO CLICK AT ALL. That is the feature: the grant the
#      first session issued is in the state directory, so duck's saved
#      refresh token is honoured by a process that never issued it and
#      /oauth/authorize is not visited even once.
#      A regenerated profile is byte-identical, and a different volume gets
#      a different identity.                                          (U7/U8)
#   9. a READ-ONLY `pelfs browse` cannot mint a writable DAV credential,
#      cannot publish, and its credential answers 403 (not 401) on a PUT
#  10. whatever duck CALLS the connection is a name pelfs chose
#
# It mounts a real filesystem in step 7, so it is Linux-only and refuses to
# run on a host that has not said it is expendable. Run it through
# scripts/browse-gate-docker.sh.
#
# Not `set -e` after the setup: every check runs and is reported, so one
# failure cannot hide the ones after it.
set -uo pipefail

if [ "${PELFS_MOUNT_TEST_OK:-}" != "1" ] && [ "${CI:-}" != "true" ]; then
  echo "refusing to mount on this host: run in CI, or via scripts/browse-gate-docker.sh," >&2
  echo "or set PELFS_MOUNT_TEST_OK=1 on a Linux machine you own." >&2
  exit 2
fi
[ "$(uname -s)" = "Linux" ] || { echo "this gate needs Linux FUSE" >&2; exit 2; }
[ -e /dev/fuse ] || { echo "no /dev/fuse" >&2; exit 1; }

fails=0
ck() { if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails+1)); fi; }

# log4j calls InetAddress.getLocalHost() at class-init time and there is no
# resolver under --network none. One line of /etc/hosts fixes it, and duck
# does not start without it.
echo "127.0.0.1 $(hostname)" >> /etc/hosts 2>/dev/null || true

WORK="${TMPDIR:-/tmp}/browse-gate"
mkdir -p "$WORK"
export TMPDIR="$WORK"
# NEVER the owner's real state root. --state-dir covers what a foreground
# session creates, but anything that registers machine-globally reads this.
export XDG_STATE_HOME="$WORK/xdg"
mkdir -p "$XDG_STATE_HOME"

PELFS="${PELFS_PREBUILT:-/stage}/pelfs"
FAKEORIGIN="${PELFS_PREBUILT:-/stage}/fakeorigin"
[ -x "$PELFS" ] || { echo "no pelfs binary at $PELFS" >&2; exit 1; }

cleanup() {
  [ -n "${BROWSE_PID:-}" ] && kill "$BROWSE_PID" 2>/dev/null
  [ -n "${AGAIN_PID:-}" ] && kill "$AGAIN_PID" 2>/dev/null
  [ -n "${OTHER_PID:-}" ] && kill "$OTHER_PID" 2>/dev/null
  [ -n "${ROBROWSE_PID:-}" ] && kill "$ROBROWSE_PID" 2>/dev/null
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null
  return 0
}
trap cleanup EXIT

echo "== versions =="
"$PELFS" version 2>&1 | head -2
duck --version 2>&1 | head -1
curl --version | head -1
echo

# ---------------------------------------------------------------- the federation
mkdir -p "$WORK/origin"
"$FAKEORIGIN" --root "$WORK/origin" --listen 127.0.0.1:18996 > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
for _ in $(seq 100); do
  curl -fsS "http://127.0.0.1:18996/" >/dev/null 2>&1 && break
  sleep 0.1
done
PREFIX="http://127.0.0.1:18996/browse/ns"

echo "== pelfs init =="
"$PELFS" init --state-dir "$WORK/state" "$PREFIX" > "$WORK/init.log" 2>&1
[ $? = 0 ] || { echo "init failed:"; cat "$WORK/init.log"; exit 1; }

# ---------------------------------------------------------------- the session
#
# --snapshot-interval 0 so that the ONLY generation this gate publishes is
# the one the button asked for: a periodic checkpoint landing mid-run would
# make step 7 pass without step 6 having worked.
echo "== pelfs browse --rw =="
"$PELFS" browse --rw --state-dir "$WORK/state" --snapshot-interval 0 \
  --stats-file "$WORK/browse-stats.json" "$PREFIX" > "$WORK/browse.log" 2>&1 &
BROWSE_PID=$!

LAUNCH=""
for _ in $(seq 300); do
  LAUNCH=$(grep -o 'http://127\.0\.0\.1:[0-9]*/#bt=[A-Za-z0-9_-]*' "$WORK/browse.log" 2>/dev/null | head -1)
  [ -n "$LAUNCH" ] && break
  kill -0 $BROWSE_PID 2>/dev/null || break
  sleep 0.1
done
if [ -z "$LAUNCH" ]; then
  echo "pelfs browse never printed a launch URL:"; cat "$WORK/browse.log"; exit 1
fi
ORIGIN="${LAUNCH%%/#bt=*}"
BOOTSTRAP="${LAUNCH##*#bt=}"
PORT="${ORIGIN##*:}"
FIRSTPORT="$PORT"
echo "   listening on $ORIGIN"

# BOTH PAGES must be servable BEFORE the volume is open — that is the whole
# reason runBrowse binds first — so this is asserted before anything waits.
#
#   /          the file manager: internal/webui's committed bundle. What is
#              checkable with curl is the shell and the hashed script it names,
#              because everything else on that page is rendered by the script.
#   /connect   the hand-written connection page, which carries the credential
#              desk this gate goes on to drive.
code=$(curl -s -o "$WORK/app.html" -w '%{http_code}' -H 'Sec-Fetch-Site: none' "$ORIGIN/")
[ "$code" = 200 ] && grep -q 'id="root"' "$WORK/app.html"
ck $? "app:served             $code, the file manager's shell at /"

# The asset the shell names, at the path it names it. There is no catch-all on
# this listener, so a bundle whose asset names moved is a white page — and this
# is the check that says so rather than a user finding out.
ASSET=$(sed -n 's/.*src="\.\/\(assets\/[^"]*\.js\)".*/\1/p' "$WORK/app.html" | head -1)
code=$(curl -s -o "$WORK/app.js" -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' "$ORIGIN/$ASSET")
[ "$code" = 200 ] && [ -s "$WORK/app.js" ]
ck $? "app:asset              $code for /$ASSET, the script the shell names"

# And the policy that lets that script run at all. The guard's default is
# `default-src 'none'`, which renders the app blank; appHandler replaces it.
csp=$(curl -s -o /dev/null -D - -H 'Sec-Fetch-Site: none' "$ORIGIN/" \
  | tr -d '\r' | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')
case "$csp" in
  *"script-src 'self'"*) case "$csp" in *unsafe-inline*) r=1 ;; *) r=0 ;; esac ;;
  *) r=1 ;;
esac
ck $r "app:csp                script-src 'self', no 'unsafe-inline'"

code=$(curl -s -o "$WORK/page.html" -w '%{http_code}' -H 'Sec-Fetch-Site: none' "$ORIGIN/connect")
[ "$code" = 200 ] && grep -q 'data-testid="connect-another-program"' "$WORK/page.html"
ck $? "page:served            $code, the connect panel at /connect"

# Each page names the other. A pair of surfaces on one port with no way
# between them is two apps sharing a port.
grep -q 'href="/"' "$WORK/page.html" && grep -q '/connect' "$WORK/app.js"
ck $? "pages:linked           /connect points at /, and the bundle at /connect"

# ---------------------------------------------------------------- 1. the session
#
# Every API call from here on carries the three things the page's fetch()
# carries and the guard requires: the session header, a provenance signal,
# and application/json on anything that mutates.
api() { # api METHOD PATH [BODY]
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -o "$WORK/out.json" -w '%{http_code}' -X "$m" \
      -H "X-Pelfs-Session: $SESSION" -H 'Sec-Fetch-Site: same-origin' \
      -H "Origin: $ORIGIN" -H 'Content-Type: application/json' \
      --data-binary "$body" "$ORIGIN$p"
  else
    curl -sS -o "$WORK/out.json" -w '%{http_code}' -X "$m" \
      -H "X-Pelfs-Session: $SESSION" -H 'Sec-Fetch-Site: same-origin' \
      -H "Origin: $ORIGIN" "$ORIGIN$p"
  fi
}

curl -sS -o "$WORK/session.json" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H "Origin: $ORIGIN" \
  -H 'Sec-Fetch-Site: same-origin' \
  --data-binary "{\"bootstrap\":\"$BOOTSTRAP\"}" \
  "$ORIGIN/api/v1/session" > "$WORK/session.code"
SESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session",""))' "$WORK/session.json" 2>/dev/null)
[ -n "$SESSION" ]
ck $? "session:exchange       the fragment bought a session token"

# The bootstrap token is single-use, which is the whole reason it may live
# in a history entry.
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H "Origin: $ORIGIN" \
  --data-binary "{\"bootstrap\":\"$BOOTSTRAP\"}" "$ORIGIN/api/v1/session")
[ "$code" = 401 ]
ck $? "session:single-use     replaying the launch link answers $code"

# The volume opens on its own goroutine. Wait on the page's own mechanism.
for _ in $(seq 600); do
  api GET /api/v1/info > /dev/null
  phase=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("phase",""))' "$WORK/out.json" 2>/dev/null)
  [ "$phase" = ready ] && break
  [ "$phase" = failed ] && { echo "the volume failed to open:"; cat "$WORK/out.json"; exit 1; }
  sleep 0.1
done
[ "$phase" = ready ]
ck $? "volume:ready           phase=$phase"

api GET /api/v1/info > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["mode"] == "read-write", s["mode"]
assert s["lease"] == "held", s["lease"]
PY
ck $? "volume:rw-and-leased   a --rw browse session took the branch"

# ---------------------------------------------------------------- 2. list + upload
code=$(api GET /api/v1/files)
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == []' "$WORK/out.json" 2>/dev/null
r=$?; [ "$code" = 200 ] || r=1
ck $r "api:list-empty         GET /api/v1/files on a fresh volume is []"

printf 'the browser wrote this\n' > "$WORK/hello.txt"
head -c 262144 /dev/urandom > "$WORK/blob.bin"
sha_want=$(sha256sum "$WORK/blob.bin" | cut -d' ' -f1)
for f in hello.txt blob.bin; do
  code=$(curl -sS -o "$WORK/upload.json" -w '%{http_code}' -X POST \
    -H "X-Pelfs-Session: $SESSION" -H 'Sec-Fetch-Site: same-origin' \
    -H "Origin: $ORIGIN" -F "file=@$WORK/$f" \
    "$ORIGIN/api/v1/upload?id=%2F")
  [ "$code" = 200 ] || { echo "upload $f: $code"; cat "$WORK/upload.json"; }
done
code=$(api GET /api/v1/files)
python3 - "$WORK/out.json" <<'PY'
import json, sys
ents = {e["id"]: e for e in json.load(open(sys.argv[1]))}
assert "/hello.txt" in ents and "/blob.bin" in ents, sorted(ents)
assert ents["/blob.bin"]["size"] == 262144, ents["/blob.bin"]
assert ents["/hello.txt"]["type"] == "file", ents["/hello.txt"]
PY
ck $? "api:upload-then-list   two uploads are in the listing with their sizes"

# A directory, and a file inside it, so the WebDAV client below has a tree
# to walk rather than a flat root.
code=$(api POST "/api/v1/files/%2F" '{"name":"sub","type":"folder"}')
[ "$code" = 200 ]
ck $? "api:mkdir              POST /api/v1/files/{id} answered $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H "X-Pelfs-Session: $SESSION" -H 'Sec-Fetch-Site: same-origin' \
  -H "Origin: $ORIGIN" -F "file=@$WORK/hello.txt" \
  "$ORIGIN/api/v1/upload?id=%2Fsub")
[ "$code" = 200 ]
ck $? "api:upload-nested      an upload into /sub answered $code"

# ---------------------------------------------------------------- 3. the ticket
api POST /api/v1/download '{"path":"/blob.bin"}' > /dev/null
TICKET=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("url",""))' "$WORK/out.json")
[ -n "$TICKET" ]
ck $? "ticket:mint            $TICKET"
# NO credential of any kind on this request: not the session header, not a
# provenance signal, not a cookie. That is the point of the mechanism.
curl -sS -o "$WORK/got-blob.bin" "$ORIGIN$TICKET"
cmp -s "$WORK/blob.bin" "$WORK/got-blob.bin"
ck $? "ticket:download        256 KiB with no credential on the URL"
code=$(curl -sS -o /dev/null -w '%{http_code}' "$ORIGIN$TICKET")
[ "$code" = 404 ]
ck $? "ticket:single-use      replaying the download URL answers $code"

# ---------------------------------------------------------------- 4. the profile
api POST /api/v1/credentials '{"label":"Cyberduck","write":true}' > /dev/null
python3 - "$WORK/out.json" "$WORK" <<'PY'
import json, os, sys
c = json.load(open(sys.argv[1]))
out = sys.argv[2]
for f in c["files"]:
    open(os.path.join(out, f["name"]), "w").write(f["content"])
    if f["name"].endswith(".cyberduckprofile"):
        open(os.path.join(out, "pelfs.cyberduckprofile"), "w").write(f["content"])
# NO PASSWORD IS IN HERE, because the response has none: /dav/* accepts an
# OAuth Bearer token and nothing else. What the gate needs is the callback
# URL (to check duck sends it verbatim) and the DAV URL.
assert "basic_password" not in c and "basic_user" not in c, sorted(c)
assert len(c["files"]) == 2, [f["name"] for f in c["files"]]
with open(os.path.join(out, "creds.env"), "w") as fh:
    fh.write("PELFS_REDIRECT=%s\nPELFS_DAV=%s\n"
             % (c["redirect_uri"], c["dav_url"]))
PY
r=$?
[ -s "$WORK/pelfs.cyberduckprofile" ] || r=1
ck $r "profile:generated      two files, no password, and a .cyberduckprofile among them"
. "$WORK/creds.env"
grep -q '<key>OAuth Client ID</key>' "$WORK/pelfs.cyberduckprofile" \
  && ! grep -q '<key>Authorization</key>' "$WORK/pelfs.cyberduckprofile"
ck $? "profile:oauth-switch   a non-blank client id, and no Authorization key"
CLIENT_ID=$(python3 - "$WORK/pelfs.cyberduckprofile" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
m = re.search(r"<key>OAuth Client ID</key>\s*<string>([^<]*)</string>", s)
print(m.group(1) if m else "")
PY
)
[ -n "$CLIENT_ID" ]
ck $? "profile:client-id      the client id is in the file"

# THE COPY STEP 8 REINSTALLS NOTHING FROM. Kept byte for byte, because the
# whole claim under test later is that a user does not have to download this
# file again -- and a claim about "the file the user already has" needs the
# file the user already had.
cp "$WORK/pelfs.cyberduckprofile" "$WORK/installed.cyberduckprofile"

# ---------------------------------------------------------------- 5. real duck
#
# consent() plays the browser: fetch the authorization screen, take the
# ticket out of it, press Authorize with the headers a browser sends for a
# same-origin form POST, and hand the 303 to Cyberduck's own loopback
# listener. Every byte on the wire is the real client's and the real
# server's; what curl replaces is a human's click, not a protocol.
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
# ONE THING CHANGED SHAPE HERE, and it is the fix for "when I click
# Authorize, nothing happens in the browser". The consent POST used to
# answer 303 straight to Cyberduck's loopback listener, which answers by
# closing the connection -- so a real user's last act in the flow was to land
# on a dead tab at the exact moment everything had worked. It answers a
# SUCCESS PAGE now, and the authorization is delivered from one hidden frame
# on that page. So the line below reads the delivery URL out of the page
# instead of out of a Location header, and `&amp;` is unescaped because the
# URL lives in an HTML attribute now.
consent() {
  url="$1"
  curl -sS -o "$WORK/consent.html" \
    -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' "$url" >/dev/null
  ticket=$(grep -o 'name="consent_ticket" value="[^"]*"' "$WORK/consent.html" \
           | head -1 | sed 's/.*value="//; s/"$//')
  [ -n "$ticket" ] || { echo "no consent ticket in the page"; return 1; }
  echo "$ticket" > "$WORK/consent.ticket"
  curl -sS -o "$WORK/connected.html" -D "$WORK/connected.hdr" \
    -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' \
    --data-urlencode "consent_ticket=$ticket" --data-urlencode "decision=allow" \
    "$ORIGIN/oauth/authorize" >/dev/null
  loc=$(deliver_url "$WORK/connected.html")
  [ -n "$loc" ] || { echo "no delivery frame on the page the consent POST answered"; return 1; }
  echo "$loc" > "$WORK/deliver.url"
  # Cyberduck's loopback HttpServer takes it from here; it answers by
  # closing the connection, so curl's "empty reply" is expected. In a real
  # browser this request is the hidden frame's.
  curl -s -o /dev/null "$loc" || true
}

# deliver_url is the src of the success page's one hidden frame: byte for
# byte the URL the 303 used to name.
deliver_url() {
  sed -n 's/.*<iframe class="deliver" src="\([^"]*\)".*/\1/p' "$1" \
    | head -1 | sed 's/&amp;/\&/g'
}

# oauth_flow CLIENT_ID REDIRECT SCOPE -- the whole authorization-code + PKCE
# flow, and it prints the access token.
#
# curl and python3 between them are a WebDAV client with no profile format,
# which is exactly what every non-Cyberduck client has to be now that there is
# no password path: rclone, WinSCP, a shell script. It leaves the token
# response in $WORK/flow-token.json so a caller can take the refresh token
# too, which is what step 8 reconnects with.
#
# SCOPE must be URL-encoded (a space is %20).
oauth_flow() {
  cid="$1"; redirect="$2"; scope="$3"
  verifier=pelfs-browse-gate-verifier-0123456789-abcdef
  challenge=$(python3 -c '
import base64, hashlib, sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).decode().rstrip("="))
' "$verifier")
  curl -sS -o "$WORK/flow-consent.html" \
    -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' \
    "$ORIGIN/oauth/authorize?response_type=code&client_id=$cid&redirect_uri=$redirect&scope=$scope&code_challenge=$challenge&code_challenge_method=S256" >/dev/null
  ticket=$(grep -o 'name="consent_ticket" value="[^"]*"' "$WORK/flow-consent.html" \
           | head -1 | sed 's/.*value="//; s/"$//')
  [ -n "$ticket" ] || { echo "no consent ticket" >&2; return 1; }
  curl -sS -o "$WORK/flow-connected.html" \
    -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' \
    --data-urlencode "consent_ticket=$ticket" --data-urlencode "decision=allow" \
    "$ORIGIN/oauth/authorize" >/dev/null
  code=$(deliver_url "$WORK/flow-connected.html" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "$code" ] || { echo "no code on the success page" >&2; return 1; }
  curl -sS -o "$WORK/flow-token.json" -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" --data-urlencode "redirect_uri=$redirect" \
    --data-urlencode "client_id=$cid" "$ORIGIN/oauth/token" >/dev/null
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("access_token",""))' \
    "$WORK/flow-token.json"
}

# duck PRINTS the authorization URL and then waits on its own callback
# server, so a headless box needs no browser at all.
run_duck() {
  : > "$WORK/duck.out"
  ( timeout 180 duck --profile "$WORK/pelfs.cyberduckprofile" --assumeyes "$@" \
      < /dev/null > "$WORK/duck.out" 2>&1 ; echo $? > "$WORK/duck.rc" ) &
  duckpid=$!
  url=""
  for _ in $(seq 1200); do
    url=$(grep -m1 -E "^http://127\.0\.0\.1:$PORT/oauth/authorize\?" "$WORK/duck.out" 2>/dev/null | tr -d '\r')
    [ -n "$url" ] && break
    kill -0 $duckpid 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$url" ]; then
    # A second and later connection reuses the refresh token and never
    # revisits /authorize, which is the property that makes one consent
    # enough. So no URL is not automatically a failure.
    wait $duckpid 2>/dev/null
    [ "$(cat "$WORK/duck.rc")" = 0 ]
    return $?
  fi
  echo "$url" > "$WORK/authorize.url"
  consent "$url" || return 1
  wait $duckpid 2>/dev/null
  [ "$(cat "$WORK/duck.rc")" = 0 ]
}

run_duck --list "dav://127.0.0.1:$PORT/dav/"
rc=$?
grep -E '^(hello\.txt|blob\.bin|sub)$' "$WORK/duck.out" > "$WORK/list.txt" 2>/dev/null
if [ "$rc" = 0 ] && grep -qx hello.txt "$WORK/list.txt" \
   && grep -qx blob.bin "$WORK/list.txt" && grep -qx sub "$WORK/list.txt"; then r=0; else r=1; fi
ck $r "duck:oauth-list        $(tr '\n' ' ' < "$WORK/list.txt")"

# No password anywhere: a non-blank client id turns OAuth on AND password
# auth off in the same move, so nothing is ever asked for and nothing sent.
if grep -q 'Authenticating as anonymous' "$WORK/duck.out" \
   && grep -q 'Login successful' "$WORK/duck.out" \
   && ! grep -qi 'password' "$WORK/duck.out"; then r=0; else r=1; fi
ck $r "duck:no-password-path  authenticated as anonymous, no password anywhere"

# ---- WHAT THE HUMAN SEES, which is the half no protocol check covers.
#
# The report: "when I click Authorize, nothing happens in the browser. I'd
# expect a 'success' type page. If I click it twice, I get an error." Both
# halves are checked here on the artifacts consent() just left behind: the
# page the POST answered, and what a second press of the same screen does.
status=$(head -1 "$WORK/connected.hdr" | tr -d '\r' | awk '{print $2}')
if [ "$status" = 200 ] && ! grep -qi '^location:' "$WORK/connected.hdr" \
   && grep -q 'Connected' "$WORK/connected.html" \
   && grep -q 'Cyberduck' "$WORK/connected.html" \
   && grep -q "$PREFIX" "$WORK/connected.html" \
   && grep -q 'close this tab' "$WORK/connected.html"; then r=0; else r=1; fi
ck $r "consent:success-page   pressing Authorize answered $status with a page a person can read"

# The delivery is a frame on that page, not a redirect the user is dumped
# on. Cyberduck got its code from it -- duck:oauth-list above is the proof
# -- and this is the check that says WHERE it came from.
if [ -s "$WORK/deliver.url" ] && grep -q "$PELFS_REDIRECT" "$WORK/deliver.url" \
   && grep -q 'code=' "$WORK/deliver.url"; then r=0; else r=1; fi
ck $r "consent:frame-delivers the authorization reaches the client from the page's own frame"

# THE SECOND PRESS. Same ticket, same screen. It must NOT be an error, must
# NOT mint anything, and must NOT re-deliver the code -- a second delivery
# would be a code presented twice, which revokes the grant.
curl -sS -o "$WORK/again-press.html" -D "$WORK/again-press.hdr" \
  -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' \
  --data-urlencode "consent_ticket=$(cat "$WORK/consent.ticket")" \
  --data-urlencode "decision=allow" "$ORIGIN/oauth/authorize" >/dev/null
status=$(head -1 "$WORK/again-press.hdr" | tr -d '\r' | awk '{print $2}')
if [ "$status" = 200 ] && grep -q 'Already connected' "$WORK/again-press.html" \
   && ! grep -q 'iframe class="deliver"' "$WORK/again-press.html"; then r=0; else r=1; fi
ck $r "consent:double-press   a second press answered $status \"already connected\", issuing nothing"

# And the connection the first press bought is untouched by the second.
api GET /api/v1/credentials > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert len(s["grants"]) == 1, s["grants"]
PY
ck $? "consent:press-is-safe  the second press did not cost the user their connection"

# ---- and what the screen says, which is now three facts and two buttons.
if grep -q 'Cyberduck' "$WORK/consent.html" && grep -q "$PREFIX" "$WORK/consent.html" \
   && grep -qi 'read AND WRITE' "$WORK/consent.html"; then r=0; else r=1; fi
ck $r "consent:names-the-ask  the screen names the program, the volume and the scope"
if grep -q "$PELFS_REDIRECT" "$WORK/consent.html" \
   || grep -q 'one thing standing' "$WORK/consent.html"; then r=1; else r=0; fi
ck $r "consent:no-filler      no callback row and no essay on the screen"

url=$(cat "$WORK/authorize.url" 2>/dev/null || echo)
case "$url" in *code_challenge_method=S256*) r=0;; *) r=1;; esac
ck $r "duck:pkce-s256         Cyberduck sent code_challenge_method=S256 unprompted"
case "$url" in *"redirect_uri=$PELFS_REDIRECT"*) r=0;; *) r=1;; esac
ck $r "duck:redirect-verbatim the profile's exact callback, port and all"
case "$url" in *"client_id=$CLIENT_ID"*) r=0;; *) r=1;; esac
ck $r "duck:client-id         the profile's client_id, verbatim"

rm -f "$WORK/duck-blob.bin"
run_duck --download "dav://127.0.0.1:$PORT/dav/blob.bin" "$WORK/duck-blob.bin"
cmp -s "$WORK/blob.bin" "$WORK/duck-blob.bin"
ck $? "duck:oauth-download    256 KiB over Authorization: Bearer, byte for byte"

printf 'Cyberduck wrote this\n' > "$WORK/from-duck.txt"
run_duck --upload "dav://127.0.0.1:$PORT/dav/sub/" "$WORK/from-duck.txt"
ck $? "duck:oauth-upload      a write into the same overlay the JSON API writes"

# And the write is visible to the JSON API, which is the two surfaces
# sharing one binding rather than two.
code=$(api GET "/api/v1/files/%2Fsub")
python3 - "$WORK/out.json" <<'PY'
import json, sys
ids = {e["id"] for e in json.load(open(sys.argv[1]))}
assert "/sub/from-duck.txt" in ids, sorted(ids)
PY
ck $? "wiring:one-binding     what duck uploaded is in the JSON listing"

# The grant the click created, on the page's own credential list.
api GET /api/v1/credentials > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["writable"] is True, s
assert len(s["clients"]) == 1, s["clients"]
assert s["clients"][0]["consented"] is True, s["clients"][0]
assert s["clients"][0]["grants"] >= 1, s["clients"][0]
assert s["grants"], s
assert "pelfs.write" in s["grants"][0]["scopes"], s["grants"][0]
# No secret in the inventory at all: it is a document the page keeps on
# screen, and there is no password anywhere on this listener any more.
body = json.dumps(s)
assert "password" not in body.lower(), body
assert s["grants"][0]["persistent"] is True, s["grants"][0]
PY
ck $? "creds:list             one consented client, one grant, no secret"

# ---- THE CONNECTION STEP 8 RECONNECTS WITH.
#
# One more authorization for the SAME client the installed profile carries,
# driven by curl, and the refresh token is kept on disk here the way a WebDAV
# client keeps it in its own credential store. Step 8 presents it to a
# DIFFERENT `pelfs browse` process and expects it to work.
#
# WHY NOT JUST USE duck's OWN CACHE: `duck --profile X dav://host/path` is an
# ad-hoc URL, not a saved bookmark, and Cyberduck attaches OAuth tokens to a
# bookmark identity -- so the CLI re-runs the flow on every invocation and has
# no cross-process token to test with. (Three grants come out of this session
# for exactly that reason.) The GUI, and any client that saves a bookmark,
# holds the token the way this file does. So the protocol half is asserted
# with a client that does keep it, and the real-duck half below asserts what
# real duck actually does with the profile.
ACCESS=$(oauth_flow "$CLIENT_ID" "$PELFS_REDIRECT" "pelfs.read%20pelfs.write")
[ -n "$ACCESS" ]
ck $? "grant:issued           a client with no profile format completed the real flow"
python3 - "$WORK/flow-token.json" "$WORK/saved-refresh" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
assert t.get("refresh_token"), t
assert t.get("expires_in", 0) > 0, t
open(sys.argv[2], "w").write(t["refresh_token"])
PY
ck $? "grant:refresh-token    it came back with a refresh token and an expiry"
api GET /api/v1/credentials > /dev/null
python3 - "$WORK/out.json" "$WORK/saved-grant-ref" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
newest = max(s["grants"], key=lambda g: g["issued"])
assert newest["persistent"] is True, newest
open(sys.argv[2], "w").write(newest["ref"])
PY
ck $? "grant:persistent       the new connection is recorded in the state directory"

# ---------------------------------------------------------------- 6. publish
code=$(api POST /api/v1/publish '{}')
[ "$code" = 202 ]
ck $? "publish:202            the button answered $code, not a synchronous 200"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("job",""))' "$WORK/out.json")
state=""
for _ in $(seq 1200); do
  api GET /api/v1/info > /dev/null
  state=$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("publish") or {}).get("state",""))' "$WORK/out.json" 2>/dev/null)
  case "$state" in done|failed) break;; esac
  sleep 0.1
done
[ "$state" = done ]
ck $? "publish:done           job $JOB reached $state"
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["generation"] > 0, s["generation"]
assert s["staged_files"] == 0, s
assert s["publish"]["reason"] == "user", s["publish"]
print("   generation %d, %s" % (s["generation"], s["publish"]["summary"]))
PY
ck $? "publish:generation     the page reports the new generation and nothing staged"

# A PUBLISH IS NOT AN EXIT, and until this block the gate could not tell.
# The three assertions above are all about the publish, and the very next
# line used to be `kill -TERM` -- so a session that ended on its own between
# the 202 and the signal was indistinguishable from one the gate stopped.
# That is exactly the report ("after the first publish the pelfs browse
# server shuts down automatically") this gate was green through.
#
# Three things, in the order a user meets them: the process is up, the data
# plane still reaches the volume, and the event stream that was open across
# the publish is still delivering.
kill -0 "$BROWSE_PID" 2>/dev/null
ck $? "publish:still-running  the session is still up after publishing"
code=$(api GET /api/v1/files)
[ "$code" = 200 ]
ck $? "publish:still-serving  the volume still lists after publishing ($code)"
# `timeout` returns 124 when it cuts the stream off, which is the PASS here:
# a stream that is still open is one that has to be killed. A stream the
# server closed returns 0 with `event: bye` in it.
timeout 3 curl -sS -N -H 'Sec-Fetch-Site: same-origin' \
  "$ORIGIN/events?s=$SESSION" > "$WORK/post-publish.sse" 2>/dev/null
[ $? = 124 ] && ! grep -q '^event: bye' "$WORK/post-publish.sse"
ck $? "publish:stream-open    the event stream survives the publish"
grep -q '"phase": *"ready"' "$WORK/post-publish.sse" || grep -q '"phase":"ready"' "$WORK/post-publish.sse"
ck $? "publish:still-ready    a stream opened after the publish reports ready"

# Stop the session the way Ctrl-C does, so the lease is released and the
# seal at exit runs, before anything else opens the branch.
kill -TERM "$BROWSE_PID" 2>/dev/null
wait "$BROWSE_PID" 2>/dev/null
BROWSE_RC=$?
BROWSE_PID=""
[ "$BROWSE_RC" = 0 ]
ck $? "session:clean-exit     pelfs browse exited $BROWSE_RC"
[ ! -f "$WORK/origin/browse/ns/meta/lease-main.json" ]
ck $? "session:lease-released the branch lease is gone after a clean exit"

# ---------------------------------------------------------------- 7. THE FEDERATION
#
# A FRESH pelfs, a FRESH state directory, and a real kernel mount. Nothing
# of the session that wrote these bytes is reachable from here: no overlay,
# no gencache, no signing key of its own. If the seal did not put the bytes
# in the federation, this is where it shows.
echo
echo "== a fresh pelfs reads the volume back out of the federation =="
mkdir -p "$WORK/verify"
"$PELFS" shell --ro --state-dir "$WORK/verify" "$PREFIX" -- /bin/sh -c '
set -e
echo "--- ls ---"
ls -1
ls -1 sub
echo "--- cat ---"
cat hello.txt
cat sub/from-duck.txt
sha256sum blob.bin | cut -d" " -f1
' > "$WORK/verify.log" 2>&1
rc=$?
cat "$WORK/verify.log"
[ "$rc" = 0 ]
ck $? "federation:mounted     pelfs shell --ro exited $rc from an empty state dir"
grep -qx 'the browser wrote this' "$WORK/verify.log"
ck $? "federation:api-upload  the file the JSON API uploaded is in the federation"
grep -qx 'Cyberduck wrote this' "$WORK/verify.log"
ck $? "federation:dav-upload  the file CYBERDUCK uploaded is in the federation"
grep -qx "$sha_want" "$WORK/verify.log"
ck $? "federation:bytes-exact 256 KiB of random data, sha256 identical"

# ---------------------------------------------------------------- 8. THE RESTART
#
# THE CHECK THIS FEATURE EXISTS FOR, and the one docs/known-issues.md said
# nothing could make ("no gate runs two `pelfs browse` processes in sequence
# against one saved profile"). This one does.
#
# A SECOND `pelfs browse` over the SAME state directory, and then real duck
# pointed at $WORK/installed.cyberduckprofile -- the copy taken in step 4,
# before this session existed, and not touched since. Nothing is regenerated
# and nothing is reinstalled first: if the client id in that file does not
# name a client this new process knows, duck's flow ends on "This is not an
# authorization request pelfs issued" and this section goes red.
#
# DUCK'S OWN TOKEN CACHE IS LEFT EXACTLY WHERE THE FIRST SESSION PUT IT, and
# that is now the SUBJECT of the check rather than a complication in it.
#
# The history is worth keeping, because the assertion inverted. The refresh
# token used to die with the process, so a second session always met a client
# holding a stale one; this gate measured that and asserted the honest
# outcome, which was "duck re-runs the authorization flow and one consent
# click is all it costs". The owner asked twice why that click was there, and
# the answer was wrong: persisting CONSENT would reinstate the attack the
# consent screen exists to stop, but persisting the ISSUED GRANT never
# touches /oauth/authorize at all. So the grant is in the state directory
# now, and what this section proves is the stronger thing:
#
#   the same bookmark, over a restart, connects with NO BROWSER
#   INTERACTION OF ANY KIND -- no consent screen, no authorization request.
#
# The click is still required to CREATE a grant, and step 5's checks above
# are what hold that line.
echo
echo "== a SECOND pelfs browse, and the profile the user already installed =="
"$PELFS" browse --rw --state-dir "$WORK/state" --snapshot-interval 0 \
  "$PREFIX" > "$WORK/again.log" 2>&1 &
AGAIN_PID=$!
LAUNCH=""
for _ in $(seq 300); do
  LAUNCH=$(grep -o 'http://127\.0\.0\.1:[0-9]*/#bt=[A-Za-z0-9_-]*' "$WORK/again.log" 2>/dev/null | head -1)
  [ -n "$LAUNCH" ] && break
  kill -0 $AGAIN_PID 2>/dev/null || break
  sleep 0.1
done
if [ -z "$LAUNCH" ]; then
  echo "the second session never printed a launch URL:"; cat "$WORK/again.log"; exit 1
fi
ORIGIN="${LAUNCH%%/#bt=*}"
BOOTSTRAP="${LAUNCH##*#bt=}"
PORT="${ORIGIN##*:}"
# The probe's first port, twice: the earlier session has exited, so 8443
# (or whatever the probe reached past what this host already had) is free
# again and the restart lands on it. That is what makes an installed
# profile -- which carries Default Port and both OAuth URLs -- still good.
[ "$PORT" = "$FIRSTPORT" ]
ck $? "restart:same-port      $PORT twice: the probe lands where it landed before"

curl -sS -o "$WORK/again-session.json" -X POST \
  -H 'Content-Type: application/json' -H "Origin: $ORIGIN" \
  -H 'Sec-Fetch-Site: same-origin' \
  --data-binary "{\"bootstrap\":\"$BOOTSTRAP\"}" "$ORIGIN/api/v1/session" >/dev/null
SESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session",""))' "$WORK/again-session.json")
[ -n "$SESSION" ]
ck $? "restart:session        the new session token"
for _ in $(seq 600); do
  api GET /api/v1/info > /dev/null
  phase=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("phase",""))' "$WORK/out.json" 2>/dev/null)
  [ "$phase" = ready ] && break
  [ "$phase" = failed ] && { echo "the second session failed to open:"; cat "$WORK/out.json"; break; }
  sleep 0.1
done
[ "$phase" = ready ]
ck $? "restart:ready          the same state directory reopened, phase=$phase"

# BEFORE anything asks for a profile or connects: the credential the user
# installed AND the connection they authorized are both already in the
# inventory, adopted from the state directory.
api GET /api/v1/credentials > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert len(s["clients"]) == 1, s["clients"]
c = s["clients"][0]
assert c["label"] == "Cyberduck", c
assert c["persistent"] is True, c
assert c["write"] is True, c
# THE STANDING CREDENTIALS, and the page can see them. This is what a user
# has to be able to look at and kill, because they are the only thing pelfs
# issues that outlives the process.
assert s["grants"], s
for g in s["grants"]:
    assert g["persistent"] is True, g
    assert g["refresh_expires"], g
    assert "pelfs.write" in g["scopes"], g
assert c["grants"] == len(s["grants"]), (c, s["grants"])
# What must NOT have survived: consent is per process and is never
# remembered at /oauth/authorize.
assert c["consented"] is False, c
# And no secret in the inventory, still.
body = json.dumps(s)
assert "password" not in body.lower(), body
PY
ck $? "restart:adopted        the profile AND the connection are listed, consent is not"

# The identity file, where it is and what it is not. A secret in the state
# directory is fine (the signing key is there and is stronger); a secret
# anywhere else is not.
[ -f "$WORK/state/browse-identity.key" ]
ck $? "restart:identity-file  the key is in the state directory"
mode=$(stat -c '%a' "$WORK/state/browse-identity.key" 2>/dev/null)
[ "$mode" = 600 ]
ck $? "restart:identity-mode  mode $mode"
if grep -q "$CLIENT_ID" "$WORK/state/browse-identity.key"; then r=1; else r=0; fi
ck $r "restart:no-id-on-disk  the client id is derived, not stored"
# THE SECOND FILE, which is the new one and the one that has to be judged.
# It holds an HMAC of a refresh token and never the token, which is what
# makes it a verifier rather than a credential.
[ -f "$WORK/state/browse-grants.key" ]
ck $? "restart:grant-file     the grant roster is in the state directory"
mode=$(stat -c '%a' "$WORK/state/browse-grants.key" 2>/dev/null)
[ "$mode" = 600 ]
ck $? "restart:grant-mode     mode $mode"
if grep -q 'refresh_mac' "$WORK/state/browse-grants.key" \
   && grep -q 'NEVER the token' "$WORK/state/browse-grants.key" \
   && ! grep -q "$CLIENT_ID" "$WORK/state/browse-grants.key"; then r=0; else r=1; fi
ck $r "restart:grant-contents an HMAC and a note, no client id, no token"
# NO PASSWORD EXISTS AT ALL any more -- not on disk, not in a response, not
# in a challenge. The last of those is the one a client meets.
code=$(curl -sS -o /dev/null -D "$WORK/challenge.hdr" -w '%{http_code}' \
  -X PROPFIND -H 'Depth: 0' "$ORIGIN/dav/")
if [ "$code" = 401 ] && grep -qi '^www-authenticate: *bearer' "$WORK/challenge.hdr" \
   && ! grep -qi '^www-authenticate: *basic' "$WORK/challenge.hdr"; then r=0; else r=1; fi
ck $r "dav:bearer-only        an anonymous PROPFIND is offered Bearer and nothing else"

# ---- THE FEATURE: THE CONNECTION FROM THE LAST SESSION, IN THIS ONE, WITH
#      NOBODY TOUCHING A BROWSER.
#
# The refresh token saved in step 5 was issued by a process that has since
# exited. Presenting it here goes to POST /oauth/token and nowhere else:
# there is no authorization request in a refresh, so there is no consent
# screen in the path and nothing for a page the user visited to drive. That
# distinction -- persisting the GRANT is not persisting CONSENT -- is the
# whole argument, and this is the check that it is true rather than merely
# argued.
SAVED=$(cat "$WORK/saved-refresh")
curl -sS -o "$WORK/refresh.json" -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=$SAVED" \
  --data-urlencode "client_id=$CLIENT_ID" "$ORIGIN/oauth/token" >/dev/null
NEWACCESS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("access_token",""))' "$WORK/refresh.json")
[ -n "$NEWACCESS" ]
ck $? "restart:no-consent     the token saved LAST session was renewed with NO authorization request"
code=$(curl -sS -o "$WORK/refresh-get.txt" -w '%{http_code}' \
  -H "Authorization: Bearer $NEWACCESS" "$ORIGIN/dav/hello.txt")
r=0; [ "$code" = 200 ] || r=1; cmp -s "$WORK/hello.txt" "$WORK/refresh-get.txt" || r=1
ck $r "restart:no-click-read  it read a file over WebDAV ($code), no browser involved"

# AND NOTHING WENT THROUGH /authorize. `consented` is set when a code is
# minted and is per process, so a false here says no authorization happened
# in this session at all -- which is the same claim as "no consent screen",
# made by the server rather than by the absence of a file.
api GET /api/v1/credentials > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["clients"][0]["consented"] is False, s["clients"][0]
assert s["grants"], s
# `last_used` is omitted when zero, so this is a get: what it says is that
# at least one adopted grant has actually been used in THIS process.
assert any(g.get("last_used") for g in s["grants"]), s["grants"]
PY
ck $? "restart:no-authorize   no authorization was requested in this session"

# ---- REVOCATION HAS TO REACH THE DISK, or the button on the page is a lie.
GRANT=$(cat "$WORK/saved-grant-ref")
code=$(api POST /api/v1/credentials/revoke "{\"grant\":\"$GRANT\"}")
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["revoked"] is True' "$WORK/out.json"
r=$?; [ "$code" = 200 ] || r=1
ck $r "revoke:grant           revoking the standing connection answered $code"
if grep -q "$GRANT" "$WORK/state/browse-grants.key"; then r=1; else r=0; fi
ck $r "revoke:off-disk        the revoked grant is gone from the state directory"
curl -sS -o "$WORK/refresh2.json" -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "refresh_token=$SAVED" \
  --data-urlencode "client_id=$CLIENT_ID" "$ORIGIN/oauth/token" >/dev/null
grep -q 'invalid_grant' "$WORK/refresh2.json"
ck $? "revoke:token-dead      the revoked connection's refresh token is refused"

# ---- and REAL duck, the OLD profile, no reinstall, in this same session.
#
# What this proves and what it does not. It proves the installed profile is
# still a profile this process recognises -- the client id is derived from the
# state directory (identity.go), so the file the user installed last week
# still names a client. It does NOT prove the no-click property: `duck
# --profile X dav://host/path` is an ad-hoc URL rather than a saved bookmark,
# and Cyberduck attaches OAuth tokens to a bookmark identity, so the CLI
# re-runs the flow on every invocation whatever the server does. The check
# above is the one that proves the feature, with a client that does keep its
# token.
cp "$WORK/installed.cyberduckprofile" "$WORK/pelfs.cyberduckprofile"
rm -f "$WORK/reconnect.txt" "$WORK/authorize.url"
run_duck --download "dav://127.0.0.1:$PORT/dav/hello.txt" "$WORK/reconnect.txt"
rc=$?
cmp -s "$WORK/hello.txt" "$WORK/reconnect.txt"
r=$?; [ "$rc" = 0 ] || r=1
ck $r "restart:reconnected    the profile installed LAST session downloaded a file THIS session"
if grep -q 'Login successful' "$WORK/duck.out"; then r=0; else r=1; fi
ck $r "restart:logged-in      real duck authenticated against the restarted session"
case "$(cat "$WORK/authorize.url" 2>/dev/null)" in
  *"client_id=$CLIENT_ID"*) r=0 ;;
  *) r=1 ;;
esac
ck $r "restart:same-client-id duck sent the client id from the old profile, verbatim"

# The regenerated profile is the same FILE, which is why reinstalling is
# unnecessary rather than merely tolerable.
api POST /api/v1/credentials '{"label":"Cyberduck","write":true}' > /dev/null
python3 - "$WORK/out.json" "$WORK/regenerated.cyberduckprofile" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
for f in c["files"]:
    if f["name"].endswith(".cyberduckprofile"):
        open(sys.argv[2], "w").write(f["content"])
        break
else:
    raise SystemExit("no profile in the response")
PY
cmp -s "$WORK/installed.cyberduckprofile" "$WORK/regenerated.cyberduckprofile"
ck $? "restart:byte-identical the regenerated profile is the installed one, byte for byte"

# A DIFFERENT VOLUME IS A DIFFERENT IDENTITY. Same label, same write flag,
# same machine, its own state directory: the client id must not be the same
# string, or one volume's profile would open another's files.
"$PELFS" init --state-dir "$WORK/state2" "$PREFIX-two" > "$WORK/init2.log" 2>&1
[ $? = 0 ] || { echo "second init failed:"; cat "$WORK/init2.log"; }
"$PELFS" browse --rw --state-dir "$WORK/state2" --snapshot-interval 0 \
  "$PREFIX-two" > "$WORK/other.log" 2>&1 &
OTHER_PID=$!
OTHERLAUNCH=""
for _ in $(seq 300); do
  OTHERLAUNCH=$(grep -o 'http://127\.0\.0\.1:[0-9]*/#bt=[A-Za-z0-9_-]*' "$WORK/other.log" 2>/dev/null | head -1)
  [ -n "$OTHERLAUNCH" ] && break
  kill -0 $OTHER_PID 2>/dev/null || break
  sleep 0.1
done
OTHERORIGIN="${OTHERLAUNCH%%/#bt=*}"
# A CONCURRENT second volume steps to the next port, because the probe is
# first-come-first-served and the first session still holds its own. Note
# what this does NOT assert any more: the port does not identify the
# volume. Which volume is on which port depends on start order, and what
# keeps a bookmark off the wrong volume is the profile's Vendor (keyed on
# the volume) plus a client_id that names nothing in the other session --
# see docs/known-issues.md KL-20.
[ -n "$OTHERORIGIN" ] && [ "$OTHERORIGIN" != "$ORIGIN" ]
ck $? "volumes:own-port       a concurrent second volume steps to the next port"
curl -sS -o "$WORK/other-session.json" -X POST \
  -H 'Content-Type: application/json' -H "Origin: $OTHERORIGIN" \
  -H 'Sec-Fetch-Site: same-origin' \
  --data-binary "{\"bootstrap\":\"${OTHERLAUNCH##*#bt=}\"}" \
  "$OTHERORIGIN/api/v1/session" >/dev/null
OTHERSESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session",""))' "$WORK/other-session.json")
curl -sS -o "$WORK/other-creds.json" -X POST \
  -H "X-Pelfs-Session: $OTHERSESSION" -H 'Sec-Fetch-Site: same-origin' \
  -H "Origin: $OTHERORIGIN" -H 'Content-Type: application/json' \
  --data-binary '{"label":"Cyberduck","write":true}' \
  "$OTHERORIGIN/api/v1/credentials" >/dev/null
OTHER_ID=$(python3 - "$WORK/other-creds.json" <<'PY'
import json, re, sys
c = json.load(open(sys.argv[1]))
for f in c.get("files", []):
    if f["name"].endswith(".cyberduckprofile"):
        m = re.search(r"<key>OAuth Client ID</key>\s*<string>([^<]*)</string>", f["content"])
        print(m.group(1) if m else "")
        break
PY
)
[ -n "$OTHER_ID" ] && [ "$OTHER_ID" != "$CLIENT_ID" ]
ck $? "volumes:own-identity   the same label on another volume is another client"
kill -TERM "$OTHER_PID" 2>/dev/null
wait "$OTHER_PID" 2>/dev/null
OTHER_PID=""

kill -TERM "$AGAIN_PID" 2>/dev/null
wait "$AGAIN_PID" 2>/dev/null
AGAIN_RC=$?
AGAIN_PID=""
[ "$AGAIN_RC" = 0 ]
ck $? "restart:clean-exit     the second session exited $AGAIN_RC"

# ---------------------------------------------------------------- 9. read-only
echo
echo "== a read-only pelfs browse over the same published generation =="
"$PELFS" browse --state-dir "$WORK/rostate" "$PREFIX" > "$WORK/robrowse.log" 2>&1 &
ROBROWSE_PID=$!
ROLAUNCH=""
for _ in $(seq 300); do
  ROLAUNCH=$(grep -o 'http://127\.0\.0\.1:[0-9]*/#bt=[A-Za-z0-9_-]*' "$WORK/robrowse.log" 2>/dev/null | head -1)
  [ -n "$ROLAUNCH" ] && break
  kill -0 $ROBROWSE_PID 2>/dev/null || break
  sleep 0.1
done
if [ -z "$ROLAUNCH" ]; then
  echo "the read-only session never printed a launch URL:"; cat "$WORK/robrowse.log"; exit 1
fi
ORIGIN="${ROLAUNCH%%/#bt=*}"
BOOTSTRAP="${ROLAUNCH##*#bt=}"
PORT="${ORIGIN##*:}"
curl -sS -o "$WORK/rosession.json" -X POST \
  -H 'Content-Type: application/json' -H "Origin: $ORIGIN" \
  --data-binary "{\"bootstrap\":\"$BOOTSTRAP\"}" "$ORIGIN/api/v1/session" >/dev/null
SESSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("session",""))' "$WORK/rosession.json")
for _ in $(seq 600); do
  api GET /api/v1/info > /dev/null
  phase=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("phase",""))' "$WORK/out.json" 2>/dev/null)
  [ "$phase" = ready ] && break
  sleep 0.1
done
python3 - "$WORK/out.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["phase"] == "ready", s
assert s["mode"] == "read-only", s["mode"]
# "none" is a read-only or --no-lease session, and it is NOT a fifth state
# of the four the control socket names.
assert s["lease"] == "none", s["lease"]
PY
ck $? "ro:mode                read-only, and no lease at all"

# It reads the federation too, which is a second and independent
# verification of step 7 with no kernel in the way.
api GET /api/v1/files > /dev/null
python3 - "$WORK/out.json" <<'PY'
import json, sys
ids = {e["id"] for e in json.load(open(sys.argv[1]))}
assert {"/hello.txt", "/blob.bin", "/sub"} <= ids, sorted(ids)
PY
ck $? "ro:reads-federation    the published generation lists over the JSON API"

code=$(api POST /api/v1/credentials '{"label":"rclone","write":true}')
[ "$code" = 403 ] && grep -q 'pelfs.write' "$WORK/out.json"
ck $? "ro:no-writable-token   a writable DAV client is refused ($code), by name"

# A CREDENTIAL FOR A CLIENT THAT IS NOT CYBERDUCK, over the only path there
# is now. This used to be two lines -- read the Basic username and password
# out of the response and pass them to `curl -u` -- and the password is gone,
# so the gate does what any other client has to do: run the real
# authorization-code flow with PKCE and use the Bearer token it gets. curl
# and python3 between them are a WebDAV client with no profile format, which
# is exactly the case this section is about.
api POST /api/v1/credentials '{"label":"rclone","write":false}' > /dev/null
RO_REDIRECT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["redirect_uri"])' "$WORK/out.json")
RO_ID=$(python3 - "$WORK/out.json" <<'PY'
import json, re, sys
c = json.load(open(sys.argv[1]))
for f in c["files"]:
    if f["name"].endswith(".cyberduckprofile"):
        m = re.search(r"<key>OAuth Client ID</key>\s*<string>([^<]*)</string>", f["content"])
        print(m.group(1) if m else "")
        break
PY
)
VERIFIER=pelfs-browse-gate-verifier-0123456789-abcdef
CHALLENGE=$(python3 -c '
import base64, hashlib, sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).decode().rstrip("="))
' "$VERIFIER")
curl -sS -o "$WORK/ro-consent.html" -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' \
  "$ORIGIN/oauth/authorize?response_type=code&client_id=$RO_ID&redirect_uri=$RO_REDIRECT&scope=pelfs.read&code_challenge=$CHALLENGE&code_challenge_method=S256" >/dev/null
RO_TICKET=$(grep -o 'name="consent_ticket" value="[^"]*"' "$WORK/ro-consent.html" \
            | head -1 | sed 's/.*value="//; s/"$//')
curl -sS -o "$WORK/ro-connected.html" \
  -H "Origin: $ORIGIN" -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: navigate' \
  --data-urlencode "consent_ticket=$RO_TICKET" --data-urlencode "decision=allow" \
  "$ORIGIN/oauth/authorize" >/dev/null
RO_CODE=$(deliver_url "$WORK/ro-connected.html" \
  | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
curl -sS -o "$WORK/ro-token.json" -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$RO_CODE" \
  --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "redirect_uri=$RO_REDIRECT" \
  --data-urlencode "client_id=$RO_ID" "$ORIGIN/oauth/token" >/dev/null
RO_TOKEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("access_token",""))' "$WORK/ro-token.json")
[ -n "$RO_TOKEN" ]
ck $? "ro:bearer-flow         a non-Cyberduck client got a token from the real flow"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $RO_TOKEN" \
  -X PROPFIND -H 'Depth: 1' "$ORIGIN/dav/")
[ "$code" = 207 ]
ck $? "ro:read-credential     a read-only credential PROPFINDs ($code)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $RO_TOKEN" \
  -X PUT --data-binary 'nope' "$ORIGIN/dav/refused.txt")
# 403 and not 401: a 401 sends the client back to authenticate again, which
# is the wrong instruction -- the credential is fine, the scope is not.
[ "$code" = 403 ]
ck $? "ro:403-on-write        a read-only credential answers $code on PUT, not 401"

code=$(api POST /api/v1/publish '{}')
[ "$code" = 403 ]
ck $? "ro:no-publish          the publish button answers $code"

code=$(api POST "/api/v1/files/%2F" '{"name":"nope.txt","type":"file"}')
[ "$code" = 403 ]
ck $? "ro:no-mkdir            the JSON API refuses a create ($code)"

kill -TERM "$ROBROWSE_PID" 2>/dev/null
wait "$ROBROWSE_PID" 2>/dev/null
ROBROWSE_PID=""

echo
echo "== what the sessions said =="
grep -E 'sealed generation|uploaded .* during the session' "$WORK/browse.log" | head -4

# The evidence half. A green check says the flow completed; these lines say
# WHAT COMPLETED IT, and they are the only place a reader can see that the
# client in this gate is Cyberduck's own stack rather than a stand-in.
echo
echo "== the authorization URL Cyberduck built =="
sed 's/client_id=[^&]*/client_id=<redacted>/' "$WORK/authorize.url" 2>/dev/null
echo
echo "== duck's own account of the connection =="
# duck redraws its progress line with backspaces, so the log is one long
# line with \010 in it. Turning those into newlines is what makes it
# greppable, and it is the difference between evidence and a smear.
# It also saves and restores the cursor with ESC 7 / ESC 8 around each
# redraw, so the ESC has to go with the digit after it or the log grows a
# "78" in front of every line.
clean_duck() {
  sed -e 's/\x1b[78]//g' -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$WORK/duck.out" 2>/dev/null \
    | tr '\010\015' '\n\n'
}
clean_duck \
  | grep -E 'Authenticating as|Login successful|Open web browser|connection opened|Upload complete' \
  | head -6

# ------------------------------------------------ 10. the name a user reads
#
# THE ONE CHECK IN THIS FILE THAT ONLY REAL CYBERDUCK CAN MAKE. A golden
# file proves pelfs wrote a `Name` and a `Default Nickname`; only Cyberduck's
# own plist reader and its own BookmarkNameProvider prove it READS them.
#
# The reported bug: "each time I click on it, it just says '127.0.0.1 -
# WebDAV (HTTP)'; no clue which each is". That string is Cyberduck's
# fallback, `toHostname(bookmark) + " – " + protocol.getName()`, and
# `getName()` fell through to the built-in `dav` parent because the profile
# set no `Name` at all. So the assertion is exactly that: whatever duck
# calls this connection, it must be a name pelfs chose and NOT the built-in
# protocol's.
displayed=$(clean_duck | grep -m1 'connection opened' | sed 's/ connection opened.*//')
case "$displayed" in
  *"WebDAV (HTTP)"*) r=1 ;;
  pelfs*) r=0 ;;
  *) r=1 ;;
esac
ck $r "profile:name-displayed real duck calls this connection ${displayed:-<nothing>}"

echo
echo "== summary: $fails failing check(s) =="
exit "$fails"
