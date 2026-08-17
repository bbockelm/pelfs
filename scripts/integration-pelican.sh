#!/bin/bash
# Integration test against a real Pelican federation-in-a-box.
#
# Launches `pelican serve --module director,registry,origin` with the pure-Go
# posixv2 origin backend (no XRootD needed), mints a token with the origin's
# issuer key, and runs the go tests in internal/integration against the live
# federation.
#
# The pelican binary is located via $PELICAN_BIN, then PATH, then built from
# $PELICAN_SRC (default ~/projects/pelican).
#
# XRootD: the federation this script starts never runs an XRootD process --
# posixv2 is served in-process by pelican's own Go code. Pelican nevertheless
# probes `xrootd -v` unconditionally at origin startup (CheckDefaults ->
# xrootd.CheckXrootdEnv -> xrootd.CheckXrootdVersion; the check is NOT gated on
# originUsesXRootD()), so a runner without XRootD sees
#     Error: XRootD binary not found in PATH.
# and the server dies before it listens. Rather than install a ~300MB storage
# daemon that would never be executed, this script puts a stub `xrootd` on the
# server's PATH that answers the version probe and REFUSES anything else, then
# asserts afterwards that the probe was the only thing ever asked of it. The
# stub is prepended, so it shadows any real XRootD on a developer machine too:
# a local run exercises exactly the same code path CI does.
set -euo pipefail
cd "$(dirname "$0")/.."

# Default to an uncommon port: IDE port-forward helpers often squat on
# 8444/127.0.0.1, winning the IPv4/IPv6 dial race and breaking TLS.
WEBPORT=${PELFS_IT_WEBPORT:-18444}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pelfs-it-XXXXXX")
WORK=$(cd "$WORK" && pwd -P) # normalize // and symlinks; origin rejects odd paths
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

PELICAN_SRC=${PELICAN_SRC:-$HOME/projects/pelican}
# The harness needs the SERVER-flavored binary (now shipped as
# `pelican-server`): a client-only `pelican` on PATH must not shadow it.
# Validate candidates by probing for a server subcommand.
has_server_cmds() { "$1" origin --help >/dev/null 2>&1; }
if [ -n "${PELICAN_BIN:-}" ]; then
  has_server_cmds "$PELICAN_BIN" || { echo "FAIL: \$PELICAN_BIN lacks server subcommands (client-only build?)"; exit 1; }
else
  for cand in pelican-server pelican; do
    if command -v "$cand" >/dev/null && has_server_cmds "$(command -v $cand)"; then
      PELICAN_BIN=$(command -v "$cand")
      break
    fi
  done
  if [ -z "${PELICAN_BIN:-}" ] && [ -d "$PELICAN_SRC" ]; then
    echo "== building pelican-server from $PELICAN_SRC =="
    (cd "$PELICAN_SRC" && go build -tags forceposix,server -o "$WORK/pelican-server" ./cmd)
    PELICAN_BIN="$WORK/pelican-server"
  fi
  if [ -z "${PELICAN_BIN:-}" ]; then
    echo "SKIP: no server-flavored pelican binary (set \$PELICAN_BIN or \$PELICAN_SRC)"
    exit 0
  fi
fi
echo "== using pelican: $PELICAN_BIN =="

mkdir -p "$WORK/origin-data" "$WORK/server-config" "$WORK/client-config" "$WORK/xrootd-stub"

# The stub `xrootd`. It records every invocation so the assertion at the end of
# this script can prove the federation only ever probed the version and never
# tried to run a storage daemon. Any invocation other than the bare `-v` probe
# fails loudly instead of silently degrading into "XRootD is required after
# all" -- which is the whole point of keeping a stub rather than a real install.
# XRootD regression guard. The pinned pelican no longer probes for the
# binary unless a server will actually launch one (native origins and
# the v2 cache never do), so this stub should record NOTHING. It stays
# as an assertion: if a future pelican reintroduces an unconditional
# probe — or genuinely tries to run the daemon — this test says so
# instead of quietly re-acquiring an XRootD dependency.
XROOTD_STUB_LOG="$WORK/xrootd-stub-invocations.log"
cat > "$WORK/xrootd-stub/xrootd" <<EOF
#!/bin/sh
# Stub XRootD, installed by scripts/integration-pelican.sh. See that script.
printf '%s\n' "\$*" >> "$XROOTD_STUB_LOG"
if [ "\$#" -eq 1 ] && [ "\$1" = "-v" ]; then
  # Real xrootd prints its version to stderr; pelican reads CombinedOutput.
  echo "v5.8.2" >&2
  exit 0
fi
echo "pelfs integration: the federation tried to RUN XRootD (args: \$*)." >&2
echo "This test is meant to be XRootD-free; see scripts/integration-pelican.sh." >&2
exit 127
EOF
chmod +x "$WORK/xrootd-stub/xrootd"
: > "$XROOTD_STUB_LOG"

cat > "$WORK/pelican.yaml" <<EOF
Logging:
  Level: Warning
  LogLocation: $WORK/pelican-server.log
ConfigDir: $WORK/server-config
TLSSkipVerify: true
Server:
  EnableUI: false
  WebPort: $WEBPORT
  Hostname: localhost
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /pelfs-test
      StoragePrefix: $WORK/origin-data
      Capabilities: ["Reads", "Writes", "DirectReads", "Listings"]
EOF

echo "== launching federation-in-a-box on port $WEBPORT =="
# Prove the binary runs at all before blaming the federation: a server
# that dies in under a second with an empty log (seen in CI) is
# indistinguishable from a broken build unless we check first.
if ! "$PELICAN_BIN" --version > "$WORK/pelican-version.txt" 2>&1; then
  echo "FAIL: the pelican binary does not run:"
  sed 's/^/    /' "$WORK/pelican-version.txt"
  exit 1
fi
sed 's/^/    /' "$WORK/pelican-version.txt" | head -3

PELICAN_CONFIGDIR="$WORK/server-config" \
PATH="$WORK/xrootd-stub:$PATH" \
  "$PELICAN_BIN" serve --module director,registry,origin --config "$WORK/pelican.yaml" \
  > "$WORK/server.log" 2>&1 &
SERVER_PID=$!

# dumpServerLog reports everything a remote debugger needs: the exit
# status, the log (even when empty, said explicitly), and the config the
# server was given.
dumpServerLog() {
  echo "--- server exit status ---"
  # `wait` reports the child's nonzero status, which under set -e would
  # kill this reporter before it reports anything (it did, in CI).
  local st=0
  wait "$SERVER_PID" 2>/dev/null || st=$?
  echo "    exit=$st"
  echo "--- $WORK/server.log ---"
  if [ -s "$WORK/server.log" ]; then
    tail -60 "$WORK/server.log" | sed 's/^/    /'
  else
    echo "    (empty or missing — the process wrote nothing)"
    ls -la "$WORK" | sed 's/^/    /'
  fi
  echo "--- xrootd stub invocations ---"
  if [ -s "$XROOTD_STUB_LOG" ]; then
    sed 's/^/    xrootd /' "$XROOTD_STUB_LOG"
  else
    echo "    (none — the server died before probing XRootD)"
  fi
  echo "--- config ---"
  sed 's/^/    /' "$WORK/pelican.yaml"
}

DISCOVERY="https://localhost:$WEBPORT/.well-known/pelican-configuration"
for i in $(seq 1 120); do
  if curl -ks --max-time 2 "$DISCOVERY" | grep -q director_endpoint; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: pelican serve exited early"
    dumpServerLog
    exit 1
  fi
  sleep 1
  [ "$i" = 120 ] && { echo "FAIL: federation never became ready"; dumpServerLog; exit 1; }
done
echo "   federation is up"

echo "== minting a token with the origin issuer key =="
# The export's issuer defaults to <web>/api/v1.0/origin; the token's iss
# claim must match or XRootD rejects it.
PELICAN_CONFIGDIR="$WORK/server-config" \
PELICAN_SERVER_ISSUERURL="https://localhost:$WEBPORT/api/v1.0/origin" \
  "$PELICAN_BIN" --config "$WORK/pelican.yaml" -f "https://localhost:$WEBPORT" origin token create \
    --profile wlcg \
    --audience "https://localhost:$WEBPORT" --audience "https://wlcg.cern.ch/jwt/v1/any" \
    --subject pelfs-integration \
    --lifetime 3600 \
    --scope "storage.read:/" --scope "storage.modify:/" \
    > "$WORK/token"
[ -s "$WORK/token" ] || { echo "FAIL: token creation produced no output"; exit 1; }

echo "== running integration tests =="
PELFS_TEST_PREFIX="pelican://localhost:$WEBPORT/pelfs-test/it" \
PELFS_TEST_TOKEN="$WORK/token" \
PELICAN_CONFIGDIR="$WORK/client-config" \
PELICAN_TLSSKIPVERIFY=true \
PELICAN_TRANSPORT_TLSHANDSHAKETIMEOUT=60s \
PELICAN_TRANSPORT_RESPONSEHEADERTIMEOUT=60s \
  go test -tags integration -count=1 -v -timeout 15m ${IT_RUN:+-run "$IT_RUN"} ./internal/integration 2>&1 | tee "$WORK/gotest.log"; \
  [ "${PIPESTATUS[0]}" = 0 ] \
  || { echo "---- server log tail ----"; tail -60 "$WORK/server.log" "$WORK/pelican-server.log" 2>/dev/null; exit 1; }

# The client logs one line per director query it actually issues (cache
# misses only). It caches per namespace and flavor, so this stays flat no
# matter how many objects the tests touch; a count that tracks object count
# means the cache is being bypassed.
echo "== director queries issued by the client: $(grep -c "Will query director at" "$WORK/gotest.log" || true) =="

# Prove the claim in the header: the only thing the federation ever wanted from
# XRootD was the version string. Anything else in the log means a real XRootD
# dependency crept back in and the stub is now hiding it.
# Count rather than test grep's exit status: `grep -vq` reports whether the
# PATTERN matched, not whether any line was selected, under the ugrep-flavored
# /usr/bin/grep some developers have installed -- which silently inverted this
# check into a no-op.
NON_PROBE=$(grep -cvx -- '-v' "$XROOTD_STUB_LOG" || true)
if [ "${NON_PROBE:-0}" -ne 0 ]; then
  echo "FAIL: the federation invoked XRootD for something other than the version probe:"
  sed 's/^/    xrootd /' "$XROOTD_STUB_LOG"
  exit 1
fi
echo "== XRootD invocations (all version probes): $(wc -l < "$XROOTD_STUB_LOG" | tr -d ' ') =="

echo "== PASS: integration tests against real pelican federation =="
