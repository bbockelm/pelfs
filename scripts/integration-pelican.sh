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
if [ -z "${PELICAN_BIN:-}" ]; then
  if command -v pelican >/dev/null; then
    PELICAN_BIN=$(command -v pelican)
  elif [ -d "$PELICAN_SRC" ]; then
    echo "== building pelican binary from $PELICAN_SRC =="
    (cd "$PELICAN_SRC" && go build -tags forceposix,server -o "$WORK/pelican" ./cmd)
    PELICAN_BIN="$WORK/pelican"
  else
    echo "SKIP: no pelican binary (set \$PELICAN_BIN or \$PELICAN_SRC)"
    exit 0
  fi
fi
echo "== using pelican: $PELICAN_BIN =="

mkdir -p "$WORK/origin-data" "$WORK/server-config" "$WORK/client-config"

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
PELICAN_CONFIGDIR="$WORK/server-config" \
  "$PELICAN_BIN" serve --module director,registry,origin --config "$WORK/pelican.yaml" \
  > "$WORK/server.log" 2>&1 &
SERVER_PID=$!

DISCOVERY="https://localhost:$WEBPORT/.well-known/pelican-configuration"
for i in $(seq 1 120); do
  if curl -ks --max-time 2 "$DISCOVERY" | grep -q director_endpoint; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: pelican serve exited early"
    tail -40 "$WORK/server.log" "$WORK/pelican-server.log" 2>/dev/null; exit 1
  fi
  sleep 1
  [ "$i" = 120 ] && { echo "FAIL: federation never became ready"; tail -40 "$WORK/server.log" "$WORK/pelican-server.log" 2>/dev/null; exit 1; }
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
  go test -tags "integration,nogspt,notikv" -count=1 -v -timeout 15m ${IT_RUN:+-run "$IT_RUN"} ./internal/integration 2>&1 | tee "$WORK/gotest.log"; \
  [ "${PIPESTATUS[0]}" = 0 ] \
  || { echo "---- server log tail ----"; tail -60 "$WORK/server.log" "$WORK/pelican-server.log" 2>/dev/null; exit 1; }

# The client logs one line per director query it actually issues (cache
# misses only). It caches per namespace and flavor, so this stays flat no
# matter how many objects the tests touch; a count that tracks object count
# means the cache is being bypassed.
echo "== director queries issued by the client: $(grep -c "Will query director at" "$WORK/gotest.log" || true) =="


echo "== PASS: integration tests against real pelican federation =="
