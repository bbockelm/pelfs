#!/bin/bash
# End-to-end test: run pelfs via its Docker fallback against a fakeorigin
# server on the host. Session 1 writes data; session 2 (fresh local state)
# restores the metadata snapshot from the "federation" and reads it back.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(go env GOARCH)
TAGS="nogspt,notikv"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pelfs-e2e-XXXXXX")
# Under `set -e` a failing session aborts the script before its own
# reporter can run, and this trap then deletes $WORK -- so CI showed a
# bare "exit 1" with no reason at all. Dump the session logs on any
# non-zero exit, before cleanup, so the failure explains itself.
dump_logs_on_failure() {
  local status=$?
  [ "$status" -eq 0 ] && return 0
  echo "== FAILED (exit $status); tail of each session log ==" >&2
  for f in "$WORK"/*.log; do
    [ -e "$f" ] || continue
    echo "--- ${f##*/} ---" >&2
    tail -25 "$f" >&2
  done
  return 0
}
trap 'dump_logs_on_failure; kill $ORIGIN_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== building binaries =="
# Build into a per-run directory: the linux binary is bind-mounted into
# containers, and a concurrent rebuild overwriting a shared ./bin while a
# container executes from it wedges the run.
BIN="$WORK/bin"
mkdir -p "$BIN"
CGO_ENABLED=0 go build -tags "$TAGS" -o "$BIN/pelfs" ./cmd/pelfs
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -tags "$TAGS" -o "$BIN/pelfs-linux-$ARCH" ./cmd/pelfs
CGO_ENABLED=0 go build -o "$BIN/fakeorigin" ./cmd/fakeorigin

echo "== starting fakeorigin =="
mkdir -p "$WORK/origin"
"$BIN"/fakeorigin --root "$WORK/origin" --listen 0.0.0.0:0 > "$WORK/origin.log" &
ORIGIN_PID=$!
for i in $(seq 1 50); do
  grep -q LISTENING "$WORK/origin.log" 2>/dev/null && break
  sleep 0.1
done
PORT=$(head -1 "$WORK/origin.log" | sed 's/.*://')
PREFIX="http://host.docker.internal:$PORT/e2e/ns"
echo "   origin on port $PORT, prefix $PREFIX"

export PELFS_LINUX_BINARY="$BIN/pelfs-linux-$ARCH"

# This script exercises the V1 (JuiceFS) workflow end to end: writeback,
# periodic metadata snapshots, compression and encryption. `pelfs shell`
# now creates v2 volumes by default, so every invocation here pins
# --engine v1 explicitly. Without the pin the shell silently ran the
# catalog-native stack, which emits none of the v1 messages this script
# asserts -- and the failure looked like a mount bug rather than a
# changed default.
echo "== session 1: write data (writeback + stats) =="
"$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --writeback --flush-timeout 5m \
  --stats-file "$WORK/stats1.json" "$PREFIX" > "$WORK/run1.log" 2>&1 <<'EOF'
set -e
echo "hello pelican" > hello.txt
mkdir -p sub/dir
head -c 8388608 /dev/urandom > sub/dir/rand.bin
sha256sum sub/dir/rand.bin | cut -d' ' -f1 > rand.sha
cat rand.sha
ls -la
EOF
# A clean shutdown must release the mount lease.
[ ! -f "$WORK/origin/e2e/ns/meta/lease.json" ] || { echo "FAIL: lease not released after session 1"; exit 1; }
grep -q "final metadata snapshot uploaded" "$WORK/run1.log" || { echo "FAIL: no final snapshot in run 1"; cat "$WORK/run1.log"; exit 1; }
SHA1=$(grep -E '^[0-9a-f]{64}$' "$WORK/run1.log" | head -1)
[ -n "$SHA1" ] || { echo "FAIL: no checksum captured in run 1"; cat "$WORK/run1.log"; exit 1; }
echo "   wrote rand.bin sha256=$SHA1"

echo "== stats summary from session 1 =="
[ -f "$WORK/stats1.json" ] || { echo "FAIL: stats file missing"; exit 1; }
python3 - "$WORK/stats1.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["clean_shutdown"] is True, s
assert s["exit_code"] == 0, s
assert s["final_snapshot_ok"] is True, s
assert s["staging_drained"] is True, s          # writeback drained at exit
assert s["put"]["ops"] >= 4 and s["put"]["bytes"] > 8000000, s["put"]
assert s["object_errors_total"] == 0, s
print(f"   stats OK: {s['put']['ops']} puts, {s['put']['bytes']} bytes up, staging drained")
PY

echo "== federation state after session 1 (writeback => packed) =="
find "$WORK/origin" -type f | sed "s|$WORK/origin/||" | sort | head -20
LOOSE=$( (find "$WORK/origin/e2e/ns/chunks" -type f 2>/dev/null || true) | wc -l | tr -d ' ')
PACKS=$( (find "$WORK/origin/e2e/ns/packs" -type f 2>/dev/null || true) | wc -l | tr -d ' ')
SNAPS=$(find "$WORK/origin/e2e/ns/meta" -type f | wc -l | tr -d ' ')
echo "   $PACKS pack objects, $LOOSE loose chunk objects, $SNAPS metadata snapshots"
[ "$PACKS" -ge 1 ] || { echo "FAIL: expected >=1 pack object"; exit 1; }
[ "$LOOSE" -eq 0 ] || { echo "FAIL: expected 0 loose chunk objects with packing, got $LOOSE"; exit 1; }
[ "$SNAPS" -ge 1 ] || { echo "FAIL: expected >=1 metadata snapshot"; exit 1; }

echo "== session 2: fresh state, restore + read back =="
"$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 "$PREFIX" > "$WORK/run2.log" 2>&1 <<'EOF'
set -e
cat hello.txt
sha256sum sub/dir/rand.bin | cut -d' ' -f1
EOF
grep -q "restored metadata from" "$WORK/run2.log" || { echo "FAIL: run 2 did not restore metadata"; cat "$WORK/run2.log"; exit 1; }
grep -q "hello pelican" "$WORK/run2.log" || { echo "FAIL: hello.txt content missing"; cat "$WORK/run2.log"; exit 1; }
SHA2=$(grep -E '^[0-9a-f]{64}$' "$WORK/run2.log" | head -1)
[ "$SHA1" = "$SHA2" ] || { echo "FAIL: checksum mismatch: $SHA1 vs $SHA2"; cat "$WORK/run2.log"; exit 1; }

echo "== session 3: encrypted + zstd-compressed volume =="
openssl genrsa -out "$WORK/enc.pem" 2048 2>/dev/null
ENCPREFIX="http://host.docker.internal:$PORT/e2e/enc"
"$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --writeback --compress zstd --encrypt-key "$WORK/enc.pem" "$ENCPREFIX" > "$WORK/run3.log" 2>&1 <<'EOF'
set -e
echo "secret-data-marker" > s.txt
cat s.txt
EOF
grep -q "final metadata snapshot uploaded" "$WORK/run3.log" || { echo "FAIL: encrypted session did not snapshot"; cat "$WORK/run3.log"; exit 1; }
if grep -rq "secret-data-marker" "$WORK/origin/e2e/enc"; then
  echo "FAIL: plaintext found in encrypted volume's objects"; exit 1
fi
ENCPACKS=$( (find "$WORK/origin/e2e/enc/packs" -type f 2>/dev/null || true) | wc -l | tr -d ' ')
[ "$ENCPACKS" -ge 1 ] || { echo "FAIL: encrypted volume should be packed too"; exit 1; }
SNAP=$(find "$WORK/origin/e2e/enc/meta" -name "final.db" | head -1)
if head -c 15 "$SNAP" | grep -q "SQLite format 3"; then
  echo "FAIL: metadata snapshot stored in plaintext"; exit 1
fi

echo "== session 4: read back from encrypted volume =="
"$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --encrypt-key "$WORK/enc.pem" "$ENCPREFIX" > "$WORK/run4.log" 2>&1 <<'EOF'
cat s.txt
EOF
grep -q "secret-data-marker" "$WORK/run4.log" || { echo "FAIL: encrypted read-back"; cat "$WORK/run4.log"; exit 1; }

echo "== prefetch: strict mode succeeds on intact volume =="
"$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --prefetch all --stats-file "$WORK/stats-pf.json" "$PREFIX" > "$WORK/run-pf.log" 2>&1 <<'EOF'
cat hello.txt
EOF
grep -q "prefetched" "$WORK/run-pf.log" || { echo "FAIL: strict prefetch did not report success"; cat "$WORK/run-pf.log"; exit 1; }
python3 -c "import json,sys; s=json.load(open('$WORK/stats-pf.json')); assert s['prefetch_complete'] and s['prefetch_slices']>0, s" \
  || { echo "FAIL: prefetch stats wrong"; cat "$WORK/stats-pf.json"; exit 1; }

echo "== prefetch: strict mode refuses when a block is missing =="
MISSING=$(find "$WORK/origin/e2e/ns/packs" -type f -size +1M | head -1)
[ -n "$MISSING" ] || { echo "FAIL: no pack to remove"; exit 1; }
mv "$MISSING" "$WORK/chunk.bak"
if echo exit | "$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --prefetch all --stats-file "$WORK/stats-pf2.json" "$PREFIX" > "$WORK/run-pf2.log" 2>&1; then
  echo "FAIL: strict prefetch should refuse to start with a missing block"
  cat "$WORK/run-pf2.log"; exit 1
fi
grep -q "prefetch incomplete" "$WORK/run-pf2.log" || { echo "FAIL: refusal did not cite prefetch"; cat "$WORK/run-pf2.log"; exit 1; }
mv "$WORK/chunk.bak" "$MISSING" # heal the volume for the remaining checks
echo "   strict prefetch verified (success + refusal)"

echo "== lease: second client refused, steal override works =="
# Plant a live lease as if another client held it.
mkdir -p "$WORK/origin/e2e/ns/meta"
cat > "$WORK/origin/e2e/ns/meta/lease.json" <<LEASE
{"session":"other-client","hostname":"elsewhere","pid":4242,
 "acquired":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","renewed":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "ttl_seconds":600}
LEASE
if echo exit | "$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 "$PREFIX" > "$WORK/run-lease.log" 2>&1; then
  echo "FAIL: mount should have been refused while another lease is live"
  cat "$WORK/run-lease.log"
  exit 1
fi
grep -q "in use by another pelfs client" "$WORK/run-lease.log" || { echo "FAIL: refusal did not mention the lease"; cat "$WORK/run-lease.log"; exit 1; }
grep -q "elsewhere" "$WORK/run-lease.log" || { echo "FAIL: refusal did not name the holder"; cat "$WORK/run-lease.log"; exit 1; }

echo exit | "$BIN"/pelfs shell --engine v1 --docker --snapshot-interval 0 --steal-lease "$PREFIX" > "$WORK/run-steal.log" 2>&1 \
  || { echo "FAIL: --steal-lease mount failed"; cat "$WORK/run-steal.log"; exit 1; }
[ ! -f "$WORK/origin/e2e/ns/meta/lease.json" ] || { echo "FAIL: stolen lease not released on exit"; exit 1; }
echo "   refusal + steal behaved as expected"

echo "== gc + fsck against the federation (native, no FUSE needed) =="
"$BIN"/pelfs gc "http://127.0.0.1:$PORT/e2e/ns" > "$WORK/gc.log" 2>&1 || { echo "FAIL: gc"; cat "$WORK/gc.log"; exit 1; }
grep -Eq "leaked: +0 " "$WORK/gc.log" || { echo "FAIL: gc reported leaks on a clean volume"; cat "$WORK/gc.log"; exit 1; }
"$BIN"/pelfs fsck "http://127.0.0.1:$PORT/e2e/ns" > "$WORK/fsck.log" 2>&1 || { echo "FAIL: fsck"; cat "$WORK/fsck.log"; exit 1; }
grep -q "volume is consistent" "$WORK/fsck.log" || { echo "FAIL: fsck did not report consistency"; cat "$WORK/fsck.log"; exit 1; }

echo "== PASS: write, snapshot, restore, read-back, gc, and fsck all succeeded =="
