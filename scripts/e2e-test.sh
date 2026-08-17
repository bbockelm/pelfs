#!/usr/bin/env bash
# End-to-end workflow against a fakeorigin standing in for a federation:
# create a volume, write through a mount, seal, read back from a fresh
# state directory, then the encrypted variant, the lease, gc, and fsck.
#
# This mounts a real filesystem. Run it in CI (Linux) or through
# scripts/e2e-docker.sh, never casually on a developer's machine.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [ "${PELFS_MOUNT_TEST_OK:-}" != "1" ] && [ "${CI:-}" != "true" ]; then
  echo "refusing to mount on this host: run in CI, or via scripts/e2e-docker.sh," >&2
  echo "or set PELFS_MOUNT_TEST_OK=1 on a Linux machine you own." >&2
  exit 2
fi
[ "$(uname -s)" = "Linux" ] || { echo "this gate needs Linux FUSE (macOS denies shell access to mounts)" >&2; exit 2; }
[ -e /dev/fuse ] || { echo "no /dev/fuse" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pelfs-e2e.XXXXXX")"
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
cleanup() {
  dump_logs_on_failure
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Binaries are either prebuilt (the container launcher cross-compiles on
# the host, since the test image has no toolchain) or built here.
if [ -n "${PELFS_PREBUILT:-}" ]; then
  echo "== using prebuilt binaries from $PELFS_PREBUILT =="
  cp "$PELFS_PREBUILT/pelfs" "$PELFS_PREBUILT/fakeorigin" "$WORK/"
else
  echo "== building pelfs and fakeorigin =="
  (cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/pelfs" ./cmd/pelfs)
  (cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/fakeorigin" ./cmd/fakeorigin)
fi
PELFS="$WORK/pelfs"

echo "== starting fakeorigin =="
mkdir -p "$WORK/origin"
"$WORK/fakeorigin" --root "$WORK/origin" --listen 127.0.0.1:18997 > "$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
for _ in $(seq 50); do
  curl -fsS "http://127.0.0.1:18997/" >/dev/null 2>&1 && break
  sleep 0.1
done
PREFIX="http://127.0.0.1:18997/e2e/ns"
ENCPREFIX="http://127.0.0.1:18997/e2e/enc"

echo "== session 1: an empty prefix becomes a volume, and takes a write =="
"$PELFS" shell --state-dir "$WORK/state1" --snapshot-interval 0 \
  --stats-file "$WORK/stats1.json" "$PREFIX" -- /bin/sh -c '
set -e
echo "hello pelican" > hello.txt
mkdir -p sub/dir
head -c 8388608 /dev/urandom > sub/dir/rand.bin
sha256sum sub/dir/rand.bin | cut -d" " -f1 > rand.sha
cat rand.sha
' > "$WORK/run1.log" 2>&1
grep -q "created volume" "$WORK/run1.log" || { echo "FAIL: the empty prefix was not initialized"; exit 1; }
grep -q "sealed generation" "$WORK/run1.log" || { echo "FAIL: session 1 did not seal"; exit 1; }
SHA1=$(grep -E '^[0-9a-f]{64}$' "$WORK/run1.log" | head -1)
[ -n "$SHA1" ] || { echo "FAIL: no checksum captured in run 1"; exit 1; }
# A clean shutdown must release the mount lease.
[ ! -f "$WORK/origin/e2e/ns/meta/lease.json" ] || { echo "FAIL: lease not released after session 1"; exit 1; }
echo "   wrote rand.bin sha256=$SHA1"

echo "== stats summary from session 1 =="
[ -f "$WORK/stats1.json" ] || { echo "FAIL: stats file missing"; exit 1; }
python3 - "$WORK/stats1.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["clean_shutdown"] is True, s
assert s["exit_code"] == 0, s
assert s["seal_ok"] is True, s
assert s["lease_held"] is True, s
assert s["put"]["ops"] >= 2 and s["put"]["bytes"] > 8000000, s["put"]
assert s["object_errors_total"] == 0, s
print(f"   stats OK: {s['put']['ops']} puts, {s['put']['bytes']} bytes up, sealed generation {s['sealed_generation']}")
PY

echo "== federation state after session 1 =="
PACKS=$( (find "$WORK/origin/e2e/ns/packs" -type f 2>/dev/null || true) | wc -l | tr -d ' ')
REFS=$( (find "$WORK/origin/e2e/ns/refs" -type f 2>/dev/null || true) | wc -l | tr -d ' ')
echo "   $PACKS pack objects, $REFS refs"
[ "$PACKS" -ge 1 ] || { echo "FAIL: expected >=1 pack object"; exit 1; }
[ "$REFS" -eq 1 ] || { echo "FAIL: expected exactly one branch ref, got $REFS"; exit 1; }

echo "== session 2: a FRESH state directory reads it all back =="
"$PELFS" shell --ro --state-dir "$WORK/state2" "$PREFIX" -- /bin/sh -c '
set -e
cat hello.txt
sha256sum sub/dir/rand.bin | cut -d" " -f1
' > "$WORK/run2.log" 2>&1
grep -q "pinning volume key" "$WORK/run2.log" || { echo "FAIL: a fresh state dir did not pin the volume key (TOFU)"; exit 1; }
grep -q "hello pelican" "$WORK/run2.log" || { echo "FAIL: hello.txt content missing"; exit 1; }
SHA2=$(grep -E '^[0-9a-f]{64}$' "$WORK/run2.log" | head -1)
[ "$SHA1" = "$SHA2" ] || { echo "FAIL: checksum mismatch: $SHA1 vs $SHA2"; exit 1; }
echo "   read-back verified from the federation alone"

echo "== encrypted volume: nothing readable lands in the objects =="
openssl genrsa -out "$WORK/enc.pem" 2048 2>/dev/null
"$PELFS" init --state-dir "$WORK/state-enc" --encrypt-key "$WORK/enc.pem" "$ENCPREFIX" > "$WORK/init-enc.log" 2>&1 \
  || { echo "FAIL: encrypted init"; exit 1; }
"$PELFS" shell --state-dir "$WORK/state-enc" --snapshot-interval 0 --encrypt-key "$WORK/enc.pem" \
  "$ENCPREFIX" -- /bin/sh -c 'echo secret-data-marker > s.txt; cat s.txt' > "$WORK/run3.log" 2>&1
grep -q "sealed generation" "$WORK/run3.log" || { echo "FAIL: encrypted session did not seal"; exit 1; }
if grep -rq "secret-data-marker" "$WORK/origin/e2e/enc"; then
  echo "FAIL: plaintext found in an encrypted volume's objects"; exit 1
fi
"$PELFS" shell --ro --state-dir "$WORK/state-enc2" --encrypt-key "$WORK/enc.pem" \
  "$ENCPREFIX" -- /bin/sh -c 'cat s.txt' > "$WORK/run4.log" 2>&1
grep -q "secret-data-marker" "$WORK/run4.log" || { echo "FAIL: encrypted read-back"; cat "$WORK/run4.log"; exit 1; }
# Without the key the volume must refuse to open, not serve garbage.
if "$PELFS" shell --ro --state-dir "$WORK/state-enc3" "$ENCPREFIX" -- /bin/sh -c 'cat s.txt' > "$WORK/run5.log" 2>&1; then
  echo "FAIL: an encrypted volume mounted without --encrypt-key"; cat "$WORK/run5.log"; exit 1
fi
echo "   encryption verified: opaque objects, key required, round trip intact"

echo "== prefetch: strict mode warms the whole generation =="
"$PELFS" shell --ro --state-dir "$WORK/state-pf" --prefetch all \
  --stats-file "$WORK/stats-pf.json" "$PREFIX" -- /bin/sh -c 'cat hello.txt' > "$WORK/run-pf.log" 2>&1
grep -q "prefetched" "$WORK/run-pf.log" || { echo "FAIL: strict prefetch did not report success"; exit 1; }
python3 -c "import json; s=json.load(open('$WORK/stats-pf.json')); assert s['prefetch_complete'] and s['prefetch_chunks']>0, s" \
  || { echo "FAIL: prefetch stats wrong"; cat "$WORK/stats-pf.json"; exit 1; }

echo "== lease: a second writer is refused, --steal-lease overrides =="
mkdir -p "$WORK/origin/e2e/ns/meta"
cat > "$WORK/origin/e2e/ns/meta/lease.json" <<LEASE
{"session":"other-client","hostname":"elsewhere","pid":4242,
 "acquired":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","renewed":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "ttl_seconds":600}
LEASE
if "$PELFS" shell --state-dir "$WORK/state1" "$PREFIX" -- /bin/sh -c true > "$WORK/run-lease.log" 2>&1; then
  echo "FAIL: mount should have been refused while another lease is live"; exit 1
fi
grep -q "in use by another pelfs client" "$WORK/run-lease.log" || { echo "FAIL: refusal did not mention the lease"; exit 1; }
grep -q "elsewhere" "$WORK/run-lease.log" || { echo "FAIL: refusal did not name the holder"; exit 1; }
"$PELFS" shell --state-dir "$WORK/state1" --steal-lease "$PREFIX" -- /bin/sh -c true > "$WORK/run-steal.log" 2>&1 \
  || { echo "FAIL: --steal-lease mount failed"; exit 1; }
[ ! -f "$WORK/origin/e2e/ns/meta/lease.json" ] || { echo "FAIL: stolen lease not released on exit"; exit 1; }
echo "   refusal + steal behaved as expected"

echo "== a retired-format prefix is recognized, not overwritten =="
mkdir -p "$WORK/origin/e2e/old/meta/20260101T000000Z-host-deadbeef"
echo "not a pelfs volume this release can read" > "$WORK/origin/e2e/old/meta/20260101T000000Z-host-deadbeef/final.db"
if "$PELFS" shell --state-dir "$WORK/state-old" "http://127.0.0.1:18997/e2e/old" -- /bin/sh -c true > "$WORK/run-old.log" 2>&1; then
  echo "FAIL: a retired-format prefix was mounted"; exit 1
fi
grep -q "retired block-and-snapshot volume" "$WORK/run-old.log" || {
  echo "FAIL: refusal did not identify the retired format:"; cat "$WORK/run-old.log"; exit 1; }
[ ! -e "$WORK/origin/e2e/old/refs/main" ] || { echo "FAIL: a new volume was created over existing data"; exit 1; }
echo "   recognized and refused without touching anything"

echo "== gc + fsck against the federation =="
"$PELFS" gc --state-dir "$WORK/state1" "$PREFIX" > "$WORK/gc.log" 2>&1 || { echo "FAIL: gc"; cat "$WORK/gc.log"; exit 1; }
grep -Eq "unreferenced: +0 " "$WORK/gc.log" || { echo "FAIL: gc found unreferenced packs on a clean volume"; cat "$WORK/gc.log"; exit 1; }
"$PELFS" fsck --deep --state-dir "$WORK/state1" "$PREFIX" > "$WORK/fsck.log" 2>&1 || { echo "FAIL: fsck"; cat "$WORK/fsck.log"; exit 1; }
grep -q "generation is consistent" "$WORK/fsck.log" || { echo "FAIL: fsck did not report consistency"; cat "$WORK/fsck.log"; exit 1; }

echo "== PASS: create, write, seal, read back, encrypt, prefetch, lease, gc, fsck =="
