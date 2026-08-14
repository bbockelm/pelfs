#!/bin/bash
# End-to-end test: run pelfs via its Docker fallback against a fakeorigin
# server on the host. Session 1 writes data; session 2 (fresh local state)
# restores the metadata snapshot from the "federation" and reads it back.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(go env GOARCH)
TAGS="nogspt,notikv"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pelfs-e2e-XXXXXX")
trap 'kill $ORIGIN_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== building binaries =="
mkdir -p bin
CGO_ENABLED=0 go build -tags "$TAGS" -o bin/pelfs ./cmd/pelfs
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -tags "$TAGS" -o "bin/pelfs-linux-$ARCH" ./cmd/pelfs
CGO_ENABLED=0 go build -o bin/fakeorigin ./cmd/fakeorigin

echo "== starting fakeorigin =="
mkdir -p "$WORK/origin"
bin/fakeorigin --root "$WORK/origin" --listen 0.0.0.0:0 > "$WORK/origin.log" &
ORIGIN_PID=$!
for i in $(seq 1 50); do
  grep -q LISTENING "$WORK/origin.log" 2>/dev/null && break
  sleep 0.1
done
PORT=$(head -1 "$WORK/origin.log" | sed 's/.*://')
PREFIX="http://host.docker.internal:$PORT/e2e/ns"
echo "   origin on port $PORT, prefix $PREFIX"

export PELFS_LINUX_BINARY="$PWD/bin/pelfs-linux-$ARCH"

echo "== session 1: write data =="
bin/pelfs shell --docker --snapshot-interval 0 "$PREFIX" > "$WORK/run1.log" 2>&1 <<'EOF'
set -e
echo "hello pelican" > hello.txt
mkdir -p sub/dir
head -c 8388608 /dev/urandom > sub/dir/rand.bin
sha256sum sub/dir/rand.bin | cut -d' ' -f1 > rand.sha
cat rand.sha
ls -la
EOF
grep -q "final metadata snapshot uploaded" "$WORK/run1.log" || { echo "FAIL: no final snapshot in run 1"; cat "$WORK/run1.log"; exit 1; }
SHA1=$(grep -E '^[0-9a-f]{64}$' "$WORK/run1.log" | head -1)
[ -n "$SHA1" ] || { echo "FAIL: no checksum captured in run 1"; cat "$WORK/run1.log"; exit 1; }
echo "   wrote rand.bin sha256=$SHA1"

echo "== federation state after session 1 =="
find "$WORK/origin" -type f | sed "s|$WORK/origin/||" | sort | head -20
CHUNKS=$(find "$WORK/origin/e2e/ns/chunks" -type f | wc -l | tr -d ' ')
SNAPS=$(find "$WORK/origin/e2e/ns/meta" -type f | wc -l | tr -d ' ')
echo "   $CHUNKS chunk objects, $SNAPS metadata snapshots"
[ "$CHUNKS" -ge 2 ] || { echo "FAIL: expected >=2 chunk objects"; exit 1; }
[ "$SNAPS" -ge 1 ] || { echo "FAIL: expected >=1 metadata snapshot"; exit 1; }

echo "== session 2: fresh state, restore + read back =="
bin/pelfs shell --docker --snapshot-interval 0 "$PREFIX" > "$WORK/run2.log" 2>&1 <<'EOF'
set -e
cat hello.txt
sha256sum sub/dir/rand.bin | cut -d' ' -f1
EOF
grep -q "restored metadata from" "$WORK/run2.log" || { echo "FAIL: run 2 did not restore metadata"; cat "$WORK/run2.log"; exit 1; }
grep -q "hello pelican" "$WORK/run2.log" || { echo "FAIL: hello.txt content missing"; cat "$WORK/run2.log"; exit 1; }
SHA2=$(grep -E '^[0-9a-f]{64}$' "$WORK/run2.log" | head -1)
[ "$SHA1" = "$SHA2" ] || { echo "FAIL: checksum mismatch: $SHA1 vs $SHA2"; cat "$WORK/run2.log"; exit 1; }

echo "== PASS: write, snapshot, restore, and read-back all succeeded =="
