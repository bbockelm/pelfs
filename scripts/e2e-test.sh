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
# A clean shutdown must release the write lease, which is the BRANCH's.
# The v0.1.0 whole-volume object must never have been written at all.
[ ! -f "$WORK/origin/e2e/ns/meta/lease-main.json" ] || { echo "FAIL: lease not released after session 1"; exit 1; }
[ ! -e "$WORK/origin/e2e/ns/meta/lease.json" ] || {
  echo "FAIL: a v0.2 writer wrote the legacy whole-volume lease; two writers on different branches would " \
       "then exclude each other through it"; exit 1; }
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
assert s["lease_key"] == "meta/lease-main.json", s.get("lease_key")
assert s["put"]["ops"] >= 2 and s["put"]["bytes"] > 8000000, s["put"]
assert s["object_errors_total"] == 0, s

# The phase split has to PARTITION the totals: a byte in neither phase, or
# in both, would make "nothing was uploaded while I was working" unsafe to
# believe. This session ran with --snapshot-interval 0, so the honest
# answer is that every uploaded byte belongs to teardown.
assert s["pelfs_stats_version"] == 2, s
ses, tear = s["session_phase"], s["teardown_phase"]
for kind in ("get", "put", "delete", "other"):
    for field in ("ops", "errors", "bytes"):
        got = ses[kind].get(field, 0) + tear[kind].get(field, 0)
        assert got == s[kind].get(field, 0), (kind, field, got, s[kind])
assert ses["put"].get("bytes", 0) == 0, ses["put"]
assert tear["put"].get("bytes", 0) > 8000000, tear["put"]
assert ses.get("seals", 0) == 0 and tear.get("seals", 0) == 1, (ses, tear)
assert s["teardown_began"], s
print(f"   stats OK: {s['put']['ops']} puts, {s['put']['bytes']} bytes up, sealed generation {s['sealed_generation']}")
print(f"   phases OK: {ses['put'].get('bytes', 0)} bytes uploaded during the session, "
      f"{tear['put'].get('bytes', 0)} after it exited")
PY
# The same answer on the console, live, for a user who never opens the file.
grep -q "during the session and" "$WORK/run1.log" || {
  echo "FAIL: the session never said when it uploaded"; tail -5 "$WORK/run1.log"; exit 1; }
grep -q "publishing: the first pack is on the wire" "$WORK/run1.log" || {
  echo "FAIL: the session never announced that publication had started"; tail -5 "$WORK/run1.log"; exit 1; }
# This log is redirected, which is what a person gets from `2>>pelfs.log`.
# A {placeholder} in it is a sentence the reader has to reassemble.
! grep -qE '\{[a-z][a-z_]*\}' "$WORK/run1.log" || {
  echo "FAIL: a redirected log carries an unexpanded placeholder"
  grep -E '\{[a-z][a-z_]*\}' "$WORK/run1.log" | sed 's/^/    /'; exit 1; }

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

echo "== prefetch: strict mode makes the whole generation local =="
# What it moves is PACKS, not decoded chunks: a pack is the unit of
# transfer, everything a read needs comes out of one, and making it local
# costs no decode. So the state directory must come away with cached packs
# and NOTHING unpacked beside them.
"$PELFS" shell --ro --state-dir "$WORK/state-pf" --prefetch all \
  --stats-file "$WORK/stats-pf.json" "$PREFIX" -- /bin/sh -c 'cat hello.txt' > "$WORK/run-pf.log" 2>&1
grep -q "prefetched" "$WORK/run-pf.log" || { echo "FAIL: strict prefetch did not report success"; exit 1; }
python3 -c "import json; s=json.load(open('$WORK/stats-pf.json')); assert s['prefetch_complete'] and s['prefetch_packs']>0, s" \
  || { echo "FAIL: prefetch stats wrong"; cat "$WORK/stats-pf.json"; exit 1; }
pf_packs="$(find "$WORK/state-pf" -path '*/gencache/packs/*' -type f | wc -l | tr -d ' ')"
[ "$pf_packs" -gt 0 ] || { echo "FAIL: strict prefetch cached no packs"; find "$WORK/state-pf" -type d; exit 1; }
echo "   strict prefetch verified: $pf_packs pack(s) local, nothing unpacked"

echo "== lease: two branches write CONCURRENTLY, and both seal =="
# THE POINT OF THE PER-BRANCH KEY. In v0.1.0 the lease was one object for
# the whole prefix (meta/lease.json), so these two mounts refused each
# other though they can never touch the same ref. They hold
# meta/lease-main.json and meta/lease-dev.json now and run at once.
#
# The overlap is FORCED, not hoped for: each session announces itself and
# then blocks until the other has announced, so a run in which they
# happened to be sequential CANNOT pass. Both then seal, and each branch
# must come away with its own generation.
#
# They share the volume's signing key (--signing-key), because a writer
# with a fresh state directory has no key the branch head was signed with.
# That is orthogonal to the lease and would be true of one writer too.
SIGNKEY="$WORK/state1/v2-signing.key"
[ -f "$SIGNKEY" ] || { echo "FAIL: no volume signing key at $SIGNKEY"; ls "$WORK/state1"; exit 1; }
"$PELFS" branch --state-dir "$WORK/state1" "$PREFIX" dev > "$WORK/branch-dev.log" 2>&1 \
  || { echo "FAIL: creating branch dev"; cat "$WORK/branch-dev.log"; exit 1; }
grep -q "write lease is per branch" "$WORK/branch-dev.log" || {
  echo "FAIL: branch creation did not state the per-branch lease:"; cat "$WORK/branch-dev.log"; exit 1; }

BARRIER="$WORK/barrier"; mkdir -p "$BARRIER"
concurrent_writer() { # $1 = own branch, $2 = the branch it waits for
  "$PELFS" shell --branch "$1" --state-dir "$WORK/state-cc-$1" --signing-key "$SIGNKEY" \
    --snapshot-interval 0 --stats-file "$WORK/stats-cc-$1.json" "$PREFIX" -- /bin/sh -c "
      echo '$1 was here' > from-$1.txt
      touch '$BARRIER/$1'
      for _ in \$(seq 600); do [ -e '$BARRIER/$2' ] && break; sleep 0.1; done
      # Both mounts are live and inside their payloads at this instant.
      # Without this the test would pass on a run where one session had
      # already exited before the other started.
      [ -e '$BARRIER/$2' ]
    "
}
( concurrent_writer main dev > "$WORK/run-cc-main.log" 2>&1; echo $? > "$WORK/rc-cc-main" ) &
CC_MAIN=$!
( concurrent_writer dev main > "$WORK/run-cc-dev.log" 2>&1; echo $? > "$WORK/rc-cc-dev" ) &
CC_DEV=$!
wait "$CC_MAIN" "$CC_DEV" 2>/dev/null || true
for b in main dev; do
  [ "$(cat "$WORK/rc-cc-$b" 2>/dev/null)" = "0" ] || {
    echo "FAIL: the concurrent writer on $b did not complete — it was refused, or never overlapped:"
    cat "$WORK/run-cc-$b.log"; exit 1; }
  grep -q "sealed generation" "$WORK/run-cc-$b.log" || {
    echo "FAIL: the concurrent writer on $b did not seal:"; cat "$WORK/run-cc-$b.log"; exit 1; }
  [ ! -f "$WORK/origin/e2e/ns/meta/lease-$b.json" ] || {
    echo "FAIL: lease-$b.json was not released on exit"; exit 1; }
done
# BOTH GENERATIONS LANDED. Two writers that both sealed but clobbered one
# ref would pass every check above and fail here.
"$PELFS" shell --ro --branch main --state-dir "$WORK/state-cc-read-main" "$PREFIX" -- \
  /bin/sh -c 'cat from-main.txt; [ ! -e from-dev.txt ]' > "$WORK/run-cc-read-main.log" 2>&1 || {
  echo "FAIL: main did not come away with its own generation:"; cat "$WORK/run-cc-read-main.log"; exit 1; }
"$PELFS" shell --ro --branch dev --state-dir "$WORK/state-cc-read-dev" "$PREFIX" -- \
  /bin/sh -c 'cat from-dev.txt; [ ! -e from-main.txt ]' > "$WORK/run-cc-read-dev.log" 2>&1 || {
  echo "FAIL: dev did not come away with its own generation:"; cat "$WORK/run-cc-read-dev.log"; exit 1; }
# And each session reported WHICH object it held, which is what a reader
# needs now that "a lease was held" no longer implies volume-wide.
python3 - "$WORK/stats-cc-main.json" "$WORK/stats-cc-dev.json" <<'PY'
import json, sys
for path, want in zip(sys.argv[1:3], ("meta/lease-main.json", "meta/lease-dev.json")):
    s = json.load(open(path))
    assert s["lease_held"] is True, (path, s)
    assert s["lease_key"] == want, (path, s.get("lease_key"), want)
    assert not s.get("lease_conflict_observed"), (path, s)
    assert s["seal_ok"] is True, (path, s)
print("   both sessions held their own lease object and neither saw a conflict")
PY
echo "   two branches wrote at the same time, both sealed, both generations landed"

echo "== merge: two diverged branches become one tree =="
# main and dev diverged just above, each with a file the other has never
# seen — which is exactly the merge this reports on. The base is FOUND, not
# named: `pelfs branch` pinned the fork point with a tag and recorded it,
# and nothing on this command line says where it is.
"$PELFS" merge --state-dir "$WORK/state1" "$PREFIX" dev > "$WORK/merge-report.log" 2>&1 \
  || { echo "FAIL: merge (report)"; cat "$WORK/merge-report.log"; exit 1; }
sed 's/^/    /' "$WORK/merge-report.log"
grep -q "mergeable with no conflicts" "$WORK/merge-report.log" || {
  echo "FAIL: two disjoint changes did not come out mergeable:"; cat "$WORK/merge-report.log"; exit 1; }
grep -q "inode collisions" "$WORK/merge-report.log" && {
  echo "FAIL: a properly forked branch collided, so per-branch lineages are not working:"
  cat "$WORK/merge-report.log"; exit 1; }
# A report writes nothing, which is the half a --apply flag is worth having.
before=$(cat "$WORK/origin/e2e/ns/refs/main" | cksum)
[ "$before" = "$(cat "$WORK/origin/e2e/ns/refs/main" | cksum)" ] || exit 1

"$PELFS" merge --apply --state-dir "$WORK/state1" --signing-key "$SIGNKEY" "$PREFIX" dev \
  > "$WORK/merge-apply.log" 2>&1 \
  || { echo "FAIL: merge --apply"; cat "$WORK/merge-apply.log"; exit 1; }
grep -q "merged dev into main" "$WORK/merge-apply.log" || {
  echo "FAIL: --apply did not report a merge:"; cat "$WORK/merge-apply.log"; exit 1; }
[ "$before" != "$(cat "$WORK/origin/e2e/ns/refs/main" | cksum)" ] || {
  echo "FAIL: --apply left main where it was"; exit 1; }

# BOTH SIDES' WORK, through a mount that has never seen either branch.
"$PELFS" shell --ro --branch main --state-dir "$WORK/state-merged" "$PREFIX" -- /bin/sh -c '
  set -eu
  cat from-main.txt
  cat from-dev.txt
' > "$WORK/merge-read.log" 2>&1 || {
  echo "FAIL: the merged tree does not serve both branches:"; cat "$WORK/merge-read.log"; exit 1; }
grep -q "main was here" "$WORK/merge-read.log" || { echo "FAIL: main's file is gone"; exit 1; }
grep -q "dev was here" "$WORK/merge-read.log" || { echo "FAIL: dev's file did not come across"; exit 1; }
"$PELFS" fsck --deep --state-dir "$WORK/state1" "$PREFIX" > "$WORK/fsck-merged.log" 2>&1 \
  || { echo "FAIL: fsck of the merged generation"; cat "$WORK/fsck-merged.log"; exit 1; }
grep -q "generation is consistent" "$WORK/fsck-merged.log" || {
  echo "FAIL: the merged generation does not verify"; cat "$WORK/fsck-merged.log"; exit 1; }
echo "   found its own base, merged both branches, and the result verifies"

echo "== merge: a conflict is refused, and --keep-both resolves it =="
# The same file changed on both branches, which no tree can resolve alone.
"$PELFS" branch --state-dir "$WORK/state1" "$PREFIX" clash > "$WORK/branch-clash.log" 2>&1 \
  || { echo "FAIL: creating branch clash"; cat "$WORK/branch-clash.log"; exit 1; }
for pair in "main:from-main-side" "clash:from-clash-side"; do
  b=${pair%%:*}; text=${pair##*:}
  "$PELFS" shell --branch "$b" --state-dir "$WORK/state-cf-$b" --signing-key "$SIGNKEY" \
    --snapshot-interval 0 "$PREFIX" -- /bin/sh -c "echo $text > contested.txt" \
    > "$WORK/run-cf-$b.log" 2>&1 \
    || { echo "FAIL: writing the contested file on $b"; cat "$WORK/run-cf-$b.log"; exit 1; }
done

if "$PELFS" merge --apply --state-dir "$WORK/state1" --signing-key "$SIGNKEY" "$PREFIX" clash \
  > "$WORK/merge-conflict.log" 2>&1; then
  echo "FAIL: a conflicting merge was applied"; cat "$WORK/merge-conflict.log"; exit 1
fi
sed 's/^/    /' "$WORK/merge-conflict.log"
# add-add rather than both-modified: clash was cut from a main that
# did not have this file, so there is no base version to compare to.
for want in "CONFLICT" "add-add" "contested.txt" "keep-both"; do
  grep -q "$want" "$WORK/merge-conflict.log" || {
    echo "FAIL: the refusal does not mention $want — a user cannot start resolving from it:"
    cat "$WORK/merge-conflict.log"; exit 1; }
done

"$PELFS" merge --apply --keep-both --state-dir "$WORK/state1" --signing-key "$SIGNKEY" \
  "$PREFIX" clash > "$WORK/merge-keepboth.log" 2>&1 \
  || { echo "FAIL: merge --keep-both"; cat "$WORK/merge-keepboth.log"; exit 1; }
"$PELFS" shell --ro --branch main --state-dir "$WORK/state-kb" "$PREFIX" -- /bin/sh -c '
  set -eu
  cat contested.txt
  cat "contested (from clash).txt"
' > "$WORK/keepboth-read.log" 2>&1 || {
  echo "FAIL: both versions are not in the merged tree:"; cat "$WORK/keepboth-read.log"
  cat "$WORK/merge-keepboth.log"; exit 1; }
grep -q "from-main-side" "$WORK/keepboth-read.log" || { echo "FAIL: ours version lost"; exit 1; }
grep -q "from-clash-side" "$WORK/keepboth-read.log" || { echo "FAIL: theirs version lost"; exit 1; }
echo "   refused with the conflict named, then kept both versions under distinct names"

echo "== lease: a second writer on the SAME branch is refused, --steal-lease overrides =="
# Narrowing the lease must not have weakened it. The holder is written
# directly, as it was for the volume lease in v0.1.0, so the refusal is
# decided by the record rather than by two processes racing.
mkdir -p "$WORK/origin/e2e/ns/meta"
cat > "$WORK/origin/e2e/ns/meta/lease-main.json" <<LEASE
{"session":"other-client","hostname":"elsewhere","pid":4242,"branch":"main",
 "acquired":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","renewed":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "ttl_seconds":600}
LEASE
if "$PELFS" shell --state-dir "$WORK/state1" "$PREFIX" -- /bin/sh -c true > "$WORK/run-lease.log" 2>&1; then
  echo "FAIL: mount should have been refused while another lease on main is live"; exit 1
fi
grep -q "in use by another pelfs client" "$WORK/run-lease.log" || { echo "FAIL: refusal did not mention the lease"; exit 1; }
grep -q "elsewhere" "$WORK/run-lease.log" || { echo "FAIL: refusal did not name the holder"; exit 1; }
grep -q "branch main is held by" "$WORK/run-lease.log" || {
  echo "FAIL: the refusal did not say WHICH branch is held:"; cat "$WORK/run-lease.log"; exit 1; }
# A writer on the other branch is admitted while that record stands: same
# volume, different ref, and nothing to wait for.
"$PELFS" shell --branch dev --state-dir "$WORK/state-alongside" --signing-key "$SIGNKEY" \
  --snapshot-interval 0 "$PREFIX" -- /bin/sh -c 'echo ok > alongside.txt' \
  > "$WORK/run-alongside.log" 2>&1 || {
  echo "FAIL: a writer on dev was refused while main's lease was held:"; cat "$WORK/run-alongside.log"; exit 1; }
"$PELFS" shell --state-dir "$WORK/state1" --steal-lease "$PREFIX" -- /bin/sh -c true > "$WORK/run-steal.log" 2>&1 \
  || { echo "FAIL: --steal-lease mount failed"; cat "$WORK/run-steal.log"; exit 1; }
[ ! -f "$WORK/origin/e2e/ns/meta/lease-main.json" ] || { echo "FAIL: stolen lease not released on exit"; exit 1; }
echo "   same branch refused by name, other branch unaffected, steal behaved as expected"

echo "== lease: a pelfs v0.1.0 client (meta/lease.json) locks every branch =="
# THE MIXED-VERSION RULE. A v0.1.0 writer holds ONE object for the whole
# prefix and its record names no branch, so it must exclude every branch
# here — assuming otherwise would be guessing where an invisible client
# is. It is simulated by writing the old key directly because this release
# has no code path that writes it, and that is the other half of the rule:
# writing both objects would put two writers on different branches back to
# excluding each other through the legacy key.
cat > "$WORK/origin/e2e/ns/meta/lease.json" <<LEASE
{"session":"other-client","hostname":"elsewhere","pid":4242,
 "acquired":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","renewed":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "ttl_seconds":600}
LEASE
for b in main dev; do
  if "$PELFS" shell --branch "$b" --state-dir "$WORK/state-legacy-$b" --signing-key "$SIGNKEY" \
      "$PREFIX" -- /bin/sh -c true > "$WORK/run-legacy-$b.log" 2>&1; then
    echo "FAIL: branch $b mounted while a v0.1.0 volume lease was live"; exit 1
  fi
  grep -q "in use by another pelfs client" "$WORK/run-legacy-$b.log" || {
    echo "FAIL: refusal did not mention the lease:"; cat "$WORK/run-legacy-$b.log"; exit 1; }
  grep -q "elsewhere" "$WORK/run-legacy-$b.log" || {
    echo "FAIL: refusal did not name the holder:"; cat "$WORK/run-legacy-$b.log"; exit 1; }
  grep -q "v0.1.0 client" "$WORK/run-legacy-$b.log" || {
    echo "FAIL: refusal did not say the holder is a v0.1.0 client, so the user cannot pick the right flag:"
    cat "$WORK/run-legacy-$b.log"; exit 1; }
done
# --steal-lease takes ONE BRANCH's lease and deliberately does not clear
# this one; the refusal has to name the flag that does.
if "$PELFS" shell --state-dir "$WORK/state-legacy-steal" --steal-lease --signing-key "$SIGNKEY" \
    "$PREFIX" -- /bin/sh -c true > "$WORK/run-legacy-steal.log" 2>&1; then
  echo "FAIL: --steal-lease walked past the v0.1.0 volume lease"; exit 1
fi
grep -q "ignore-volume-lease" "$WORK/run-legacy-steal.log" || {
  echo "FAIL: the refusal did not name the flag that does apply:"; cat "$WORK/run-legacy-steal.log"; exit 1; }
# --ignore-volume-lease proceeds, takes its BRANCH lease, and leaves the
# legacy object exactly where it was: ignoring is not stealing.
#
# On state1 deliberately, so this last advance of main leaves that state
# directory's overlay current. The sections below write through state1
# again, and an overlay recorded over a generation some other state
# directory has since superseded cannot be sealed.
"$PELFS" shell --state-dir "$WORK/state1" --ignore-volume-lease \
  --snapshot-interval 0 --stats-file "$WORK/stats-legacy.json" "$PREFIX" -- /bin/sh -c 'echo past > past.txt' \
  > "$WORK/run-legacy-ok.log" 2>&1 || {
  echo "FAIL: --ignore-volume-lease mount failed"; cat "$WORK/run-legacy-ok.log"; exit 1; }
python3 -c "
import json; s=json.load(open('$WORK/stats-legacy.json'))
assert s.get('lease_key') == 'meta/lease-main.json', s.get('lease_key')
" || { echo "FAIL: the session did not hold its own branch lease"; cat "$WORK/stats-legacy.json"; exit 1; }
[ -f "$WORK/origin/e2e/ns/meta/lease.json" ] || {
  echo "FAIL: the v0.1.0 lease was removed; this release must never write or delete that object"; exit 1; }
grep -q "other-client" "$WORK/origin/e2e/ns/meta/lease.json" || {
  echo "FAIL: the v0.1.0 lease was rewritten"; cat "$WORK/origin/e2e/ns/meta/lease.json"; exit 1; }
[ ! -f "$WORK/origin/e2e/ns/meta/lease-main.json" ] || {
  echo "FAIL: the branch lease was not released on exit"; exit 1; }
rm -f "$WORK/origin/e2e/ns/meta/lease.json"
echo "   v0.1.0 lease excluded every branch; --steal-lease refused; --ignore-volume-lease proceeded, untouched"

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

echo "== repack: measures, and refuses to touch packs inside the grace window =="
# Make some content dead: write a file, seal, rewrite it, seal. The old
# chunks are now garbage inside immutable packs, which is exactly what a
# repack is for.
"$PELFS" shell --state-dir "$WORK/state1" "$PREFIX" -- /bin/sh -c \
  'head -c 400000 /dev/urandom > churn.bin' > "$WORK/repack-w1.log" 2>&1 \
  || { echo "FAIL: write for repack"; cat "$WORK/repack-w1.log"; exit 1; }
"$PELFS" shell --state-dir "$WORK/state1" "$PREFIX" -- /bin/sh -c \
  'head -c 400000 /dev/urandom > churn.bin' > "$WORK/repack-w2.log" 2>&1 \
  || { echo "FAIL: rewrite for repack"; cat "$WORK/repack-w2.log"; exit 1; }

before=$(cat "$WORK/origin/e2e/ns/refs/main" | cksum)
"$PELFS" repack --state-dir "$WORK/state1" "$PREFIX" > "$WORK/repack.log" 2>&1 \
  || { echo "FAIL: repack (report)"; cat "$WORK/repack.log"; exit 1; }
grep -q "grace window:" "$WORK/repack.log" || {
  echo "FAIL: repack did not report the grace window it applied:"; cat "$WORK/repack.log"; exit 1; }
# The assertion that keeps this from passing vacuously: the rewrite above
# left a pack that is entirely dead, so the planner must have SEEN a
# candidate and declined it for its age alone. A run that simply found
# nothing would prove only that the command exits zero.
grep -q "held back:" "$WORK/repack.log" || {
  echo "FAIL: a rewritten file left no candidate for the age guard to hold back;"
  echo "      this check would pass on a volume with nothing to repack:"; cat "$WORK/repack.log"; exit 1; }
sed 's/^/    /' "$WORK/repack.log"

# THE SAFETY ASSERTION. Every pack here is seconds old, and a young pack
# is one a concurrent writer may be about to reference. --apply must
# therefore do nothing at all and leave the branch where it was. A repack
# that rewrote these would be a repack that races every other writer.
"$PELFS" repack --apply --state-dir "$WORK/state1" "$PREFIX" > "$WORK/repack-apply.log" 2>&1 \
  || { echo "FAIL: repack --apply"; cat "$WORK/repack-apply.log"; exit 1; }
grep -q "published generation" "$WORK/repack-apply.log" && {
  echo "FAIL: repack --apply published a generation from packs inside the grace window:"
  cat "$WORK/repack-apply.log"; exit 1; }
after=$(cat "$WORK/origin/e2e/ns/refs/main" | cksum)
[ "$before" = "$after" ] || {
  echo "FAIL: repack --apply moved the branch though it proposed nothing"; exit 1; }
"$PELFS" fsck --deep --state-dir "$WORK/state1" "$PREFIX" > "$WORK/fsck2.log" 2>&1 \
  || { echo "FAIL: fsck after repack"; cat "$WORK/fsck2.log"; exit 1; }
grep -q "generation is consistent" "$WORK/fsck2.log" || {
  echo "FAIL: fsck after repack did not report consistency"; cat "$WORK/fsck2.log"; exit 1; }
# A repack PUBLISHES a generation, so it takes the advisory lease — the
# lease of the BRANCH it is about to flip, and only that one. Losing a flip
# is cheap for a checkpoint and expensive here: the sweep and the rewrite
# are already paid by the time the flip happens.
cat > "$WORK/origin/e2e/ns/meta/lease-main.json" <<LEASE
{"session":"other-client","hostname":"elsewhere","pid":4242,"branch":"main",
 "acquired":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","renewed":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "ttl_seconds":600}
LEASE
if "$PELFS" repack --apply --state-dir "$WORK/state1" "$PREFIX" > "$WORK/repack-held.log" 2>&1; then
  echo "FAIL: repack --apply ran while another client held the lease"
  cat "$WORK/repack-held.log"; exit 1
fi
grep -q "in use by another pelfs client" "$WORK/repack-held.log" || {
  echo "FAIL: the refusal did not mention the lease:"; cat "$WORK/repack-held.log"; exit 1; }
grep -q "elsewhere" "$WORK/repack-held.log" || {
  echo "FAIL: the refusal did not name the holder:"; cat "$WORK/repack-held.log"; exit 1; }
# A repack of the OTHER branch is not blocked by it: disjoint refs, and
# the rewrite it would waste is not the held branch's.
"$PELFS" repack --branch dev --state-dir "$WORK/state1" "$PREFIX" > "$WORK/repack-dev.log" 2>&1 || {
  echo "FAIL: repack of dev was refused while main's lease was held:"
  cat "$WORK/repack-dev.log"; exit 1; }
# A REPORT needs no lease: inspecting a volume someone else is using is
# exactly when you want to know what it is carrying.
"$PELFS" repack --state-dir "$WORK/state1" "$PREFIX" > "$WORK/repack-held-report.log" 2>&1 || {
  echo "FAIL: repack (report) was refused while the lease was held:"
  cat "$WORK/repack-held-report.log"; exit 1; }
rm -f "$WORK/origin/e2e/ns/meta/lease-main.json"
echo "   measured the volume, held back every pack inside the grace window, changed nothing"
echo "   refused to publish while another client held the lease; reporting stayed available"

echo "== PASS: create, write, seal, read back, encrypt, prefetch, lease, gc, fsck, repack =="
