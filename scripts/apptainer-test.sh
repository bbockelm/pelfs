#!/usr/bin/env bash
# The apptainer feasibility matrix, run INSIDE the container by
# scripts/apptainer-docker.sh. See that file for what the sandbox models
# and for the one deviation from a stock apptainer install.
#
# Every check prints WORKS / FAILS with the command line it ran, so the
# document can quote a line a user could type. Nothing here asserts: this
# is a MEASUREMENT harness, and a FAILS line is a result, not a bug in the
# script. Every apptainer case that reads from pelfs is paired with the
# SAME case reading from local disk, so a failure can be attributed
# without argument.
set -uo pipefail

[ "${PELFS_APPTAINER_CONTAINED:-}" = 1 ] || {
  echo "refusing to run outside scripts/apptainer-docker.sh" >&2; exit 1; }

PELFS=/stage/pelfs
PORT=18994
PREFIX="http://127.0.0.1:$PORT/ns"
MNT=/work/mnt
STATE=/work/state
LOGDIR=/work/logs
mkdir -p "$HOME" "$LOGDIR" /work/atmp "$STATE"

RESULTS=/work/results.txt
: > "$RESULTS"
note() { echo "$*" >> "$RESULTS"; }
say() { printf '\n===== %s =====\n' "$*"; }
verdict() { printf '  [%s] %s\n' "$1" "$2"; note "$1|$2"; }
cmdline() { printf '    $ %s\n' "$*"; }
# run LABEL COMMAND... : report WORKS/FAILS with the first interesting line
run() {
  local label="$1"; shift
  local log="$LOGDIR/$(echo "$label" | tr -c 'a-zA-Z0-9' '-').log"
  if "$@" > "$log" 2>&1; then
    verdict WORKS "$label"
    return 0
  fi
  verdict FAILS "$label: $(grep -iE 'FATAL|ERROR|error:|denied|no such|invalid' "$log" | head -1 | cut -c1-160)"
  return 1
}

# ----------------------------------------------------------------- 0. env
say "0. environment"
id
echo "kernel:     $(uname -srm)"
echo "apptainer:  $(apptainer --version)"
apptainer buildcfg | grep -E 'APPTAINER_SUID_INSTALL'
grep '^enable overlay' /usr/local/etc/apptainer/apptainer.conf
ls -l /dev/fuse
echo "max_user_namespaces: $(cat /proc/sys/user/max_user_namespaces)"
if unshare -U -r true 2>/dev/null; then
  verdict WORKS "unprivileged user namespaces (unshare -U -r)"
else
  verdict FAILS "unprivileged user namespaces: $(unshare -U -r true 2>&1)"
fi
if [ -r /dev/fuse ] && [ -w /dev/fuse ]; then
  verdict WORKS "/dev/fuse readable+writable by uid $(id -u)"
else
  verdict FAILS "/dev/fuse not accessible to uid $(id -u)"
fi
echo "squashfuse_ll: $(command -v squashfuse_ll) $(squashfuse_ll --help 2>&1 | head -1)"

say "0b. CONTROLS: the same apptainer cases against LOCAL DISK"
run "control: apptainer exec of a SIF on local disk" \
    apptainer exec /images/el9.sif /bin/true
run "control: apptainer exec of a sandbox on local disk" \
    apptainer exec /images/el9-sandbox /bin/true

# --------------------------------------------------------- 1. the origin
say "1. federation stand-in"
mkdir -p /work/origin
/stage/fakeorigin --root /work/origin --listen 127.0.0.1:$PORT &
ORIGIN=$!
cleanup() { "$PELFS" umount "$MNT" >/dev/null 2>&1; kill $ORIGIN 2>/dev/null; }
trap cleanup EXIT
sleep 1

# ------------------------------------------------- 2. populate the volume
say "2. populate the volume (images, binaries, a sandbox tree)"
cp /bin/busybox /work/busybox-static
cp /bin/echo /work/echo-dynamic
file /work/busybox-static /work/echo-dynamic | sed 's/^/  /'
SBOX_FILES=$(find /images/el9-sandbox | wc -l)
echo "  sandbox tree: $SBOX_FILES entries, $(du -sh /images/el9-sandbox | cut -f1)"
ls -l /images/*.sif | sed 's/^/  /'

POP_START=$(date +%s)
"$PELFS" shell --state-dir "$STATE" --stats-file /work/pop-stats.json "$PREFIX" -- /bin/bash -c '
  set -e
  cp /images/el9.sif /images/el9-derived.sif /images/el9-tiny-change.sif /images/el10.sif .
  cp /work/busybox-static /work/echo-dynamic .
  chmod 755 busybox-static echo-dynamic
  cp -a /images/el9-sandbox ./el9-sandbox
' > "$LOGDIR/populate.log" 2>&1
POP_RC=$?
POP_SECS=$(( $(date +%s) - POP_START ))
if [ $POP_RC -eq 0 ]; then
  verdict WORKS "wrote 4 SIFs + a $SBOX_FILES-entry sandbox into a pelfs volume in ${POP_SECS}s"
else
  echo "--- populate.log ---"; tail -40 "$LOGDIR/populate.log"
  verdict FAILS "populating the volume"; exit 1
fi
"$PELFS" fsck --state-dir "$STATE" "$PREFIX" 2>&1 | tee "$LOGDIR/fsck.log" | sed 's/^/  /'
CHUNKS=$(grep -o '[0-9]* chunks referenced' "$LOGDIR/fsck.log" | grep -o '^[0-9]*')
LOGICAL=$(grep -o '[0-9]* logical bytes' "$LOGDIR/fsck.log" | grep -o '^[0-9]*')
note "INFO|chunks=$CHUNKS logical_bytes=$LOGICAL"
# What the write path actually uploaded, for the dedup question.
jq -r '"INFO|uploaded_bytes=\(.put.bytes) deduped_chunks=\(.write.deduped_chunks // 0)"' \
  /work/pop-stats.json 2>/dev/null | tee -a "$RESULTS" | sed 's/^/  /'

# ------------------------------------------------------------- helpers
DLOG=""
mount_ro() {
  "$PELFS" mount --ro --debug --state-dir "$STATE" \
    --stats-file /work/mount-stats.json "$@" "$PREFIX" "$MNT" \
    > "$LOGDIR/mount.log" 2>&1 || { tail -20 "$LOGDIR/mount.log"; return 1; }
  DLOG=$(sed -n 's/.*log \([^ )]*daemon\.log\).*/\1/p' "$LOGDIR/mount.log" | tail -1)
  [ -n "$DLOG" ] || DLOG=$(find /work "$HOME" -name daemon.log -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2)
  return 0
}
umount_ro() { "$PELFS" umount "$MNT" >>"$LOGDIR/mount.log" 2>&1; }

LOG_MARK=0
meas_start() {
  "$PELFS" ctl "$MNT" stats > /work/s0.json 2>/dev/null
  LOG_MARK=$(wc -c < "$DLOG" 2>/dev/null || echo 0)
}
jqn() { jq -r "$1 // 0" "$2" 2>/dev/null || echo 0; }
meas_end() { # $1 label
  "$PELFS" ctl "$MNT" stats > /work/s1.json 2>/dev/null
  local g0 g1 h0 h1 m0 m1 fuse
  g0=$(jqn '.get.bytes' /work/s0.json); g1=$(jqn '.get.bytes' /work/s1.json)
  h0=$(jqn '.cache.chunk_hits' /work/s0.json); h1=$(jqn '.cache.chunk_hits' /work/s1.json)
  m0=$(jqn '.cache.chunk_misses' /work/s0.json); m1=$(jqn '.cache.chunk_misses' /work/s1.json)
  fuse=$(tail -c +$((LOG_MARK + 1)) "$DLOG" 2>/dev/null \
    | grep ' READ ' | sed -n 's/.*\[[0-9]* +\([0-9]*\)).*/\1/p' \
    | awk '{s+=$1} END{print s+0}')
  note "MEAS|$1|fuse_read_bytes=$fuse|origin_get_bytes=$((g1-g0))|chunk_hits=$((h1-h0))|chunk_misses=$((m1-m0))"
  printf '    MEAS %-30s fuse_read=%-11s origin_get=%-11s hits=%-6s misses=%s\n' \
    "$1" "$fuse" "$((g1-g0))" "$((h1-h0))" "$((m1-m0))"
}
timed() { /usr/bin/time -f '    wall %e s  maxrss %M KiB' "$@" 2>&1 | tail -3; }
# The SIZE DISTRIBUTION of the reads the kernel asks pelfs for. This is the
# number that decides whether the whole-chunk decode hurts: a 4 KiB read
# that decodes a 4 MiB chunk is 1000x, and the same 4 MiB chunk serving a
# 1 MiB read is 4x. Printed for the cold SIF case only.
read_hist() {
  echo "    read sizes the kernel asked pelfs for (bytes -> count):"
  tail -c +$((LOG_MARK + 1)) "$DLOG" 2>/dev/null \
    | grep ' READ ' | sed -n 's/.*\[[0-9]* +\([0-9]*\)).*/\1/p' \
    | sort -n | uniq -c | awk '{printf "      %-10s %s\n", $2, $1}'
}

# ------------------------------------------- 3. exec a binary off the mount
say "3. exec a binary directly off a pelfs FUSE mount"
mount_ro || { verdict FAILS "read-only mount would not start"; exit 1; }
ls -l "$MNT" | sed 's/^/  /'

cmdline "$MNT/busybox-static echo hello"
out=$("$MNT/busybox-static" echo hello 2>&1)
[ "$out" = hello ] && verdict WORKS "exec a STATIC binary off a pelfs mount" \
                   || verdict FAILS "exec a static binary off pelfs: $out"

cmdline "$MNT/echo-dynamic hello"
out=$("$MNT/echo-dynamic" hello 2>&1)
[ "$out" = hello ] && verdict WORKS "exec a DYNAMIC binary off a pelfs mount (the loader mmaps it too)" \
                   || verdict FAILS "exec a dynamic binary off pelfs: $out"

cmdline "$MNT/busybox-static sh -c 'exec $MNT/busybox-static true'"
run "a binary on pelfs exec'ing another binary on pelfs" \
    "$MNT/busybox-static" sh -c "exec $MNT/busybox-static true"

# ------------------------------------ 4. apptainer exec of a SIF on pelfs
say "4. apptainer exec of a SIF stored on pelfs, unprivileged"
cmdline "apptainer exec $MNT/el9.sif /bin/true"
run "apptainer exec of a SIF on a pelfs mount, as uid $(id -u), no privileges" \
    apptainer exec "$MNT/el9.sif" /bin/true
cmdline "apptainer exec $MNT/el9.sif cat /etc/redhat-release"
echo "    -> $(apptainer exec "$MNT/el9.sif" cat /etc/redhat-release 2>&1 | tail -1)"
cmdline "apptainer run $MNT/el9.sif"
run "apptainer run of a SIF on pelfs" apptainer run "$MNT/el9.sif" /bin/true
cmdline "apptainer exec $MNT/el9.sif /bin/sh -c 'ls /usr/bin | wc -l'"
echo "    -> $(apptainer exec "$MNT/el9.sif" /bin/sh -c 'ls /usr/bin | wc -l' 2>&1 | tail -1) files in /usr/bin"

echo "  -- how did it reach the SIF? --"
apptainer -d exec "$MNT/el9.sif" /bin/true > "$LOGDIR/sif-debug.log" 2>&1
grep -E 'squashfuse_ll|proc/self/fd|Mounting block' "$LOGDIR/sif-debug.log" | head -5 | sed 's/^/    /'
if grep -q 'squashfuse_ll' "$LOGDIR/sif-debug.log"; then
  verdict WORKS "the SIF is mounted by squashfuse_ll in userspace, reading pelfs through a passed fd (no loop device, no privilege)"
fi

# --------------------------------------- 5. a sandbox directory on pelfs
say "5. apptainer exec of a SANDBOX directory on pelfs"
cmdline "apptainer exec $MNT/el9-sandbox /bin/true"
run "apptainer exec of an extracted sandbox tree on pelfs" \
    apptainer exec "$MNT/el9-sandbox" /bin/true
cmdline "apptainer exec $MNT/el9-sandbox /bin/sh -c 'ls -laR /usr | wc -l'"
run "a sandbox on pelfs running a many-file workload" \
    apptainer exec "$MNT/el9-sandbox" /bin/sh -c 'ls -laR /usr | wc -l'
run "sandbox on pelfs with --fakeroot" \
    apptainer exec --fakeroot "$MNT/el9-sandbox" /bin/true

# ------------------------------ 6. a pelfs mount visible in the container
say "6. a pelfs mount visible INSIDE the container"
cp "$MNT/el9.sif" /work/local-el9.sif
cmdline "apptainer exec --bind $MNT:/data /work/local-el9.sif ls /data"
run "bind-mounting a host-side pelfs mount into an apptainer container" \
    apptainer exec --bind "$MNT:/data" /work/local-el9.sif ls /data
cmdline "apptainer exec --bind $MNT:/data IMAGE sh -c 'wc -c < /data/el9.sif'"
run "reading a pelfs file from inside the container through --bind" \
    apptainer exec --bind "$MNT:/data" /work/local-el9.sif /bin/sh -c 'wc -c < /data/el9.sif'
cmdline "apptainer exec --bind $MNT:/data IMAGE /data/busybox-static echo hi"
run "exec'ing a binary off the bound pelfs mount from inside the container" \
    apptainer exec --bind "$MNT:/data" /work/local-el9.sif /data/busybox-static echo hi

# --------------------------------------------- 7. --fusemount, argv probe
say "7. --fusemount: what does apptainer hand the FUSE driver?"
cat > /work/argvprobe.sh <<'PROBE'
#!/bin/bash
{
  echo "ARGV0=$0"
  i=1; for a in "$@"; do echo "  ARG$i=$a"; i=$((i+1)); done
  echo "  fds: $(ls /proc/self/fd 2>&1 | tr '\n' ' ')"
  for f in /proc/self/fd/*; do
    printf '    %s -> %s\n' "$f" "$(readlink "$f" 2>&1)"
  done
} >> /work/logs/fusemount-argv.log 2>&1
sleep 15
PROBE
chmod 755 /work/argvprobe.sh
: > "$LOGDIR/fusemount-argv.log"
for FORM in container host; do
  echo "  -- form: $FORM --"
  echo "### form=$FORM" >> "$LOGDIR/fusemount-argv.log"
  cmdline "apptainer exec --fusemount \"$FORM:/work/argvprobe.sh /mnt/probe\" IMAGE ls /mnt/probe"
  timeout 60 apptainer -d exec --fusemount "$FORM:/work/argvprobe.sh /mnt/probe" \
    /work/local-el9.sif ls /mnt/probe > "$LOGDIR/fusemount-$FORM.log" 2>&1
  echo "    rc=$?"
done
echo "  -- argv the driver actually saw --"
sed 's/^/    /' "$LOGDIR/fusemount-argv.log"

say "7b. --fusemount: a libfuse driver, as a CONTROL"
# squashfuse_ll is a stock libfuse server, so it accepts the /dev/fd/N
# mountpoint. If this works and pelfs does not, the gap is pelfs's.
cat > /work/sq-fusemount.sh <<'SQFM'
#!/bin/sh
exec /usr/bin/squashfuse_ll -o offset=36864 /images/el9.sif "$1"
SQFM
chmod 755 /work/sq-fusemount.sh
cmdline "apptainer exec --fusemount \"host:/work/sq-fusemount.sh /mnt/probe\" IMAGE ls /mnt/probe"
run "CONTROL: a libfuse driver (squashfuse_ll) mounted into the container by --fusemount" \
    timeout 90 apptainer exec --fusemount "host:/work/sq-fusemount.sh /mnt/probe" \
      /work/local-el9.sif ls /mnt/probe

say "7c. --fusemount with pelfs mount-gen itself"
# mount-gen is the foreground, single-generation mount: no daemon, no
# re-exec, which is the shape a --fusemount driver has to have. The
# environment apptainer gives the driver is SCRUBBED, so the prefix, the
# state directory and HOME are spelled out rather than inherited.
cat > /work/pelfs-fusemount.sh <<PELFSFM
#!/bin/bash
export HOME=/work/home
exec /stage/pelfs mount-gen --ro --state-dir /work/state-fm "$PREFIX" "\$1"
PELFSFM
chmod 755 /work/pelfs-fusemount.sh
for FORM in host container; do
  cmdline "apptainer exec --fusemount \"$FORM:/work/pelfs-fusemount.sh /mnt/pelfs\" IMAGE ls /mnt/pelfs"
  timeout 120 apptainer -d exec --fusemount "$FORM:/work/pelfs-fusemount.sh /mnt/pelfs" \
    /work/local-el9.sif ls /mnt/pelfs > "$LOGDIR/pelfs-fusemount-$FORM.log" 2>&1
  RC=$?
  if [ $RC -eq 0 ] && grep -q 'busybox-static' "$LOGDIR/pelfs-fusemount-$FORM.log"; then
    verdict WORKS "pelfs mount-gen as an apptainer --fusemount driver ($FORM)"
  else
    verdict FAILS "pelfs as a --fusemount driver ($FORM): $(grep -iE 'mkdir|not a directory|ERROR pelfs|FATAL' "$LOGDIR/pelfs-fusemount-$FORM.log" | head -1 | sed 's/.*\(ERROR pelfs.*\|FATAL.*\)/\1/' | cut -c1-140)"
  fi
done
echo "  -- and the same mountpoint given to mount-gen directly, with apptainer out of the picture --"
cmdline "pelfs mount-gen --ro <prefix> /dev/fd/3   (3 redirected from /dev/null)"
"$PELFS" mount-gen --ro --state-dir /work/state-fm "$PREFIX" /dev/fd/3 3</dev/null 2>&1 | tail -2 | sed 's/^/    /'
note "INFO|mount-gen /dev/fd/3: $("$PELFS" mount-gen --ro --state-dir /work/state-fm "$PREFIX" /dev/fd/3 3</dev/null 2>&1 | grep -o 'mkdir.*' | head -1)"

# ------------------------------------------------- 8. read amplification
say "8. read amplification"
echo "  chunker: min 1 MiB / avg 4 MiB (internal/chunkid); a miss decodes a WHOLE chunk"
echo "  volume:  $CHUNKS chunks over $LOGICAL logical bytes"
SIFSIZE=$(stat -c %s /work/local-el9.sif)
echo "  el9.sif: $SIFSIZE bytes"
note "INFO|sif_bytes=$SIFSIZE"
umount_ro

runmeas() { # $1 label, rest command
  local label="$1"; shift
  meas_start
  timed "$@" | sed 's/^/  /'
  meas_end "$label"
}

echo
echo "  == COLD: cache cleared, fresh mount =="
"$PELFS" cache clear --state-dir "$STATE" "$PREFIX" >/dev/null 2>&1
mount_ro || exit 1
runmeas cold-exec-true          apptainer exec "$MNT/el9.sif" /bin/true
read_hist
echo "  == WARM (same session: pack cache AND decoded arena hot) =="
runmeas warm-exec-true          apptainer exec "$MNT/el9.sif" /bin/true
echo "  == a workload that touches many files inside the image =="
runmeas warm-workload           apptainer exec "$MNT/el9.sif" /bin/sh -c 'ls -laR /usr >/dev/null 2>&1; cat /usr/lib64/libc.so.6 > /dev/null; rpm -qa > /dev/null 2>&1'
echo "  == whole-file copy of the SIF, for comparison =="
runmeas whole-file-copy         cp "$MNT/el9.sif" /work/copy2.sif
umount_ro

echo
echo "  == WARM PACKS, COLD ARENA (a second job on the same node) =="
mount_ro || exit 1
runmeas warmpacks-coldarena     apptainer exec "$MNT/el9.sif" /bin/true
runmeas warmpacks-workload      apptainer exec "$MNT/el9.sif" /bin/sh -c 'ls -laR /usr >/dev/null 2>&1'
umount_ro

echo
echo "  == --prefetch all: the whole generation local before anything runs =="
"$PELFS" cache clear --state-dir "$STATE" "$PREFIX" >/dev/null 2>&1
PF=$(date +%s)
mount_ro --prefetch all || verdict FAILS "--prefetch all mount"
echo "    prefetch wall: $(( $(date +%s) - PF ))s"
grep -i prefetch "$LOGDIR/mount.log" | head -2 | sed 's/^/    /'
runmeas prefetched-exec-true    apptainer exec "$MNT/el9.sif" /bin/true
runmeas prefetched-workload     apptainer exec "$MNT/el9.sif" /bin/sh -c 'ls -laR /usr >/dev/null 2>&1'
runmeas prefetched-sandbox      apptainer exec "$MNT/el9-sandbox" /bin/true
runmeas prefetched-sbox-workload apptainer exec "$MNT/el9-sandbox" /bin/sh -c 'ls -laR /usr >/dev/null 2>&1'
umount_ro

echo
echo "  == COLD whole-file read of the SIF, in a session that does nothing else =="
echo "     (the staging baseline: what one cp off the mount costs from scratch)"
"$PELFS" cache clear --state-dir "$STATE" "$PREFIX" >/dev/null 2>&1
mount_ro || exit 1
runmeas cold-whole-file-copy    cp "$MNT/el9.sif" /work/copy3.sif
cmp /work/copy3.sif /work/local-el9.sif && echo "    (byte-identical to the original)"
umount_ro

echo
echo "  == the local-disk baseline (what any workflow can fall back to) =="
timed apptainer exec /work/copy2.sif /bin/true | sed 's/^/  /'
timed apptainer exec /work/copy2.sif /bin/sh -c 'ls -laR /usr >/dev/null 2>&1' | sed 's/^/  /'

echo
echo "  == COLD sandbox-on-pelfs: the thousands-of-small-files case =="
"$PELFS" cache clear --state-dir "$STATE" "$PREFIX" >/dev/null 2>&1
mount_ro || exit 1
runmeas cold-sandbox-exec       apptainer exec "$MNT/el9-sandbox" /bin/true
runmeas cold-sandbox-workload   apptainer exec "$MNT/el9-sandbox" /bin/sh -c 'ls -laR /usr >/dev/null 2>&1'
umount_ro

# ------------------------------------------- 8b. write-path dedup
say "8b. write-path dedup: is a pelfs volume an image DISTRIBUTION channel?"
# The chunker's POTENTIAL is measured by internal/dedupbench (CDC finds
# ~93% between a base SIF and the same sandbox plus one file). This asks
# what the WRITE PATH actually realizes, which is a different number: the
# default packs during the session out of an in-memory, per-session index,
# and --no-memtable stages and chunks everything at the seal, where the
# SQLite dedup sidecar (internal/publish/dedup.go) spans generations.
dedup_gen() { # $1 label, $2 origin dir, $3 state dir, $4 mnt, $5 extra flag, $6.. cp args
  local label="$1" org="$2" st="$3" mp="$4" flag="$5"; shift 5
  local safe; safe=$(echo "$label" | tr -c 'a-zA-Z0-9' '-')
  local js="/work/dedup-$safe.json"
  mkdir -p "$org" "$st" "$mp"
  "$PELFS" mount-gen --rw $flag --state-dir "$st" --stats-file "$js" \
    "$DPFX" "$mp" -- /bin/sh -c "cp $* $mp/" > "$LOGDIR/dedup-$safe.log" 2>&1
  local up ded
  up=$(jqn '.put.bytes' "$js"); ded=$(jqn '.write.deduped_chunks' "$js")
  printf '    %-42s uploaded=%-12s deduped_chunks=%-4s origin=%s\n' \
    "$label" "$up" "$ded" "$(du -sb "$org" | cut -f1)"
  note "DEDUP|$label|uploaded=$up|deduped_chunks=$ded|origin=$(du -sb "$org" | cut -f1)"
}
DPORT=19100
for MODE in default no-memtable; do
  FLAG=""; [ "$MODE" = no-memtable ] && FLAG="--no-memtable"
  DPORT=$((DPORT + 1))
  DORG="/work/dd-$MODE/origin"; DST="/work/dd-$MODE/state"; DMNT="/work/dd-$MODE/mnt"
  mkdir -p "$DORG" "$DST" "$DMNT"
  DPFX="http://127.0.0.1:$DPORT/ns"
  /stage/fakeorigin --root "$DORG" --listen "127.0.0.1:$DPORT" >/dev/null 2>&1 &
  DPID=$!
  sleep 1
  "$PELFS" init --state-dir "$DST" "$DPFX" >/dev/null 2>&1
  echo "  -- $MODE (el9.sif is $(stat -c %s /images/el9.sif) bytes) --"
  dedup_gen "$MODE/gen1 el9.sif"                    "$DORG" "$DST" "$DMNT" "$FLAG" /images/el9.sif
  dedup_gen "$MODE/gen2 +ONE small file added"      "$DORG" "$DST" "$DMNT" "$FLAG" /images/el9-tiny-change.sif
  dedup_gen "$MODE/gen3 +3MB payload (derived)"     "$DORG" "$DST" "$DMNT" "$FLAG" /images/el9-derived.sif
  dedup_gen "$MODE/gen4 +el10 (base moved)"         "$DORG" "$DST" "$DMNT" "$FLAG" /images/el10.sif
  kill $DPID 2>/dev/null
done
echo "  (a gen2 far below gen1 is cross-generation dedup working; equal is none.)"
echo "  NOTE: deduped_chunks is incremented only on the memtable path"
echo "        (internal/memtable/seal.go), so the path that DOES dedup reports 0."

say "9. the origin's shape"
du -sh /work/origin | sed 's/^/    origin total: /'
find /work/origin -type f -size +1M -printf '%s\n' 2>/dev/null | sort -rn | head -3 | sed 's/^/    largest packs: /'
find /work/origin -type f -size +1M 2>/dev/null | wc -l | sed 's/^/    packs over 1 MiB: /'

say "RESULTS (machine-readable)"
cat "$RESULTS"
echo
echo "logs are in $LOGDIR"
exit 0
