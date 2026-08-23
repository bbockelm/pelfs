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

# --only-fusemount runs sections 0-2 and 7 and stops: the --fusemount work
# (W1) is what changes, and the amplification and dedup measurements below
# it take minutes and answer questions nothing is changing. The full run is
# still the default.
ONLY=""
[ "${1:-}" = "--only-fusemount" ] && { ONLY=fusemount; shift; }

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
  # The permission fixture, for section 7e. A mode-denying file has to be
  # refused the same way through every frontend, and a --fusemount mount is
  # the one where the KERNEL is not the thing refusing it.
  echo "readable by anyone" > public.txt      && chmod 644 public.txt
  echo "readable by nobody" > secret.txt      && chmod 000 secret.txt
  echo "readable by me only" > owneronly.txt  && chmod 600 owneronly.txt
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
umount_ro() {
  if ! "$PELFS" umount "$MNT" > "$LOGDIR/umount.log" 2>&1; then
    # Losing this used to cost an afternoon: the NEXT mount reported
    # "already mounted" and the reason -- whatever was holding the mount
    # busy -- had been truncated out of mount.log by the failing mount
    # itself.
    echo "    umount of $MNT FAILED:"; sed 's/^/      /' "$LOGDIR/umount.log" | tail -5
    return 1
  fi
}

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

# The host-side read-only mount. Hoisted out of section 3 because section
# 7e needs it too, as the CONTROL for the permission question: the same
# volume, the same modes, mounted the ordinary way where the kernel does
# the checking.
mount_ro || { verdict FAILS "read-only mount would not start"; exit 1; }

if [ -z "$ONLY" ]; then
# ------------------------------------------- 3. exec a binary off the mount
say "3. exec a binary directly off a pelfs FUSE mount"
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

else
  # Section 6 is what produced this; the fusemount cases need a SIF to run.
  cp /images/el9.sif /work/local-el9.sif
fi

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
  # THE ENVIRONMENT, in full. What is missing from this is what a wrapper
  # has to spell out (scripts/pelfs-fusemount.sh); PREFIX below is exported
  # by the caller and its absence is the whole point.
  echo "  env: $(env | sort | tr '\n' ' ')"
  # And the driver's view of the mount it was handed: if the options carry
  # default_permissions, the KERNEL is still doing the permission check on
  # a passed fd and pelfs need not. This is the evidence for that question.
  echo "  fuse mounts visible to the driver:"
  grep -i fuse /proc/self/mountinfo 2>&1 | sed 's/^/    /'
} >> /work/logs/fusemount-argv.log 2>&1
sleep 15
PROBE
chmod 755 /work/argvprobe.sh
: > "$LOGDIR/fusemount-argv.log"
export PREFIX
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

say "7c. --fusemount with pelfs mount-gen itself (W1)"
# The driver is scripts/pelfs-fusemount.sh, shipped as itself: the file a
# job would deliver into its scratch directory, with the prefix and the
# work directory on the COMMAND LINE because the environment is scrubbed.
# apptainer appends /dev/fd/N and -f to whatever the spec says, so the
# spec's own arguments come first and the mountpoint written here (/data)
# is never what the driver sees.
DRIVER=/stage/pelfs-fusemount.sh
FMWORK=/work/fm
mkdir -p "$FMWORK"
FMSPEC="$DRIVER $PREFIX $FMWORK /data"

# NO host-side pelfs is involved in this case, which is the point of it:
# the mount happens inside the container, by the job, and the volume was
# published by a session that has already exited.
cmdline "apptainer exec --fusemount \"host:$FMSPEC\" el9.sif sh -c 'cat /data/public.txt'"
timeout 120 apptainer exec --fusemount "host:$FMSPEC" /work/local-el9.sif \
  /bin/sh -c 'ls /data && cat /data/public.txt && wc -c < /data/el9.sif' \
  > "$LOGDIR/fusemount-pelfs.log" 2>&1
RC=$?
sed 's/^/    /' "$LOGDIR/fusemount-pelfs.log" | head -20
if [ $RC -eq 0 ] && grep -q 'readable by anyone' "$LOGDIR/fusemount-pelfs.log"; then
  verdict WORKS "pelfs mount-gen as an apptainer --fusemount driver: a volume mounted INSIDE the container, no host-side pelfs, read and exited cleanly (rc=0)"
else
  verdict FAILS "pelfs as a --fusemount driver (rc=$RC): $(grep -iE 'mkdir|not a directory|ERROR pelfs|FATAL|cannot' "$LOGDIR/fusemount-pelfs.log" | head -1 | cut -c1-160)"
fi

echo "  -- exec a binary off the in-container mount --"
cmdline "apptainer exec --fusemount \"host:$FMSPEC\" el9.sif /data/busybox-static echo hi"
run "exec a binary off a volume the container mounted itself" \
    timeout 120 apptainer exec --fusemount "host:$FMSPEC" /work/local-el9.sif \
      /data/busybox-static echo hi

echo "  -- the container: form, which resolves the driver inside the IMAGE --"
cmdline "apptainer exec --fusemount \"container:$FMSPEC\" el9.sif ls /data"
timeout 120 apptainer exec --fusemount "container:$FMSPEC" /work/local-el9.sif ls /data \
  > "$LOGDIR/fusemount-container.log" 2>&1
CFRC=$?
CFWHY=$(grep -iE 'could not start|no such file|FATAL|ERROR' "$LOGDIR/fusemount-container.log" | head -1 | cut -c1-140)
echo "    rc=$CFRC -> ${CFWHY:-(no error line; see the log)}"
echo "    (expected to fail here: the driver is a HOST path, and this form looks for"
echo "     it inside the image. Bake pelfs and the wrapper in, or use host:.)"
note "INFO|container-form rc=$CFRC: $CFWHY"

echo "  -- and the mountpoint given to mount-gen directly, apptainer out of the picture --"
cmdline "pelfs mount-gen --ro <prefix> /dev/fd/3 -f   (3 redirected from /dev/null)"
"$PELFS" mount-gen --ro --state-dir /work/state-fm "$PREFIX" /dev/fd/3 -f 3</dev/null 2>&1 | tail -3 | sed 's/^/    /'
note "INFO|mount-gen /dev/fd/3 -f: $("$PELFS" mount-gen --ro --state-dir /work/state-fm "$PREFIX" /dev/fd/3 -f 3</dev/null 2>&1 | grep -oiE '(mkdir|expected .* positional|mount:).*' | head -1 | cut -c1-120)"

# ------------------------- 7d. is default_permissions applied on a passed fd?
say "7d. does anything apply default_permissions to a passed fd?"
# Three independent readings of the same question, because the answer
# decides who has to do the permission check.
echo "  (1) what go-fuse does with a /dev/fd/N mountpoint: it skips fusermount"
echo "      AND mount(2), so MountOptions.Options is never delivered."
echo "  (2) what apptainer asks the kernel for, from its own binaries:"
for b in /usr/local/bin/apptainer /usr/local/libexec/apptainer/bin/starter; do
  [ -f "$b" ] || continue
  printf '        %s: %s\n' "$(basename "$b")" \
    "$(strings -n 8 "$b" 2>/dev/null | grep -oE 'fd=%d[,a-z_=%]*|rootmode=[^ ]{0,12}|default_permissions' | sort -u | tr '\n' ' ' | cut -c1-200)"
done
echo "  (3) the mount options the CONTAINER sees on a live pelfs --fusemount:"
timeout 120 apptainer exec --fusemount "host:$FMSPEC" /work/local-el9.sif \
  /bin/sh -c 'grep " /data " /proc/self/mountinfo; grep -c default_permissions /proc/self/mountinfo' \
  > "$LOGDIR/fusemount-mountinfo.log" 2>&1
sed 's/^/        /' "$LOGDIR/fusemount-mountinfo.log" | head -5
if grep -q 'default_permissions' "$LOGDIR/fusemount-mountinfo.log"; then
  verdict WORKS "default_permissions IS set on the passed fd (the kernel is still checking; pelfs's own check is redundant)"
  note "INFO|default_permissions=yes"
else
  verdict WORKS "default_permissions is NOT set on the passed fd -- so pelfs is the only thing that can apply the mode bits (internal/rawfuse/perm.go)"
  note "INFO|default_permissions=no"
fi

# ---------------------- 7e. the permission answer, in the mount, both ways
say "7e. a mode-denying read, refused the same way through both mounts"
# CONTROL first: the ordinary host-side FUSE mount, where the kernel does
# the checking because pelfs asked it to.
cmdline "cat \$MNT/secret.txt   (mode 000, on a normal pelfs FUSE mount)"
if OUT=$(cat "$MNT/secret.txt" 2>&1); then
  verdict FAILS "CONTROL: a 0000 file was readable on a normal FUSE mount: $OUT"
else
  echo "    -> $OUT"
  verdict WORKS "CONTROL: a 0000 file is refused on a normal FUSE mount (the kernel, via default_permissions)"
fi
[ "$(cat "$MNT/public.txt" 2>/dev/null)" = "readable by anyone" ] \
  && verdict WORKS "CONTROL: the 0644 file next to it reads fine" \
  || verdict FAILS "CONTROL: the 0644 file did not read"

# And now the same two files through a --fusemount mount, where the kernel
# is NOT doing it.
cmdline "apptainer exec --fusemount \"host:$FMSPEC\" el9.sif sh -c 'cat /data/secret.txt; test -r /data/secret.txt'"
timeout 120 apptainer exec --fusemount "host:$FMSPEC" /work/local-el9.sif /bin/sh -c '
  printf "container id: "; id
  echo "what the mount REPORTS, as the container sees it (a 65534 here would"
  echo "mean the id is not mapped in the namespace, which changes every answer):"
  stat -c "  %n uid=%u gid=%g mode=%a" /data /data/public.txt /data/owneronly.txt
  if cat /data/owneronly.txt >/dev/null 2>&1; then echo OWNER_CLASS_READ; else echo OWNER_CLASS_DENIED; fi
  if cat /data/secret.txt 2>&1; then echo "SECRET_READ"; else echo "SECRET_DENIED"; fi
  if test -r /data/secret.txt; then echo "TEST_R_YES"; else echo "TEST_R_NO"; fi
  if cat /data/public.txt >/dev/null 2>&1; then echo "PUBLIC_READ"; else echo "PUBLIC_DENIED"; fi
  if test -r /data/public.txt; then echo "PUBLIC_TEST_R_YES"; else echo "PUBLIC_TEST_R_NO"; fi
' > "$LOGDIR/fusemount-perm.log" 2>&1
sed 's/^/    /' "$LOGDIR/fusemount-perm.log"
if grep -q SECRET_DENIED "$LOGDIR/fusemount-perm.log" && grep -q PUBLIC_READ "$LOGDIR/fusemount-perm.log"; then
  verdict WORKS "a 0000 file is refused INSIDE a --fusemount mount, and the 0644 file beside it still reads"
else
  verdict FAILS "--fusemount permission enforcement: $(grep -E 'SECRET|PUBLIC' "$LOGDIR/fusemount-perm.log" | tr '\n' ' ' | cut -c1-140)"
fi
if grep -q OWNER_CLASS_READ "$LOGDIR/fusemount-perm.log"; then
  verdict WORKS "a 0600 file reads: the caller is recognised as the volume's owner, not squashed into the other class"
else
  verdict FAILS "a 0600 file was refused to its own owner (the caller's identity is not what the mount reports)"
fi
if grep -q TEST_R_NO "$LOGDIR/fusemount-perm.log"; then
  verdict WORKS "access(2) answers no about it too (the FUSE ACCESS request, which the kernel sends only when default_permissions is off)"
else
  verdict FAILS "test -r said yes about a 0000 file (ACCESS is not being answered)"
fi

# ------------------- 7f. teardown: the container is KILLED mid-write
say "7f. --fusemount --rw: SIGKILL the container mid-write; does it still seal?"
# The failure mode worth guarding against is a driver that leaks an
# unsealed generation when the job dies. There is nothing to unmount on a
# passed fd, so the ONLY thing that ends the session is the connection
# going away -- which is exactly what a killed container does.
# On its own BRANCH: everything below section 7 is a measurement of the
# main branch, and a 32 MiB file dropped into it would move numbers the
# document quotes. A branch is also the honest shape for a job that writes.
RWWORK=/work/fmrw
mkdir -p "$RWWORK"
"$PELFS" branch --state-dir "$STATE" "$PREFIX" fusekill > "$LOGDIR/branch.log" 2>&1 \
  || { sed 's/^/    /' "$LOGDIR/branch.log"; verdict FAILS "could not create the fusekill branch"; }
# The VOLUME's signing key: a writable session in a FRESH state directory
# has nothing to sign a new generation with, and the seal fails after the
# job has finished -- which is the worst possible moment to find out. A
# real job ships this file the same way it ships the binary.
SIGNKEY="$STATE/v2-signing.key"
[ -f "$SIGNKEY" ] || verdict FAILS "no volume signing key at $SIGNKEY to give the writable driver"
RWSPEC="$DRIVER --rw --signing-key $SIGNKEY --branch fusekill $PREFIX $RWWORK /data"

echo "  -- first: can the container write into a --rw --fusemount mount at all? --"
timeout 120 apptainer exec --fusemount "host:$DRIVER --rw --debug --signing-key $SIGNKEY --branch fusekill $PREFIX /work/fmw /data" \
  /work/local-el9.sif /bin/sh -c '
  id
  grep " /data " /proc/self/mountinfo
  # THE FIRST TOUCH OF THE MOUNT IS DELIBERATELY A WRITE, because the
  # kernel refuses that one on its own: the root inode it created at
  # mount(2) carries PLACEHOLDER attributes (uid 0), apptainer mounted
  # inside a user namespace that does not map uid 0, so i_uid is
  # INVALID_UID and inode_permission fails HAS_UNMAPPED_ID with EACCES for
  # any MAY_WRITE. Nothing has asked pelfs anything at this point -- no
  # CREATE is sent at all -- and one stat of the mountpoint replaces those
  # attributes with the ones we report and the write goes through.
  if dd if=/dev/zero of=/data/nostat.bin bs=1M count=1 2>&1; then echo "dd-before-stat=0"; else echo "dd-before-stat=1"; fi
  stat -c "  %n uid=%u gid=%g mode=%a" /data
  if dd if=/dev/zero of=/data/afterstat.bin bs=1M count=1 2>&1; then echo "dd-after-stat=0"; else echo "dd-after-stat=1"; fi
  touch /data/probe-touch; echo "touch=$?"
  mkdir /data/probe-dir;   echo "mkdir=$?"
  echo hi > /data/probe-redirect; echo "redirect=$?"
  dd if=/dev/zero of=/data/probe-dd bs=1M count=1 2>&1 | tail -1; echo "dd-1m=$?"
  dd if=/dev/zero of=/data/probe-dd32 bs=1M count=32 2>&1 | tail -1; echo "dd-32m=$?"
  ls -l /data/probe-dd /data/probe-dd32 2>&1
' > "$LOGDIR/fusemount-write.log" 2>&1
grep -vE "^(rx|tx) " "$LOGDIR/fusemount-write.log" | sed 's/^/    /' | head -25
echo "    -- the protocol trace around the first mutating op --"
grep -E "CREATE|MKNOD|MKDIR|SETATTR|ACCESS|probe-dd" "$LOGDIR/fusemount-write.log" | head -20 | sed 's/^/    /'
# The probe's own driver is still SEALING what it just wrote when apptainer
# exits (32 MiB to pack and upload), and it holds the branch's write lease
# until it is done. The kill case below takes the same branch, so wait for
# it rather than racing it.
for i in $(seq 1 60); do
  pgrep -f 'mount-gen .*--rw' >/dev/null 2>&1 || break
  sleep 1
done
echo "  -- CONTROL: the same dd as the first write into an ORDINARY --rw mount --"
timeout 120 "$PELFS" mount-gen --rw --branch fusekill --state-dir /work/ddctl \
  "$PREFIX" /work/ddmnt -- /bin/sh -c 'dd if=/dev/zero of=/work/ddmnt/dd-first.bin bs=1M count=32 2>&1 | tail -1; ls -l /work/ddmnt/dd-first.bin' \
  > "$LOGDIR/dd-control.log" 2>&1
echo "    rc=$?"; grep -vE "^20[0-9][0-9]-" "$LOGDIR/dd-control.log" | sed 's/^/    /' | head -6
grep -q 'dd-first.bin' "$LOGDIR/dd-control.log" \
  && verdict WORKS "CONTROL: dd as the first write into an ordinary --rw mount" \
  || verdict FAILS "CONTROL: dd as the first write into an ORDINARY --rw mount also fails: $(grep -iE 'denied|error' "$LOGDIR/dd-control.log" | head -1 | cut -c1-120)"
for i in $(seq 1 60); do
  pgrep -f 'mount-gen .*--rw' >/dev/null 2>&1 || break
  sleep 1
done
if grep -q 'touch=0' "$LOGDIR/fusemount-write.log"; then
  verdict WORKS "a --fusemount mount is writable from inside the container"
else
  verdict FAILS "a --fusemount --rw mount refused a write: $(grep -E 'touch=|cannot|denied' "$LOGDIR/fusemount-write.log" | head -2 | tr '\n' ' ' | cut -c1-140)"
fi
# The ordering result, which is the kernel's and not pelfs's. Recorded as
# its own verdict because a job that writes has to know it.
BEFORE=$(sed -n 's/^ *dd-before-stat=//p' "$LOGDIR/fusemount-write.log" | head -1)
AFTER=$(sed -n 's/^ *dd-after-stat=//p' "$LOGDIR/fusemount-write.log" | head -1)
echo "    dd as the FIRST op: rc=$BEFORE   the same dd after one stat of the mountpoint: rc=$AFTER"
note "INFO|write-before-stat=$BEFORE write-after-stat=$AFTER"
if [ "$BEFORE" != 0 ] && [ "$AFTER" = 0 ]; then
  verdict WORKS "KERNEL, NOT PELFS: the first write into a passed-fd mount is EACCES until something stats the mountpoint (placeholder root attrs, uid 0 unmapped in the container's userns -> HAS_UNMAPPED_ID). No CREATE reaches pelfs at all; the trace above shows the LOOKUP and nothing after it"
elif [ "$BEFORE" = 0 ]; then
  verdict WORKS "no ordering constraint on this kernel: the first write into a passed-fd mount needs no prior stat"
else
  verdict FAILS "writes into a passed-fd mount fail even after a stat (before=$BEFORE after=$AFTER)"
fi
genof() { "$PELFS" fsck --branch "$1" --state-dir "$STATE" "$PREFIX" 2>/dev/null | sed -n 's/^generation \([0-9]*\).*/\1/p' | head -1; }
GEN_BEFORE=$(genof fusekill)
# SIGKILL to APPTAINER ALONE, and deliberately not to its process group.
# The distinction is the whole test: killing the group kills the driver
# too, and a SIGKILL'd driver cannot seal anything by definition (its
# overlay survives in the state directory for a remount to seal, which is
# what any kill -9 of any pelfs mount leaves, and its lease expires on the
# 2-minute TTL). What a --fusemount driver has to survive is the CONTAINER
# dying while the driver lives: the namespace goes, the mount with it, the
# device answers ENODEV, and the seal happens then.
cmdline "apptainer exec --fusemount \"host:$RWSPEC\" el9.sif sh -c 'dd ... /data/killed.bin; sleep 300' & ... kill -9 the apptainer pid"
apptainer exec --fusemount "host:$RWSPEC" /work/local-el9.sif /bin/sh -c '
  ls -ld /data > /dev/null    # see the ordering result above: this is what
                              # makes the kernel fetch the root attributes
  if dd if=/dev/zero of=/data/killed.bin bs=1M count=32 2>&1 | tail -1; then
    ls -l /data/killed.bin; echo WROTE
  else
    echo DD_FAILED
  fi
  sleep 4242
' > "$LOGDIR/fusemount-kill.log" 2>&1 &
APID=$!
for i in $(seq 1 90); do
  grep -q WROTE "$LOGDIR/fusemount-kill.log" 2>/dev/null && break
  sleep 1
done
grep -q WROTE "$LOGDIR/fusemount-kill.log" 2>/dev/null \
  && echo "    the job wrote 32 MiB into the mount; killing apptainer (pid $APID) now" \
  || echo "    WARNING: the write never reported; killing anyway"
kill -9 $APID 2>/dev/null
wait $APID 2>/dev/null
echo "    apptainer is gone (rc=$?)"
# The driver inherited this log, so its teardown lands in the same file
# AFTER apptainer's own output: give it a moment and then print all of it,
# because the seal line is the answer this section is looking for.
sleep 5
sed 's/^/    /' "$LOGDIR/fusemount-kill.log"
# The driver outlives apptainer by however long the seal takes.
for i in $(seq 1 60); do
  pgrep -f 'mount-gen .*--rw' >/dev/null 2>&1 || break
  sleep 1
done
if pgrep -f 'mount-gen .*--rw' >/dev/null 2>&1; then
  verdict FAILS "the driver was still running 60s after the container was killed"
  pkill -f 'mount-gen .*--rw'
else
  verdict WORKS "the driver exited on its own once the connection died"
fi
# The container's payload is ORPHANED, not reaped: killing apptainer's
# starter leaves the `sleep` it launched alive in the container's mount
# namespace, which holds a recursive bind of /work -- including the
# host-side pelfs mount at $MNT -- so `pelfs umount` later fails with the
# mount busy and section 8 cannot remount. Reap it here, by the marker it
# was given.
# The killed apptainer leaves ORPHANS, and they matter to everything after
# this: apptainer binds the cwd (/work) recursively into the container, so
# any surviving process of that container holds a mount namespace
# containing the host-side pelfs mount at $MNT -- and `pelfs umount` then
# fails with the mount busy, which is how section 8 came to report
# "already mounted" with the real reason truncated away. Reap them by name,
# and say what was reaped.
echo "    orphans left by the SIGKILL: $(pgrep -a -f 'squashfuse|sleep 4242|starter' 2>/dev/null | tr '\n' ';' | cut -c1-160)"
pkill -f 'sleep 4242' 2>/dev/null && echo "    reaped the container's payload"
pkill -x squashfuse_ll 2>/dev/null && echo "    reaped the container's squashfuse_ll (it held the rootfs mount)"
pkill -f 'appinit|starter' 2>/dev/null && echo "    reaped a leftover starter"
sleep 2
echo "  -- what its statistics file says about the seal --"
jq -r '"    seal_ok=\(.seal_ok) generation=\(.generation) clean_shutdown=\(.clean_shutdown) exit_code=\(.exit_code) put_bytes=\(.put.bytes)"' \
  "$RWWORK/pelfs-stats.json" 2>/dev/null || echo "    (no stats file)"
if [ "$(jq -r '.seal_ok' "$RWWORK/pelfs-stats.json" 2>/dev/null)" = true ]; then
  verdict WORKS "the killed container's generation WAS sealed (seal_ok=true)"
else
  verdict FAILS "the killed container left the generation unsealed: $(jq -c . "$RWWORK/pelfs-stats.json" 2>/dev/null | cut -c1-120)"
fi
GEN_AFTER=$(genof fusekill)
echo "    branch head: generation $GEN_BEFORE -> $GEN_AFTER"
note "INFO|kill-seal generations $GEN_BEFORE -> $GEN_AFTER"
if [ -n "$GEN_AFTER" ] && [ "$GEN_AFTER" != "$GEN_BEFORE" ]; then
  verdict WORKS "the branch advanced, so what the job wrote before it died is published"
else
  verdict FAILS "the branch head did not move ($GEN_BEFORE -> $GEN_AFTER)"
fi
echo "  -- and the write lease: a later writer must not have to steal it --"
run "the lease was released: a new writable session takes it without --steal-lease" \
    timeout 120 "$PELFS" mount-gen --rw --branch fusekill --state-dir /work/leasetest \
      "$PREFIX" /work/leasemnt -- /bin/true
# The file the killed job wrote is in the published generation.
if [ "$(timeout 120 apptainer exec --fusemount "host:$DRIVER --branch fusekill $PREFIX /work/fmro /data" \
        /work/local-el9.sif /bin/sh -c 'wc -c < /data/killed.bin' 2>/dev/null | tr -d ' ')" = "33554432" ]; then
  verdict WORKS "the 32 MiB the job wrote before the SIGKILL reads back at full length from a NEW mount"
else
  verdict FAILS "killed.bin did not read back at 33554432 bytes"
fi

if [ -n "$ONLY" ]; then
  say "results (--only-fusemount)"
  sed 's/^/  /' "$RESULTS"
  umount_ro
  exit 0
fi

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
# what the WRITE PATH actually realizes, which used to be a different
# number: the default path packed during the session against an in-memory,
# per-session index and realized NOTHING across generations, while
# --no-memtable staged everything to the seal where the SQLite sidecar
# spans them. Since W2 the default path asks the base generation's own
# pack index (genfs.Placed), so the two columns should now agree to within
# the metadata a generation costs.
dedup_gen() { # $1 label, $2 origin dir, $3 state dir, $4 mnt, $5 extra flag, $6.. cp args
  local label="$1" org="$2" st="$3" mp="$4" flag="$5"; shift 5
  local safe; safe=$(echo "$label" | tr -c 'a-zA-Z0-9' '-')
  local js="/work/dedup-$safe.json"
  mkdir -p "$org" "$st" "$mp"
  "$PELFS" mount-gen --rw $flag --state-dir "$st" --stats-file "$js" \
    "$DPFX" "$mp" -- /bin/sh -c "cp $* $mp/" > "$LOGDIR/dedup-$safe.log" 2>&1
  local up ded base sealed
  up=$(jqn '.put.bytes' "$js")
  # Three counters, because there are three mechanisms and only one of them
  # used to be reported. base_deduped_* is the memtable path recognising
  # content the BASE GENERATION already holds (the cross-generation case);
  # deduped_chunks includes that plus the within-session repeats;
  # sealed_deduped_chunks is publish's own, which is what --no-memtable
  # uses and what reported zero everywhere before it existed.
  ded=$(jqn '.write.deduped_chunks' "$js")
  base=$(jqn '.write.base_deduped_bytes' "$js")
  sealed=$(jqn '.sealed_deduped_chunks' "$js")
  printf '    %-42s uploaded=%-12s deduped=%-4s base_bytes=%-11s sealed_deduped=%-5s origin=%s\n' \
    "$label" "$up" "$ded" "$base" "$sealed" "$(du -sb "$org" | cut -f1)"
  note "DEDUP|$label|uploaded=$up|deduped_chunks=$ded|base_deduped_bytes=$base|sealed_deduped_chunks=$sealed|origin=$(du -sb "$org" | cut -f1)"
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
echo "  (the two modes' final origin sizes should now agree; the default path"
echo "   asks the base generation's pack index, --no-memtable the sidecar.)"

say "9. the origin's shape"
du -sh /work/origin | sed 's/^/    origin total: /'
find /work/origin -type f -size +1M -printf '%s\n' 2>/dev/null | sort -rn | head -3 | sed 's/^/    largest packs: /'
find /work/origin -type f -size +1M 2>/dev/null | wc -l | sed 's/^/    packs over 1 MiB: /'

say "RESULTS (machine-readable)"
cat "$RESULTS"
echo
echo "logs are in $LOGDIR"
exit 0
