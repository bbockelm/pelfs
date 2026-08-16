#!/usr/bin/env bash
# End-to-end filesystem benchmarks against ANY mounted pelfs path
# (v1 shell/mount, the NFS fallback, or a phase-3 mount-gen mountpoint) —
# the acceptance scenarios from docs/design-packfs.md: many-small-file
# unpack (the kernel-untar shape), full-tree tar-up (sequential read of
# everything), metadata walk (the git-status shape), and big-file I/O.
#
# Usage: scripts/bench-e2e.sh <mounted-dir> [source-tarball]
#   The tarball defaults to a synthetic tree (8k files across 512 dirs,
#   sized like a source tree) so runs are self-contained; pass a real
#   linux source tarball for the canonical numbers.
set -euo pipefail

MNT="${1:?usage: bench-e2e.sh <mounted-dir> [source-tarball]}"
TARBALL="${2:-}"
[ -d "$MNT" ] || { echo "$MNT is not a directory" >&2; exit 1; }
WORK="$MNT/bench-e2e.$$"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$WORK" "$SCRATCH"' EXIT

if [ -z "$TARBALL" ]; then
  echo "== building synthetic source tree (8192 files / 512 dirs) =="
  SRC="$SCRATCH/tree"
  for d in $(seq 0 511); do
    dir="$SRC/pkg$((d / 64))/mod$d"
    mkdir -p "$dir"
    for f in $(seq 0 15); do
      head -c $(( (d * 16 + f) % 8192 + 512 )) /dev/urandom > "$dir/f$f.c"
    done
  done
  TARBALL="$SCRATCH/tree.tar"
  tar -C "$SCRATCH" -cf "$TARBALL" tree
fi

files=$(tar -tf "$TARBALL" | grep -vc '/$')
bytes=$(wc -c < "$TARBALL")
echo "== corpus: $files files, $((bytes / 1024 / 1024)) MiB tar =="
mkdir -p "$WORK"

t() { # t <label> <cmd...>
  local label="$1"; shift
  local start end
  start=$(python3 -c 'import time; print(time.time())')
  "$@"
  end=$(python3 -c 'import time; print(time.time())')
  python3 -c 'import sys; print(f"{sys.argv[1]:<24} {float(sys.argv[3]) - float(sys.argv[2]):8.2f}s")' "$label" "$start" "$end"
}

echo "== end-to-end timings against $MNT =="
t "untar (many small)"   tar -C "$WORK" -xf "$TARBALL"
sync
t "walk (find+stat)"     sh -c "find '$WORK' -type f -exec stat -f%z {} + > /dev/null 2>&1 || find '$WORK' -type f -exec stat -c%s {} + > /dev/null"
t "tar-up (read all)"    sh -c "tar -C '$WORK' -cf '$SCRATCH/out.tar' ."
t "grep sweep"           sh -c "grep -r --binary-files=text -c x '$WORK' > /dev/null || true"
t "big write (256MiB)"   sh -c "head -c 268435456 /dev/urandom > '$WORK/big.bin'"
sync
t "big read"             sh -c "cat '$WORK/big.bin' > /dev/null"
t "rm -rf"               rm -rf "$WORK"

echo "== done; compare v1 (pelfs shell) vs phase-3 (pelfs mount-gen) runs =="
