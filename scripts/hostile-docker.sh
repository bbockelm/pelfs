#!/usr/bin/env bash
# The HOSTILE FILESYSTEM EXERCISER containment launcher — the ONLY
# sanctioned way to run internal/hostile.
#
# ============================ WHY THIS IS LOCKED DOWN ====================
# This tool generates adversarial filesystem operations — symlink forests
# aimed out of the tree, rm -rf storms, rename storms, thousands of entries
# mutated mid-enumeration — against a REAL kernel mount, at speed.
# Escaped, it destroys a working directory. It does not run on a
# developer's machine. Not "should not": the layers below make it
# impossible, and each one is independently sufficient.
#
#   1. BUILD TAG. internal/hostile/exec_test.go compiles only under
#      `-tags hostile`, and is a _test.go file, so no ordinary build, vet
#      or `go test ./...` can link it and no product code can import it.
#   2. ENV GATE. It skips unless PELFS_HOSTILE_CONTAINED=1. Only this
#      script sets it, and only in `docker run`.
#   3. IMAGE SENTINEL. It aborts unless /etc/pelfs-hostile-container
#      exists — baked into the image this script builds and nowhere else.
#      Being in *a* container is not enough; it must be THIS one.
#   4. NO WRITABLE HOST PATH EXISTS INSIDE THE CONTAINER. The only bind
#      mount is the staged binaries, read-only. Every writable byte is on
#      a tmpfs that dies with the container. There is no route from inside
#      to the developer's filesystem for a bug to find. This is the layer
#      that does not depend on the harness being correct.
#   5. os.Root. Every path operation the harness performs goes through an
#      os.Root rooted at the sandbox, so a generated symlink to
#      /etc/passwd or a path full of ".." cannot be followed out.
#   6. NEGATIVE ASSERTION. Before any hostile op runs, the harness proves
#      os.Root still refuses absolute targets, climbing targets and ".."
#      paths — it does not assume the confinement, it tests it.
#
# Cross-compilation happens on the host because compiling is not fuzzing;
# EXECUTION only ever happens in the sealed container.
#
# THE ONE HONEST RELAXATION, stated plainly: a real kernel mount requires
# CAP_SYS_ADMIN and /dev/fuse, so unlike scripts/opfuzz-docker.sh this
# container cannot run --cap-drop ALL as an unprivileged user. It runs
# --cap-drop ALL --cap-add SYS_ADMIN, and layer 4 is what carries the
# weight in exchange: a root process with SYS_ADMIN inside a container
# whose only host-visible path is a read-only directory of two binaries
# has nothing of the developer's machine to damage. That is why the rootfs
# is read-only and why the repo is NOT mounted for the run.
#
# Usage:
#   scripts/hostile-docker.sh                 # CI budget: corpus + short run
#   scripts/hostile-docker.sh --long          # manual: 20k ops, big dirs
#   scripts/hostile-docker.sh --seed 12345    # replay a printed seed
#   scripts/hostile-docker.sh --plan FILE     # replay a corpus/minimized plan
#   scripts/hostile-docker.sh --retro [REF]   # run TODAY's exerciser against
#                                             # an OLD pelfs built from REF
#   scripts/hostile-docker.sh --run PATTERN   # -run filter
#   scripts/hostile-docker.sh --snapshot 100ms # checkpoint cadence in phase A
#   scripts/hostile-docker.sh --env K=V       # diagnostic env var in the container
#   scripts/hostile-docker.sh --drop-chown    # run with CAP_CHOWN/CAP_FOWNER
#                                             # dropped: the capability-poor shape
#   scripts/hostile-docker.sh --encrypt       # every volume ENCRYPTED: chunks are
#                                             # compressed and then sealed, so no
#                                             # pack entry is its plaintext's length
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BASE_IMAGE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
BUILDER_IMAGE="${PELFS_HOSTILE_BUILDER:-golang:1.26}"
ARCH="${PELFS_DOCKER_ARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"
IMAGE_TAG="pelfs-hostile-runner:1"

MODE=ci
RUN_PATTERN=""
SEED=""
PLAN=""
RETRO_REF=""
OPS=""
BIGDIR=""
DROP_CHOWN=0
LARGEFILE=""
EXTRA_ENVS=(-e PELFS_HOSTILE_MARKER=1)
TIMEOUT="${PELFS_HOSTILE_TIMEOUT:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --long)   MODE=long ;;
    --ci)     MODE=ci ;;
    --seed)   SEED="${2:?--seed needs a value}"; shift ;;
    --ops)    OPS="${2:?--ops needs a value}"; shift ;;
    --bigdir) BIGDIR="${2:?--bigdir needs a value}"; shift ;;
    # Size of the one file per plan the content-defined chunker cuts in
    # two (default 6 MiB; 0 removes it). Every other body this vocabulary
    # writes is under 70 KB and the volume's chunker has a 1 MiB minimum,
    # so without this no plan has ever contained a chunk BOUNDARY. It is
    # also the cheapest thing to turn off if the budget is squeezed.
    --large-file) LARGEFILE="${2:?--large-file needs a byte count}"; shift ;;
    --plan)   PLAN="${2:?--plan needs a path}"; shift ;;
    --run)    RUN_PATTERN="${2:?--run needs a pattern}"; shift ;;
    --drop-chown) DROP_CHOWN=1 ;;
    # Run against ENCRYPTED volumes. The harness mints a throwaway RSA key
    # on the container's own tmpfs and passes --encrypt-key to init, to
    # every mount, and to fsck; it then proves the volume really is
    # encrypted by requiring fsck --deep to FAIL without the key.
    #
    # This is the strongest form of the question the fill kinds ask. A
    # chunk is compressed and THEN encrypted, so a nonce and a GCM tag are
    # always added and the entry in the pack is never the length of the
    # plaintext -- for every chunk, not only the compressible ones.
    --encrypt) EXTRA_ENVS+=(-e PELFS_HOSTILE_ENCRYPT=1) ;;
    # How often a writable mount checkpoints in phase A (default 1s).
    # Shorten it to make a checkpoint far more likely to land INSIDE a
    # large directory's enumeration -- see the readdir finding in
    # docs/TODO.md, which is a race and was studied by moving this.
    --snapshot) EXTRA_ENVS+=(-e "PELFS_HOSTILE_SNAPSHOT=${2:?--snapshot needs a duration}"); shift ;;
    # Diagnostic passthrough: set an env var inside the sealed container,
    # e.g. --env PELFS_NFS_NO_DESCENT_CACHE=1 to ask whether a finding is
    # the NFS dir-descent cache's. It cannot weaken containment -- every
    # containment decision is a docker flag or a check, not an env var,
    # and the two variables that ARE containment (PELFS_HOSTILE_CONTAINED,
    # PELFS_HOSTILE_SANDBOX) are set unconditionally after this.
    --env)    EXTRA_ENVS+=(-e "${2:?--env needs KEY=VALUE}"); shift ;;
    --retro)  MODE=retro
              # Default: the parent of the RECHUNK fix, which is also
              # before the sparse-train fix and before the go-nfs REMOVE
              # fix -- so one checkout exhibits all three of the bugs the
              # corpus exists to prove this tool would have caught. See
              # the note under RETRO below.
              case "${2:-}" in -*|"") RETRO_REF="c26428f" ;; *) RETRO_REF="$2"; shift ;; esac ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- host guards
# The invoking host runs NOTHING but docker build/run and a cross-compile.
# These guards exist so that a mistake is an error message rather than a
# hostile op sequence loose in someone's home directory.
command -v docker >/dev/null || {
  echo "docker is required: containment is mandatory, and the container IS the containment" >&2
  exit 1
}
if [ "${PELFS_HOSTILE_CONTAINED:-}" = "1" ]; then
  echo "PELFS_HOSTILE_CONTAINED=1 is set in the CALLING environment." >&2
  echo "That variable is the container's, not yours. Refusing: if you are trying to" >&2
  echo "run the exerciser directly on this machine, that is the one thing this script" >&2
  echo "exists to prevent." >&2
  exit 1
fi
if [ -n "${PELFS_HOSTILE_SANDBOX:-}" ]; then
  echo "PELFS_HOSTILE_SANDBOX is set in the calling environment; refusing." >&2
  echo "The sandbox is a tmpfs inside the container and is not configurable from here." >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

# ---------------------------------------------------------------- the image
# Built here rather than pulled, because the SENTINEL FILE is what proves
# to the harness that it is inside the container this script launched. It
# is layer 3, and it only works if this script is the only thing that
# writes it.
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the hostile runner image (once) =="
  docker build -q -t "$IMAGE_TAG" - <<DOCKERFILE
FROM ${BASE_IMAGE}
RUN apt-get -qq update && apt-get -qq install -y fuse3 nfs-common \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && rm -rf /var/lib/apt/lists/*
# Layer 3. internal/hostile refuses to run without this file, so a stray
# \`docker run debian\` cannot execute the exerciser even with the env var
# set, and neither can any host.
RUN printf 'pelfs hostile exerciser containment sentinel\n' > /etc/pelfs-hostile-container
DOCKERFILE
fi

# ---------------------------------------------------------------- build
echo "== cross-compiling on the host (compiling is not exercising) =="
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
  go test -c -tags hostile -o "$STAGE/hostile.test" ./internal/hostile/)

if [ "$MODE" = retro ]; then
  # ============================== RETRO ==================================
  # The proof that this tool would have caught what humans caught: run
  # TODAY's exerciser against YESTERDAY's pelfs.
  #
  # A NOTE ON THE REFERENCE, because the obvious choice is wrong. All
  # three bugs were fixed AT OR BEFORE v0.1.0 -- the tag sits exactly on
  # e68a538, which IS the go-nfs REMOVE fix -- so v0.1.0 exhibits NONE of
  # them and a retro run against it proves nothing. The pre-fix states
  # are the fixes' parents, and they nest:
  #     9d953c7  = e68a538^  dangling-symlink rm -rf present
  #     2afa231  = 9d953c7^  sparse-train seal failure ALSO present
  #     c26428f  = 2afa231^  rechunk CLen/Alg metadata ALSO present
  # c26428f is therefore the default: one checkout, all three bugs.
  #
  # The rechunk one needs BOTH halves of what the fill vocabulary added.
  # A compressible body, because for incompressible bytes the broken row
  # is accidentally correct; and a SECOND WRITABLE SESSION over a
  # generation a previous one published (phase C2), because inside one
  # session the seal re-renders those rows from locations the memtable
  # recorded itself and the damage never reaches a reader. Add --encrypt
  # and it also fires on the incompressible control, off by exactly the
  # 28 bytes a nonce and a GCM tag add.
  #
  # `git archive` rather than `git worktree add`: a worktree writes into
  # the repository's .git directory, and this script does not write to the
  # developer's repository. An archive is a read-only operation whose
  # output lands in a temp dir and is extracted onto a tmpfs inside the
  # container.
  echo "== RETRO: archiving $REPO at $RETRO_REF =="
  git -C "$REPO" rev-parse --verify "$RETRO_REF^{commit}" >/dev/null || {
    echo "not a commit: $RETRO_REF" >&2; exit 1; }
  RETRO_SHA="$(git -C "$REPO" rev-parse --short "$RETRO_REF")"
  RETRO_SUBJ="$(git -C "$REPO" log -1 --format=%s "$RETRO_REF")"
  echo "   $RETRO_SHA  $RETRO_SUBJ"
  git -C "$REPO" archive --format=tar "$RETRO_REF" > "$STAGE/retro.tar"

  echo "== RETRO: building the old pelfs inside the builder image (offline) =="
  # The module cache is mounted READ-ONLY and the network is off, so this
  # builds from what the host already has -- including the pre-fix go-nfs
  # the old go.mod names, which is the point.
  docker run --rm \
    --network none \
    -v "$STAGE/retro.tar":/retro.tar:ro \
    -v "$(go env GOMODCACHE)":/gomod:ro \
    --tmpfs /src:rw,size=1g,exec \
    --tmpfs /out:rw,size=256m,exec \
    --tmpfs /gocache:rw,size=4g \
    -e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOFLAGS=-mod=readonly \
    -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$ARCH" \
    -w /src \
    "$BUILDER_IMAGE" \
    sh -c 'tar -xf /retro.tar -C /src \
        && go build -o /out/pelfs ./cmd/pelfs \
        && go build -o /out/fakeorigin ./cmd/fakeorigin \
        && tar -cf - -C /out pelfs fakeorigin' > "$STAGE/retro-bins.tar"
  mkdir -p "$STAGE/retro"
  tar -xf "$STAGE/retro-bins.tar" -C "$STAGE/retro"
  rm -f "$STAGE/retro.tar" "$STAGE/retro-bins.tar"
  PELFS_BIN=/stage/retro/pelfs
  ORIGIN_BIN=/stage/retro/fakeorigin
  echo "   built $RETRO_SHA -> /stage/retro/{pelfs,fakeorigin}"
else
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
  PELFS_BIN=/stage/pelfs
  ORIGIN_BIN=/stage/fakeorigin
fi

# The corpus travels as data, not as a bind mount of the repo: the
# container must not be able to see the repository at all.
mkdir -p "$STAGE/testdata"
cp -R "$REPO/internal/hostile/testdata/corpus" "$STAGE/testdata/corpus"
if [ -n "$PLAN" ]; then
  [ -f "$PLAN" ] || { echo "no such plan file: $PLAN" >&2; exit 1; }
  cp "$PLAN" "$STAGE/replay.plan"
fi

# ---------------------------------------------------------------- budget
case "$MODE" in
  ci)
    # A few minutes: the whole corpus on both backends plus one short
    # random run per backend at a FIXED seed, so CI is reproducible and a
    # CI failure is replayable by hand with the same command.
    : "${OPS:=400}"
    : "${BIGDIR:=800}"
    : "${SEED:=20260821}"
    : "${TIMEOUT:=12m}"
    : "${RUN_PATTERN:=TestReplayTheRegressionCorpus|TestHostileFUSE|TestHostileNFS}"
    ;;
  long)
    # The manual mode: hours if you let it. Random seed unless one was
    # given, printed by the harness either way.
    : "${OPS:=20000}"
    : "${BIGDIR:=5000}"
    : "${TIMEOUT:=6h}"
    : "${RUN_PATTERN:=TestHostileFUSE|TestHostileNFS}"
    ;;
  retro)
    # Retro proves detection, so it runs the CORPUS -- the two sequences
    # whose bugs the old binary still has. A random run would also find
    # them, eventually; the corpus finds them in seconds and names them.
    : "${OPS:=200}"
    : "${BIGDIR:=200}"
    : "${SEED:=20260821}"
    : "${TIMEOUT:=15m}"
    : "${RUN_PATTERN:=TestReplayTheRegressionCorpus}"
    ;;
esac

# CAP_CHOWN and CAP_FOWNER: the vocabulary includes chown and utimes
# immediately after close, and the ORACLE is a tmpfs tree, so without these
# the reference cannot perform those ops and the whole shape silently stops
# being tested. They grant nothing that matters here — the only host-visible
# path is a read-only bind mount, where chown fails with EROFS regardless,
# and everything else is a tmpfs that dies with the container. Layer 4 is
# untouched.
#
# --drop-chown runs the same vocabulary with both dropped, which is the
# shape that found the mode-bits bug: with CAP_CHOWN absent, the NFS
# frontend used to ACCEPT a chown that the kernel and the FUSE frontend
# both refused. It is fixed (docs/TODO.md, modebits-agent — the frontend
# applies the model itself now, reading its OWN capability set, so dropping
# a capability changes its answer exactly as it changes the reference's),
# and this switch is what keeps that true: both variants must be green,
# the default one testing that the capabilities are honored and this one
# testing that their absence is.
CAPS=(--cap-add CHOWN --cap-add FOWNER)
if [ "$DROP_CHOWN" = 1 ]; then
  # Explicit drops rather than an empty array: --cap-drop ALL above already
  # covers it, and bash 3.2 (the macOS system shell) treats "${EMPTY[@]}"
  # as an unbound variable under `set -u`.
  CAPS=(--cap-drop CHOWN --cap-drop FOWNER)
  echo "   NOTE: running WITHOUT CAP_CHOWN/CAP_FOWNER. Both frontends must refuse"
  echo "         what the reference refuses; this is the variant that says so."
fi

ENVS=(
  -e PELFS_HOSTILE_CONTAINED=1
  -e PELFS_HOSTILE_SANDBOX=/sandbox
  -e "PELFS_HOSTILE_PELFS=$PELFS_BIN"
  -e "PELFS_HOSTILE_FAKEORIGIN=$ORIGIN_BIN"
  -e "PELFS_HOSTILE_OPS=$OPS"
  -e "PELFS_HOSTILE_BIGDIR=$BIGDIR"
  -e TMPDIR=/sandbox/tmp
  -e HOME=/sandbox
)
[ -n "$LARGEFILE" ] && ENVS+=(-e "PELFS_HOSTILE_LARGEFILE=$LARGEFILE")
[ -n "$SEED" ] && ENVS+=(-e "PELFS_HOSTILE_SEED=$SEED")
[ -n "$PLAN" ] && ENVS+=(-e PELFS_HOSTILE_PLAN_FILE=/stage/replay.plan)
ENVS+=("${EXTRA_ENVS[@]}")

echo "== running SEALED: --network none, --cap-drop ALL (+SYS_ADMIN for mount(2)),"
echo "   read-only rootfs, every writable byte on tmpfs, no repo mount =="
echo "   mode=$MODE ops=$OPS bigdir=$BIGDIR seed=${SEED:-random} timeout=$TIMEOUT"
echo "   pattern=$RUN_PATTERN"

# The inner preamble re-checks containment in the shell as well as in Go,
# and refuses to exec the binary otherwise. Two independent implementations
# of the same rule, because this is the rule that matters.
exec docker run --rm \
  --network none \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  "${CAPS[@]}" \
  --security-opt apparmor=unconfined \
  --device /dev/fuse \
  --read-only \
  --tmpfs /sandbox:rw,size=4g,exec,mode=0755 \
  --tmpfs /tmp:rw,size=512m,exec \
  --tmpfs /run:rw,size=64m \
  --tmpfs /var/lib/nfs:rw,size=16m \
  -v "$STAGE":/stage:ro \
  "${ENVS[@]}" \
  -w /stage \
  "$IMAGE_TAG" \
  sh -euc '
    # -------- containment re-check, in the container, before anything ----
    [ -f /etc/pelfs-hostile-container ] || { echo "no containment sentinel: refusing" >&2; exit 1; }
    [ ! -e /Users ] || { echo "/Users is visible: this is not the sealed container" >&2; exit 1; }
    # The rootfs must be read-only. If it is writable, the launcher was
    # edited and the guarantee is gone.
    if touch /containment-probe 2>/dev/null; then
      rm -f /containment-probe
      echo "the container rootfs is WRITABLE; refusing (expected --read-only)" >&2
      exit 1
    fi
    # /stage must be read-only: it is the only host-visible path, and it
    # must stay one-way.
    if touch /stage/containment-probe 2>/dev/null; then
      rm -f /stage/containment-probe
      echo "/stage is WRITABLE; refusing (expected a :ro bind mount)" >&2
      exit 1
    fi
    # No network at all. --network none is what keeps a hostile run from
    # reaching a real federation by accident.
    #
    # Read /proc/net/route rather than shelling out to `ip`: the runner
    # image has no iproute2, so `ip route show default` printed nothing
    # and the check passed on a container that HAD a default route. A
    # containment check that silently succeeds because its tool is missing
    # is worse than no check, so this one uses a file that is always
    # present and fails closed if it is not. (Destination 00000000 is the
    # default route.)
    if [ ! -r /proc/net/route ]; then
      echo "/proc/net/route is unreadable, so the no-network check cannot run; refusing" >&2
      exit 1
    fi
    # Shell-only, no awk: this whole preamble is a single-quoted argument
    # to `sh -euc`, so an embedded single-quoted awk program would close
    # the quote and leave $1 to be expanded by the OUTER shell.
    has_default=no
    while read -r rt_iface rt_dest rt_rest; do
      [ "$rt_iface" = Iface ] && continue
      [ "$rt_dest" = 00000000 ] && has_default=yes
    done < /proc/net/route
    if [ "$has_default" = yes ]; then
      echo "a default route exists; refusing (expected --network none)" >&2
      exit 1
    fi
    mkdir -p /sandbox/tmp
    echo "containment verified inside the container: sentinel present, rootfs ro,"
    echo "/stage ro, no default route, sandbox on tmpfs"
    # go test resolves testdata relative to the package dir, which is the
    # working directory of the compiled test binary.
    cd /sandbox && mkdir -p testdata && cp -R /stage/testdata/corpus testdata/corpus
    exec /stage/hostile.test "$@"
  ' -- \
  -test.v -test.count=1 -test.timeout "$TIMEOUT" -test.run "$RUN_PATTERN"
