#!/usr/bin/env bash
# Run the APPTAINER FEASIBILITY MATRIX inside a Linux container.
#
# The question this answers is the owner's: can an unprivileged HTCondor
# job on a worker node run `apptainer` against a container image that
# lives in a pelfs volume? Nothing on a macOS host can answer it — macOS
# denies the shell access to its own FUSE mounts, and apptainer is Linux
# only — so the only honest local answer is a real Linux kernel in a
# container, the same shape scripts/mount-gate-docker.sh uses.
#
# Findings live in docs/design-apptainer.md. This script is how they were
# obtained and how they are re-obtained.
#
# ====================== WHAT THE CONTAINER MODELS =======================
#
#   NATIVE ARCH. Apptainer publishes prebuilt packages for amd64 only, so
#   on an arm64 host this BUILDS APPTAINER FROM SOURCE rather than running
#   an amd64 one under emulation. That is not fussiness: under Docker
#   Desktop's amd64 emulation every `apptainer exec` dies at the final
#   execve with EINVAL, including images on local disk, so an emulated run
#   cannot tell a pelfs problem from an emulator problem. Two minutes of
#   `mconfig && make` buys a matrix that means something.
#
#   UNPRIVILEGED. The payload runs as uid 1001 with no supplementary
#   groups, against a NON-setuid apptainer (mconfig --without-suid, so
#   there is no starter-suid to fall back to). Every container it starts
#   goes through the unprivileged user-namespace path — the one a batch
#   job gets.
#
#   --security-opt seccomp=unconfined IS NOT A PRIVILEGE. Docker's default
#   seccomp profile refuses clone/unshare with CLONE_NEWUSER to a process
#   without CAP_SYS_ADMIN, so NO unprivileged container runtime can start
#   inside a default container. Unconfining seccomp only stops the
#   container runtime from blocking a syscall the host kernel already
#   allows; it hands uid 1001 nothing. It stands in for a worker node whose
#   kernel permits unprivileged user namespaces — the site policy this
#   whole scenario rests on, and the one thing no container can decide.
#
#   --cap-add SYS_ADMIN is in the BOUNDING SET only, for the same reason
#   scripts/unprivileged-docker.sh needs it: fusermount3 is setuid-root and
#   needs CAP_SYS_ADMIN to call mount(2) for pelfs. uid 1001 holds no
#   capabilities and gains none — a real login node's fusermount3 has
#   exactly this, so this is faithful rather than generous.
#
#   `enable overlay = no` IS BAKED INTO apptainer.conf, and this is the one
#   deviation from a stock install, so it is spelled out. Apptainer's
#   default builds the container root as a KERNEL OVERLAYFS whose lower
#   layer is the squashfuse mount of the SIF. On this kernel (Docker
#   Desktop's LinuxKit 6.12) a binary on such an overlay can be READ and
#   cannot be EXEC'd: execve returns EINVAL, because load_elf_binary turns
#   a failed mmap into EINVAL. It fails identically for a SIF on LOCAL
#   DISK, which is what proves it is the kernel and not pelfs — and it is
#   obviously not what a real site sees, since sites run SIFs all day.
#   `enable overlay = no` moves apptainer to its underlay/bind path, where
#   the container root IS the squashfuse mount, and everything works. The
#   test still runs a local-disk control for every case so the attribution
#   is visible in the output rather than asserted here.
#
#   --security-opt systempaths=unconfined IS ALSO NOT A PRIVILEGE, and is
#   here for exactly one case: --fusemount. Apptainer mounts a FRESH procfs
#   when it runs a FUSE driver, and the kernel's mount_too_revealing() check
#   refuses a new proc mount in a user namespace while the existing one has
#   masked entries — which is precisely what Docker does to /proc/kcore and
#   friends. Without this flag every --fusemount attempt dies with
#   "can't mount proc filesystem to /proc: operation not permitted", which
#   is Docker's masking and nothing about pelfs. A worker node's /proc is
#   not masked, so unconfining it is what makes the container resemble one.
#
#   --network none. The image is built WITH network (apptainer sources,
#   base images, SIFs); the test runs with none, and talks only to a
#   fakeorigin on its own loopback. Timing therefore understates a real
#   federation by however slow the real one is; byte counts do not change.
#
# Usage: scripts/apptainer-docker.sh [-- extra args to the test]
#        scripts/apptainer-docker.sh -- --only-fusemount   (sections 1,2,7)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${PELFS_APPTAINER_IMAGE:-pelfs-apptainer-runner:4}"
AV="${PELFS_APPTAINER_VERSION:-1.5.3}"
GOIMG="${PELFS_APPTAINER_BUILDER:-golang:1.26-trixie}"
BASE="${PELFS_DOCKER_IMAGE:-debian:stable-slim}"
STAGE="$(mktemp -d)"
[ "${1:-}" = "--" ] && shift
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  echo "== building the apptainer test image (once; needs network, ~4 min) =="
  # The SIF set exists for the dedup question as much as the exec one:
  # el9-derived is the SAME sandbox as el9 plus a 3 MB payload and a
  # script, which is what "my image is FROM the base image" produces, and
  # el9-tiny-change is the same sandbox plus ONE small file, the floor of
  # what any change can cost. el10 is the other question — the base moved.
  docker build -q -t "$IMAGE_TAG" - <<DOCKERFILE
FROM ${GOIMG} AS builder
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
      build-essential libseccomp-dev pkg-config uuid-dev cryptsetup-bin \
      git wget ca-certificates libfuse3-dev libglib2.0-dev
WORKDIR /src
RUN wget -q https://github.com/apptainer/apptainer/releases/download/v${AV}/apptainer-${AV}.tar.gz \
 && tar xf apptainer-${AV}.tar.gz \
 && cd apptainer-${AV} \
 && ./mconfig --without-suid --prefix=/usr/local >/dev/null \
 && make -C builddir >/dev/null \
 && make -C builddir install DESTDIR=/out >/dev/null

FROM ${BASE}
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
      ca-certificates squashfuse squashfs-tools fuse3 fuse-overlayfs uidmap \
      procps busybox-static file strace jq time \
 && ln -sf /usr/bin/fusermount3 /bin/fusermount \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/usr/local /usr/local
# See the header: this kernel cannot exec off overlayfs-whose-lower-is-FUSE,
# for a SIF on local disk exactly as for one on pelfs.
RUN sed -i 's/^enable overlay = yes/enable overlay = no/' /usr/local/etc/apptainer/apptainer.conf \
 && grep '^enable overlay' /usr/local/etc/apptainer/apptainer.conf \
 && useradd -m -u 1001 job && apptainer --version \
 && apptainer buildcfg | grep APPTAINER_SUID_INSTALL
ENV APPTAINER_TMPDIR=/var/tmp
RUN mkdir -p /images \
 && apptainer build --sandbox /var/tmp/el9 docker://almalinux:9 \
 && apptainer build /images/el9.sif /var/tmp/el9 \
 && cp -a /var/tmp/el9 /var/tmp/el9d \
 && mkdir -p /var/tmp/el9d/opt/analysis \
 && head -c 3000000 /dev/urandom > /var/tmp/el9d/opt/analysis/payload.bin \
 && echo "my analysis code" > /var/tmp/el9d/opt/analysis/run.sh \
 && apptainer build /images/el9-derived.sif /var/tmp/el9d \
 && cp -a /var/tmp/el9 /var/tmp/el9t \
 && echo "one small script" > /var/tmp/el9t/tiny.sh \
 && apptainer build /images/el9-tiny-change.sif /var/tmp/el9t \
 && apptainer build /images/el10.sif docker://almalinux:10 \
 && cp -a /var/tmp/el9 /images/el9-sandbox \
 && rm -rf /var/tmp/el9 /var/tmp/el9d /var/tmp/el9t \
 && chmod -R a+rX /images && ls -l /images
DOCKERFILE
fi

echo "== cross-compiling pelfs for the container's arch =="
ARCH="$(docker image inspect "$IMAGE_TAG" --format '{{.Architecture}}')"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/pelfs" ./cmd/pelfs)
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$STAGE/fakeorigin" ./cmd/fakeorigin)
cp "$REPO/scripts/apptainer-test.sh" "$STAGE/test.sh"
# The --fusemount driver wrapper is shipped as itself, not inlined by the
# test: it is the file a job would deliver, so the harness proves THAT file
# works rather than a copy of it that has drifted.
cp "$REPO/scripts/pelfs-fusemount.sh" "$STAGE/pelfs-fusemount.sh"
chmod -R a+rX "$STAGE"

echo "== running the apptainer matrix on a real Linux kernel (linux/$ARCH) =="
exec docker run --rm \
  --device /dev/fuse \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  --user 1001:1001 \
  --network none \
  -v "$STAGE":/stage:ro \
  --tmpfs /work:rw,size=4g,exec,uid=1001,gid=1001 \
  --tmpfs /var/tmp:rw,size=1g,exec,uid=1001,gid=1001 \
  -e HOME=/work/home \
  -e TMPDIR=/work \
  -e APPTAINER_TMPDIR=/work/atmp \
  -e PELFS_APPTAINER_CONTAINED=1 \
  -w /work \
  "$IMAGE_TAG" \
  /bin/bash /stage/test.sh "$@"
