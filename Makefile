ARCH  := $(shell go env GOARCH)

.PHONY: all build linux test e2e integration mount-gate opfuzz hostile hostile-long hostile-retro unprivileged crash big-tree vet clean

all: build

build:
	CGO_ENABLED=0 go build -o bin/pelfs ./cmd/pelfs

# Linux binary for the containerized test harnesses, which cross-compile on
# the host because the test image carries no toolchain.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/pelfs-linux-$(ARCH) ./cmd/pelfs

# ./... rather than ./internal/...: cmd/pelfs holds the tests for the mount
# session itself — the exit seal, the checkpoint cadence, what a FAILED seal
# leaves behind — and leaving them out of the project's own test target
# meant the paths closest to a user were the ones it did not check.
test:
	CGO_ENABLED=0 go test ./...

e2e:
	./scripts/e2e-docker.sh

mount-gate:
	./scripts/mount-gate-docker.sh

integration:
	./scripts/integration-pelican.sh

opfuzz:
	./scripts/opfuzz-docker.sh

# The hostile filesystem exerciser: adversarial op sequences against a REAL
# mount (both frontends), with a reference tree mutated identically and
# byte-and-metadata-exact comparison at checkpoints, then the whole
# lifecycle -- seal, cold remount, compare, fsck --deep, gc -- plus a
# kill -9 and recovery.
#
# There is NO host target and there will not be one. Running this outside
# its container is not discouraged, it is impossible: the code is behind a
# build tag, refuses to start without an env var only the launcher sets,
# aborts unless a sentinel file from the launcher's own image is present,
# confines every path through os.Root, and proves that confinement before
# it starts. Every target below is the launcher.
hostile:
	./scripts/hostile-docker.sh

# Hours if you let it: 20k ops, 5000-entry directories, a random seed
# (printed, and replayable with --seed).
hostile-long:
	./scripts/hostile-docker.sh --long

# Today's exerciser against an OLD pelfs, built inside the container from
# a git archive. Proof that it finds what humans found: EXPECTED TO FAIL,
# and each failure is one of the release-week bugs. See the script's RETRO
# comment for why the reference is a fix's parent and not v0.1.0.
hostile-retro:
	./scripts/hostile-docker.sh --retro

# kill -9 a mount mid-flush, remount, and hold recovery to its contract.
crash:
	./scripts/crash-recovery-docker.sh

# 50k files through both frontends, two generations, with bounds on the
# rates it measures. ~4 minutes.
big-tree:
	./scripts/bench-untar-nfs-docker.sh 50000 2500 4

# The scenario a user actually has: a linux/amd64 binary on a host where
# they are not root.
unprivileged:
	./scripts/unprivileged-docker.sh

vet:
	CGO_ENABLED=0 go vet ./...

clean:
	rm -rf bin
