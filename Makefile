ARCH  := $(shell go env GOARCH)

.PHONY: all build linux test e2e integration mount-gate opfuzz vet clean

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

vet:
	CGO_ENABLED=0 go vet ./...

clean:
	rm -rf bin
