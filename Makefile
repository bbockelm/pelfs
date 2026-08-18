ARCH  := $(shell go env GOARCH)

.PHONY: all build linux test e2e integration mount-gate vet clean

all: build

build:
	CGO_ENABLED=0 go build -o bin/pelfs ./cmd/pelfs

# Linux binary for the containerized test harnesses, which cross-compile on
# the host because the test image carries no toolchain.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o bin/pelfs-linux-$(ARCH) ./cmd/pelfs

test:
	CGO_ENABLED=0 go test ./internal/...

e2e:
	./scripts/e2e-docker.sh

mount-gate:
	./scripts/mount-gate-docker.sh

integration:
	./scripts/integration-pelican.sh

vet:
	CGO_ENABLED=0 go vet ./...

clean:
	rm -rf bin
