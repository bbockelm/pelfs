TAGS  := nogspt,notikv
ARCH  := $(shell go env GOARCH)

.PHONY: all build linux test e2e integration vet clean

all: build linux

build:
	CGO_ENABLED=0 go build -tags "$(TAGS)" -o bin/pelfs ./cmd/pelfs

# Linux binary for the Docker fallback; pelfs looks for it next to itself.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -tags "$(TAGS)" -o bin/pelfs-linux-$(ARCH) ./cmd/pelfs

test:
	CGO_ENABLED=0 go test -tags "$(TAGS)" ./internal/...

e2e:
	./scripts/e2e-docker.sh

integration:
	./scripts/integration-pelican.sh

vet:
	CGO_ENABLED=0 go vet -tags "$(TAGS)" ./...

clean:
	rm -rf bin
