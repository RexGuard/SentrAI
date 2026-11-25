# SentrAI Gate build.
#   make          build ./sentrai-gate (needs Go 1.23+)
#   make bpf      rebuild the kernel program after editing bpf/ (needs clang)
#   make test     run all tests (kernel tests need root: sudo make test)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/RexGuard/SentrAI/gate/internal/engine.Version=$(VERSION)

sentrai-gate: $(shell find cmd internal -name '*.go' -o -name '*.o')
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/sentrai-gate

bpf:
	cd internal/kern && go generate ./...

test:
	go vet ./...
	go test ./...

clean:
	rm -f sentrai-gate

.PHONY: bpf test clean
