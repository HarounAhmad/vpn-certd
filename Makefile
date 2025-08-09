APP := vpn-certd
BIN := bin/$(APP)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

.PHONY: all build run test vet fmt clean dirs

all: build

dirs:
	mkdir -p bin dist/run dist/pki dist/state

build: dirs
	# Force normal executable build; nuke any inherited GOFLAGS that request archives.
	GOFLAGS= CGO_ENABLED=0 go build -trimpath -buildmode=exe \
		-ldflags "-s -w -X github.com/HarounAhmad/vpn-certd/pkg/version.Commit=$(COMMIT)" \
		-o $(BIN) ./cmd/vpn-certd
	chmod 0755 $(BIN)

run: build
	./$(BIN) --socket ./dist/run/$(APP).sock --pki ./dist/pki --state ./dist/state --log-level info

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin dist
