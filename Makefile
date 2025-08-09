APP := vpn-certd
BIN := bin/$(APP)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

.PHONY: all build run test vet fmt clean dirs

all: build

dirs:
	mkdir -p bin dist/run dist/pki dist/state

CTL := bin/vpn-certctl

build: dirs
	GOFLAGS= CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X github.com/HarounAhmad/vpn-certd/pkg/version.Commit=$(COMMIT)" \
		-o $(BIN) ./cmd/vpn-certd
	chmod 0755 $(BIN)
	GOFLAGS= CGO_ENABLED=0 go build -trimpath -o $(CTL) ./cmd/vpn-certctl
	chmod 0755 $(CTL)

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


dev-ca:
	mkdir -p dist/pki
	openssl genrsa -out dist/pki/int-ca.key 4096
	openssl req -x509 -new -key dist/pki/int-ca.key -days 3650 -config dist/pki/openssl.cnf -extensions v3_ca -out dist/pki/int-ca.crt

print-ca:
	openssl x509 -in dist/pki/int-ca.crt -noout -text | sed -n '1,60p'
