APP := vpn-certd
BIN := bin/$(APP)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
CTL := bin/vpn-certctl
BUNDLE := bin/vpn-bundle

.PHONY: all build run test vet fmt clean dirs dev-ca print-ca

all: build

dirs:
	mkdir -p bin dist/run dist/pki dist/state

build: dirs
	GOFLAGS= CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X github.com/HarounAhmad/vpn-certd/pkg/version.Commit=$(COMMIT)" \
		-o $(BIN) ./cmd/vpn-certd
	chmod 0755 $(BIN)
	GOFLAGS= CGO_ENABLED=0 go build -trimpath -o $(CTL) ./cmd/vpn-certctl
	chmod 0755 $(CTL)
	GOFLAGS= CGO_ENABLED=0 go build -trimpath -o $(BUNDLE) ./cmd/vpn-bundle
	chmod 0755 $(BUNDLE)

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
	openssl x509 -in dist/pki/int-ca.crt -noout -text | sed -n '1,80p'

deps:
	go mod tidy

install-policy:
	mkdir -p dist/etc
	cp config/policy.yaml dist/etc/policy.yaml


install:
	install -Dm0755 bin/vpn-certd /usr/local/bin/vpn-certd
	install -Dm0755 bin/vpn-certctl /usr/local/bin/vpn-certctl
	install -Dm0755 bin/vpn-bundle /usr/local/bin/vpn-bundle
	install -Dm0644 config/policy.yaml /etc/vpn-certd/policy.yaml
	install -Dm0644 deploy/systemd/vpn-certd.service /etc/systemd/system/vpn-certd.service
	install -Dm0644 deploy/systemd/vpn-certd.socket /etc/systemd/system/vpn-certd.socket
	install -Dm0644 deploy/systemd/openvpn-crl.path /etc/systemd/system/openvpn-crl.path
	install -Dm0644 deploy/systemd/openvpn-crl.service /etc/systemd/system/openvpn-crl.service
	install -Dm0644 deploy/tmpfiles/vpn-certd.conf /usr/lib/tmpfiles.d/vpn-certd.conf
	install -Dm0644 deploy/sysusers/vpn-certd.conf /usr/lib/sysusers.d/vpn-certd.conf
	install -d -m0755 /var/lib/vpn-certd/pki /var/lib/vpn-certd/state
	install -d -m0755 /etc/vpn-certd
	@if [ -f dist/pki/int-ca.crt ]; then install -Dm0600 dist/pki/int-ca.key /var/lib/vpn-certd/pki/int-ca.key; fi
	@if [ -f dist/pki/int-ca.crt ]; then install -Dm0644 dist/pki/int-ca.crt /var/lib/vpn-certd/pki/int-ca.crt; fi

enable:
	systemd-sysusers
	systemd-tmpfiles --create
	systemctl daemon-reload
	systemctl enable --now vpn-certd.socket
	systemctl enable --now openvpn-crl.path