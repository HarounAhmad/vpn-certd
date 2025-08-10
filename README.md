# VPN Certificate Issuance Agent (`vpn-certd`)

## Overview
`vpn-certd` is a hardened, single-purpose daemon for managing OpenVPN client and server certificates.  
It holds an **intermediate CA private key** and exposes a minimal local API to a trusted control application (e.g., Java-based admin panel).  
Root CA keys remain **offline**.

**Key goals:**
- Isolate CA private key from the main application.
- Enforce certificate issuance and revocation policies centrally.
- Minimize blast radius in case of compromise.
- Support fully automated VPN client provisioning with minimal user interaction.

---

## Features
- **Client certificate generation** (with server-side key generation or CSR signing).
- **Server certificate issuance**.
- **Certificate revocation** with CRL regeneration.
- **Policy enforcement** for CN patterns, lifetimes, key sizes, KU/EKU.
- **No plaintext private key persistence** — ephemeral in `tmpfs`.
- **Local-only UNIX socket API** — no TCP exposure.
- **Auditable** — all operations logged with CN, serial, CSR fingerprint, and timestamps.

---

## Architecture
```
[Admin Panel / Java App]
      |
      | AF_UNIX socket
      v
[ vpn-certd ] -- holds intermediate CA key
      |
      v
Intermediate CA
      |
      v
Signed Certificates / CRL
```

- **Root CA** – offline, used once to sign the intermediate CA.
- **Intermediate CA** – private key stored by `vpn-certd`, used to sign client/server certs.
- **Java App** – orchestrates provisioning (CCD, firewall rules, packaging `.ovpn` bundles), never sees CA key.

---

## Installation

### 1. Clone repository
```bash
git clone https://github.com/HarounAhmad/vpn-certd.git
cd vpn-certd
```

### 2. Install Go (>=1.20)
Follow [Go installation guide](https://go.dev/dl/).

### 3. Install dependencies
```bash
sudo apt update && sudo apt install -y make openssl
```

---

## Configuration

### 1. Create OpenSSL intermediate CA config
Create `dist/pki/openssl.cnf`:
```cnf
[ req ]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no
default_md         = sha256

[ dn ]
CN = dev-intermediate

[ v3_ca ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
```

### 2. Generate development intermediate CA
```bash
make dev-ca
make print-ca
```

---

## Building

```bash
make clean # Clean previous builds, will also delete the openssl.cnf
make build
```

This produces binaries in `bin/`:
- `vpn-certd` — daemon
- `vpn-certctl` — CLI client
- `vpn-bundle` — bundle generator

---

## Running

### Start daemon
```bash
./bin/vpn-certd   --socket ./dist/run/vpn-certd.sock   --pki ./dist/pki   --state ./dist/state   --policy ./dist/etc/policy.yaml   --crl-out ./dist/openvpn/crl.pem   --log-level info &
```

### Health check
```bash
./bin/vpn-certctl --socket ./dist/run/vpn-certd.sock --op HEALTH
```

---

## Certificate Operations

### 1. Generate key + certificate
```bash
./bin/vpn-certctl --socket ./dist/run/vpn-certd.sock   --op GENKEY_AND_SIGN   --cn admin-haroun   --profile client   --key-type rsa4096   --passphrase "CorrectHorseBattery"
```

### 2. Sign existing CSR
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/h.key
openssl req -new -key /tmp/h.key -subj "/CN=guest-minecraft" -out /tmp/h.csr
CSR="$(cat /tmp/h.csr)"
./bin/vpn-certctl --socket ./dist/run/vpn-certd.sock   --op SIGN   --cn guest-minecraft   --profile client   --csr "$CSR"
```

### 3. Revoke certificate
```bash
./bin/vpn-certctl --socket ./dist/run/vpn-certd.sock   --op REVOKE   --serial 1000   --reason keyCompromise
```

### 4. Get CRL
```bash
./bin/vpn-certctl --socket ./dist/run/vpn-certd.sock --op GET_CRL
```

---

## Building Client Bundles

### 1. Prepare artifacts
```bash
jq -r '.cert_pem' /tmp/issue.json > dist/admin-haroun.crt
jq -r '.key_pem_encrypted' /tmp/issue.json > dist/admin-haroun.key
cp dist/pki/int-ca.crt dist/ca.crt
echo "dummy-ta-key" > dist/ta.key
```

### 2. Build bundle
```bash
./bin/vpn-bundle   -cn admin-haroun   -ca dist/ca.crt   -ta dist/ta.key   -cert dist/admin-haroun.crt   -key dist/admin-haroun.key   -remote 127.0.0.1   -port 1194   -proto udp   -out dist/admin-haroun.zip
```

---

## Integration with OpenVPN
- Deploy `ca.crt`, `ta.key`, and `crl.pem` to OpenVPN server.
- Configure:
```bash
crl-verify /etc/openvpn/crl.pem
```

---

## Security Notes
- Limit socket access via filesystem ACLs.
- Run under restricted user, apply `systemd` hardening options.
- Root CA always offline.