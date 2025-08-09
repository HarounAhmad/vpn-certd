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

## API
All communication uses JSON over a **UNIX domain socket**.

### 1. Generate key + certificate
Request:
```json
{
  "op": "GENKEY_AND_SIGN",
  "cn": "admin-haroun",
  "profile": "client",
  "key_type": "rsa4096",
  "passphrase": "one-time-passphrase"
}
```
Response:
```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "key_pem_encrypted": "-----BEGIN ENCRYPTED PRIVATE KEY-----...",
  "serial": "01",
  "not_after": "2025-11-15T12:00:00Z"
}
```

### 2. Sign existing CSR
Request:
```json
{
  "op": "SIGN",
  "cn": "admin-haroun",
  "profile": "client",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```

### 3. Revoke certificate
Request:
```json
{
  "op": "REVOKE",
  "serial": "01",
  "reason": "keyCompromise"
}
```
Response:
```json
{
  "crl_pem": "-----BEGIN X509 CRL-----..."
}
```

### 4. Get CRL
Request:
```json
{
  "op": "GET_CRL"
}
```

---

## File Structure
```
/srv/pki/intermediate/     # CA material
  int-ca.crt
  int-ca.key               # 0600 signer:signer
  index.txt serial crlnumber crl.pem

/run/vpn-certd/            # UNIX socket dir (0700 signer:signer)
/srv/vpn/static/           # Public artifacts
  ca.crt
  ta.key
```

---

## Security Model
- **CA private key** never leaves the agent.
- Communication restricted to a **UNIX socket** with filesystem ACLs to the trusted app user.
- Root filesystem **read-only** inside container/VM.
- Work directory **tmpfs**; ephemeral key material wiped after use.
- `capabilities=none`, `no-new-privileges`, `seccomp`, `AppArmor` enforced.
- **No network access** — all I/O is filesystem and socket only.

---

## Hardening Example (systemd)
```
[Service]
User=signer
Group=signer
ExecStart=/usr/local/bin/vpn-certd --socket=/run/vpn-certd/sock --pki=/srv/pki/intermediate
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
ReadWritePaths=/srv/pki/intermediate /run/vpn-certd
```

---

## Integration with OpenVPN
- `ca.crt` from `/srv/vpn/static/ca.crt` used by server and included in client bundles.
- `ta.key` from `/srv/vpn/static/ta.key` included in bundles.
- `crl.pem` deployed to OpenVPN and referenced with:
  ```
  crl-verify /etc/openvpn/crl.pem
  ```
- No OpenVPN restart required on new cert issuance; only CRL updates on revocation.

---

## Example Workflow
1. **Admin** logs in to control panel.
2. **Control panel** calls `GENKEY_AND_SIGN` on `vpn-certd`.
3. **Agent** generates encrypted private key + signed certificate.
4. **Control panel** creates CCD entry + firewall rules.
5. **Control panel** assembles `.ovpn` bundle with:
    - `ca.crt`
    - `ta.key`
    - `<cn>.crt`
    - `<cn>.key` (encrypted)
    - `client-inline.ovpn` (optional)
6. **Admin** sends ZIP and passphrase to the end user via separate channels.

### Test
to Test the `vpn-certd` binary, you can run the following commands:

```bash
make clean
make build
file ./bin/vpn-certd
./bin/vpn-certd --socket ./dist/run/vpn-certd.sock --pki ./dist/pki --state ./dist/state --log-level info &
printf '{"op":"HEALTH"}\n' | socat - UNIX-CONNECT:./dist/run/vpn-certd.sock
```