# cert_scanner

A network certificate discovery tool that performs live TLS probing, extracts X.509 certificate metadata from remote hosts, and structures the output for ingestion into certificate management platforms.

---

## Abstract

Managing SSL/TLS certificates across a network is an operationally critical and often underinvested problem. Certificates expire silently, issuers go untrusted, and weak cryptographic primitives persist long after they should have been rotated. This tool addresses the discovery layer of that problem: given a list of network targets, it establishes a TLS session with each host, extracts the certificate chain presented during the handshake, parses the X.509 structure, and surfaces the fields that matter for operational risk assessment.

The output is structured JSON, designed with a schema compatible with REST API ingestion pipelines and certificate management platforms.

---

## Architecture

```
cert_scanner/
├── probe.py       # TCP/TLS layer
├── parser.py      # X.509 parsing layer
├── analyzer.py    # Risk analysis layer
├── main.py        # Orchestrator
├── targets.txt    # One host:port per line
└── output.json    # Generated on each run
```

Each module has a single responsibility. `probe.py` knows nothing about parsing. `parser.py` knows nothing about the network. `analyzer.py` is pure logic with no I/O. This separation makes each component independently testable and extensible.

---

## How It Works

### 1. Probing (`probe.py`)

A raw TCP socket is opened to the target host and port. The connection is then wrapped in a TLS context using Python's native `ssl` module, which triggers the TLS handshake. During the handshake, the server presents its certificate — your tool extracts it before the encrypted session begins.

SNI (Server Name Indication) is explicitly passed via `server_hostname`, ensuring that on shared-hosting infrastructure where multiple certificates coexist on a single IP, the correct certificate is returned.

The certificate is extracted in DER format (raw ASN.1-encoded bytes) and converted to PEM (base64 with standard headers) for downstream processing.

### 2. Parsing (`parser.py`)

The PEM certificate is loaded into an X.509 object using the `cryptography` library, which decodes the ASN.1 structure into addressable Python attributes. The following fields are extracted:

| Field | Description |
|---|---|
| `subject` | Common Name (CN) of the certificate holder |
| `issuer` | Common Name of the signing Certificate Authority |
| `valid_from` | Certificate validity start date |
| `valid_until` | Certificate validity end date |
| `days_to_expiry` | Days remaining until expiry (negative = already expired) |
| `sans` | Subject Alternative Names |
| `signature_algorithm` | Hash and signature scheme used by the CA |
| `public_key_type` | RSA or EC (Elliptic Curve) |
| `public_key_bits` | Key size in bits |
| `self_signed` | Whether the issuer and subject are identical |
| `serial_number` | Unique certificate identifier, used for revocation tracking |

Fields are accessed via OIDs (Object Identifiers) — standardized numerical codes defined in the X.509 specification that uniquely identify each attribute in the ASN.1 structure.

### 3. Risk Analysis (`analyzer.py`)

The parsed dictionary is evaluated against a set of operational risk rules:

- `EXPIRED` — `days_to_expiry < 0`
- `CRITICAL` : expiry within 7 days
- `WARNING` : expiry within 30 days
- `SELF_SIGNED` : issuer equals subject; no trusted CA vouches for this certificate
- `WEAK_ALGORITHM` : SHA-1 or MD5 detected in the signature algorithm
- `WEAK_KEY` : RSA key size below 2048 bits

### 4. Orchestration (`main.py`)

Reads `targets.txt` (one `host:port` per line), runs each target through the full pipeline, and writes the aggregated results to `output.json`. Errors on individual hosts are caught and logged without interrupting the scan.

---

## Installation

```bash
git clone https://github.com/walidooo3e/cert_scanner.git
cd cert_scanner
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography pyopenssl
```

---

## Usage

### Single host (current)

```python
from probe import get_pem_certificate
from parser import parse_certificate

pem = get_pem_certificate("github.com", 443)
result = parse_certificate(pem)
print(result)
```

### Test against known-bad certificates

[badssl.com](https://badssl.com) provides endpoints specifically designed for testing TLS scanners:

```bash
# Expired certificate
python3 -c "from probe import *; print(get_pem_certificate('expired.badssl.com'))"

# Self-signed certificate
python3 -c "from probe import *; print(get_pem_certificate('self-signed.badssl.com'))"

# SHA-1 intermediate
python3 -c "from probe import *; print(get_pem_certificate('sha1-intermediate.badssl.com'))"
```

Note: with `create_default_context()`, connections to invalid certificates will raise exceptions by design. Error handling for scanner mode (where verification is intentionally disabled) is part of the planned implementation.

---

## Sample Output

```json
{
  "subject": "github.com",
  "issuer": "DigiCert TLS RSA SHA256 2020 CA1",
  "valid_from": "2024-03-07",
  "valid_until": "2025-03-07",
  "days_to_expiry": 124,
  "sans": ["github.com", "www.github.com"],
  "signature_algorithm": "sha256",
  "public_key_type": "RSA",
  "public_key_bits": 2048,
  "self_signed": false,
  "serial_number": "16115816711950100753"
}
```

---

## Design Decisions

**Why native `ssl` and `socket` instead of `requests` or `httpx`?**
HTTP libraries abstract away the TLS layer. This tool needs direct access to the handshake and the certificate it exposes, not the HTTP response. Working at the socket level also means the tool is protocol-agnostic: it can probe SMTP, LDAP, or any TLS-wrapped service, not just HTTPS.

**Why JSON output?**
The output schema is designed to be consumed by certificate management platforms via REST API ingestion pipelines. JSON is the standard interchange format for this class of tooling. Each record is self-contained and maps directly to the fields a platform like CertManager would need to track and alert on.

**Why separate `probe`, `parse`, and `analyze`?**
Separation of concerns. A scanner that probes and parses in the same function cannot be unit tested properly, cannot be extended without risk, and cannot be reasoned about independently. The current architecture allows each layer to be swapped or upgraded without touching the others, let's take, for example, upgrading `probe.py` to use `pyOpenSSL` for full chain extraction without changing parser logic.

---

## Planned Extensions

- **Full chain extraction** using `pyOpenSSL` to retrieve intermediate and root certificates, not just the leaf
- **Concurrent scanning** via `asyncio` for performance across large target sets
- **STARTTLS support** for non-HTTPS services (SMTP port 587, LDAP port 636, IMAP port 993)
- **CIDR range scanning** to discover certificates across an IP range
- **Platform integration** REST API output compatible with certificate management platform ingestion

---

## Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | X.509 parsing, ASN.1 decoding, OID resolution |
| `pyopenssl` | Full certificate chain extraction (planned) |
| `ssl`, `socket` | Native Python TLS and TCP (no install required) |

---