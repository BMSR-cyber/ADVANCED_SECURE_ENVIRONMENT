# KRS Verification Policy v1

## Overview

This document specifies the **exact verification checks** the Key Release Service (KRS) must perform before releasing a Customer Encryption Key (CEK) to a confidential VM. Every check is **fail-closed**: a single failure at any stage results in key-release refusal.

The KRS is the **final trust anchor** in the confidential deployment pipeline. It bridges the gap between hardware attestation and runtime secret delivery. Its correctness — both in what it checks and in what it refuses to reveal — is the lynchpin of the entire system.

### Architecture Context

```
Confidential VM                KRS                    AMD KDS         Auditor
     │                          │                        │                │
     │── attestation_report ──>│                        │                │
     │── ephemeral_pubkey ────>│── fetch VCEK cert ────>│                │
     │── contract_id ─────────>│                        │                │
     │── nonce ───────────────>│── verify entire chain  │                │
     │                          │── check contract policy│                │
     │                          │── wrap CEK ───────────│                │
     │<── wrapped_cek ─────────│                        │                │
     │<── KRS signature ──────│                        │                │
     │                          │── signed audit record ───────────────>│
```

---

## Check Order

All checks execute sequentially in the order defined below. The KRS **must not short-circuit by reordering checks**, even if an earlier check would be cheaper to compute. The fixed order prevents timing side-channels from leaking which check failed.

**Any failure at any step produces an identical HTTP 403 response** (see [Error Handling](#6-error-handling)).

---

### 1. Transport Security

Before any request content is examined, the transport layer must meet minimum security requirements.

#### 1.1 Client Certificate Validation

- The client (confidential VM) presents an X.509 client certificate.
- The KRS validates the certificate chain against a **pinned CA certificate** provisioned at KRS deployment time.
- The pinned CA is specific to the trust domain; it is **not** a public CA.
- Certificate must not be expired.
- Certificate must not be revoked (CRL or OCSP, with hard-fail on OCSP lookup failure).

```yaml
# KRS transport config (conceptual)
tls:
  min_version: "1.3"
  client_ca_pin: "sha256:abcd1234..."
  require_client_cert: true
  crl_refresh_interval: 3600  # seconds
  ocsp_hard_fail: true
```

#### 1.2 TLS Version

- TLS 1.3 is the **minimum** acceptable version.
- TLS 1.2 connections are **rejected** at the handshake level.
- The KRS must advertise only TLS 1.3 in its server hello.

#### 1.3 Channel Binding

- The KRS computes the **TLS-Exporter** value (RFC 9266) for the established session.
- The VM includes this TLS-Exporter value as `channel_binding` in the request body.
- The KRS verifies that the request's `channel_binding` matches the session's computed value.
- This prevents request-forwarding attacks where a malicious proxy relays a valid attestation request from a legitimate VM.

```
channel_binding = TLS-Exporter(label="hpvs-krs-channel-binding", context=client_cert_fingerprint, length=32)
```

#### 1.4 Rate Limiting

- **Per VM limit**: maximum 10 verification attempts per minute (identified by the client certificate's Subject Key Identifier, or by source IP if certificate identity is unknown — but IP-based limits are only a coarse fallback).
- **Global limit**: maximum 1,000 verification attempts per minute across all clients (prevents the KRS from being overwhelmed).
- Exceeding the rate limit returns HTTP 429, **not** 403, to distinguish it from attestation failures.
- Rate limit counters are stored in a local LRU cache and are not shared between KRS instances (acceptable since each KRS instance serves a distinct set of VMs in its region).

---

### 2. Request Validation

Once the transport layer is accepted, the KRS validates the structure and integrity of the request payload.

#### 2.1 JSON Schema Validation

The request body must conform to:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "contract_id",
    "ephemeral_pubkey",
    "nonce",
    "attestation_report",
    "vcek_certificate",
    "timestamp",
    "channel_binding",
    "operator_token"
  ],
  "properties": {
    "contract_id": {
      "type": "string",
      "format": "uuid"
    },
    "ephemeral_pubkey": {
      "type": "string",
      "pattern": "^[A-Za-z0-9+/]{43}=$",
      "description": "Base64-encoded X25519 public key (32 bytes = 43 base64 chars + padding)"
    },
    "nonce": {
      "type": "string",
      "pattern": "^[A-Za-z0-9+/]{43}=$",
      "description": "Base64-encoded 32-byte random nonce"
    },
    "attestation_report": {
      "type": "string",
      "minLength": 1184,
      "maxLength": 10000,
      "description": "Base64-encoded SNP attestation report (minimum 1184 bytes raw)"
    },
    "vcek_certificate": {
      "type": "string",
      "description": "Base64-encoded DER VCEK certificate"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO8601 with timezone"
    },
    "channel_binding": {
      "type": "string",
      "pattern": "^[A-Za-z0-9+/]{43}=$"
    },
    "operator_token": {
      "type": "string",
      "description": "JWT signed by an allowed operator key"
    }
  }
}
```

#### 2.2 Contract ID Validation

- `contract_id` is looked up in the KRS's local contract cache.
- Contract must exist (not found → reject).
- Contract must be in `ACTIVE` state (not `EXPIRED`, not `REVOKED`).
- Contract's `metadata.expires` must be in the future (KRS clock is the authority).

#### 2.3 Ephemeral Public Key Validation

- Decode base64 → must yield exactly 32 bytes.
- The byte sequence must be a valid X25519 public key: all 32 bytes are not all-zero; the high bit is not meaningful (X25519 clamps are handled during ECDH computation, not validation).
- Key must be different from any key seen in the last 3600 seconds (key freshness challenge — prevents re-use of a stolen wrapped CEK).

#### 2.4 Nonce Freshness

- Decode nonce → must yield exactly 32 bytes.
- Nonce must not appear in the **replay cache**:

```
Replay cache configuration:
  - Backend: in-memory LRU with overflow to disk-backed bloom filter
  - Max entries: 100,000
  - TTL: 3600 seconds (1 hour)
  - Eviction: LRU after TTL expiry
  - Cache key: hash(contract_id || nonce)
```

- If a nonce is seen → the request is a replay → reject.
- After successful verification (or after rejection for any reason other than replay), the nonce is inserted into the cache to prevent reuse.

#### 2.5 Timestamp Freshness

- Parse `timestamp` as ISO8601 with timezone.
- Compute `delta = abs(KRS_clock - request_timestamp)`.
- If `delta > 300 seconds` (5 minutes) → reject.
- This prevents stale attestation reports from being replayed days later.
- The 300-second window allows for clock skew between VM and KRS plus VM boot and attestation generation time.

#### 2.6 Operator Token Validation

- `operator_token` is a JWT (JSON Web Token) with the following required claims:

| Claim | Description |
|---|---|
| `sub` | Operator identity (e.g., GCP service account) |
| `iat` | Issued-at timestamp |
| `exp` | Expiry (max 15 minutes from `iat`) |
| `contract_id` | Must match the request's `contract_id` |
| `environment_id` | Must match the contract's environment context |

- Token signature is verified against a list of **allowed operator public keys** maintained in the contract registry.
- Token must not be expired.
- Token must not have been previously used (nonce embedded in `jti` claim, checked against the same replay cache with a separate prefix).

---

### 3. Attestation Report Verification (AMD SEV-SNP)

This is the core of the TEE verification. The KRS must cryptographically verify that the attestation report was genuinely produced by AMD SEV-SNP firmware running on authentic hardware.

#### 3.1 Report Structure

The SNP attestation report is a 1184-byte structure. Key fields:

| Offset | Size | Field | Use |
|---|---|---|---|
| 0x000 | 4 | Version | Must be ≥ 2 |
| 0x004 | 4 | Guest SVN | Reserved |
| 0x008 | 8 | Policy | Encoded policy flags |
| **0x0A0** | **48** | **Measurement** | **SHA-384 of the VM's initial memory state** |
| 0x0D0 | 32 | Host Data | Provided by the hypervisor |
| 0x110 | 32 | ID Key Digest | One of MASK_CHIP_ID, MASK_CHIP_KEY |
| 0x130 | 32 | Author Key Digest | Identifies the key that signed the ID block |
| **0x1A0** | **64** | **Report Data** | **512 bits of VM-supplied data (launch digest target)** |
| 0x2A0 | 512 | Signature | ECDSA P-384 signature over [0x000, 0x2A0) |
| 0 | 32 | Report ID | Unique per report |

For the full structure, see AMD SEV-SNP ABI Specification, Table 21.

#### 3.2 VCEK/VLEK Certificate Chain Verification

The attestation report is signed by the Versioned Chip Endorsement Key (VCEK) or Versioned LE Key (VLEK), embedded in the AMD processor.

**Step A — Parse VCEK certificate**:
- Decode the DER certificate provided by the VM.
- Extract the VCEK public key (ECDSA P-384).
- Extract the CHIP_ID and firmware TCB version from the VCEK certificate extensions.

**Step B — Verify certificate chain to AMD root**:
```
VCEK/VLEK ─── signed by ──> ARK (AMD Root Key)
                 │
                 └─ signed by ──> ASK (AMD SEV Signing Key)

The complete chain is: VCEK ← ASK ← ARK
```

- ARK is the AMD root certificate, pinned in the KRS configuration.
- ASK is the intermediate signing key, fetched from the AMD Key Distribution System (KDS).
- The KRS must fetch CRLs for both ARK and ASK from AMD KDS.
- The KRS must verify that both ARK and ASK are not revoked.

**Step C — Verify attestation report signature**:
- Hash the first 0x2A0 bytes of the attestation report with SHA-384.
- Verify the ECDSA P-384 signature at offset 0x2A0 using the VCEK public key.
- The signature covers all bytes from offset 0x000 to offset 0x29F inclusive.

#### 3.3 Certificate Revocation Checking

- CRLs are fetched from AMD KDS at KRS startup and refreshed every 3600 seconds.
- If a CRL fetch fails, the KRS continues using the last-known-good CRL for up to 24 hours, then hard-fails (fail-closed — no key release without valid CRL data).
- OCSP is also checked if the certificate contains an OCSP responder URL.
- Both CRL and OCSP must agree the certificate is not revoked.

#### 3.4 Extract Report Data

- Read 64 bytes from offset 0x1A0.
- Interpret as: `SHA-512(ephemeral_pubkey || nonce || contract_id || image_digest)`.
- This binding proves the VM tied this specific attestation to this specific request and this specific contract.

#### 3.5 Extract Measurement

- Read 48 bytes from offset 0x0A0.
- This is the SHA-384 measurement of the VM's initial memory state (firmware + bootloader + kernel + initrd).
- Compare against the contract's `workload.expected_sev_measurement`.

#### 3.6 Extract TCB Version

- Parse the `TCB` field from the attestation report (offset 0x018, 8 bytes).
- The TCB version encodes the firmware patch level.
- Compare against the contract's `environment.min_tcb_version`.

#### 3.7 Extract Policy Flags

- Policy is at offset 0x008 (8 bytes, 64-bit bitfield).
- Key flags:

| Bit | Mask | Field | Meaning |
|---|---|---|---|
| 0 | 0x01 | SMT_ENABLED | 1 = SMT is enabled |
| 1 | 0x02 | (reserved) | |
| 2 | 0x04 | MIGRATION_AGENT_ALLOWED | 1 = MA can migrate the VM |
| 3 | 0x08 | DEBUG_ALLOWED | 1 = debug is permitted |
| 4 | 0x10 | SINGLE_SOCKET | 1 = single socket only |

---

### 4. Policy Verification (Against Deployment Contract)

After the attestation report is cryptographically verified, the KRS checks each extracted value against the deployment contract's policy. Failures at this stage are **policy failures** — the hardware is authentic, but the VM state does not meet the deployment requirements.

#### 4.1 Measurement Allowlist Check

```
IF attestation.measurement != contract.workload.expected_sev_measurement
  → REJECT (reason: measurement_allowlist)
ENDIF
```

- The measurement must match **exactly**. No prefix matching, no fuzzy matching.
- If the contract contains both `expected_sev_measurement` and `expected_tdx_mrconfigid`, and the attested TEE type is SEV-SNP, only the SEV measurement is checked (and vice versa).

#### 4.2 Report Data Binding Check

```
expected_report_data = SHA-512(
    request.ephemeral_pubkey 
    || request.nonce 
    || request.contract_id 
    || contract.workload.image_digest
)

IF attestation.report_data != expected_report_data
  → REJECT (reason: report_data_binding)
ENDIF
```

- The `||` operator denotes raw byte concatenation (no length prefixes, no encoding).
- `image_digest` is taken from the contract, not the request, to prevent a malicious VM from substituting a different digest.

#### 4.3 Image Digest Match

```
IF request.image_digest != contract.workload.image_digest
  → REJECT (reason: image_digest_match)
ENDIF
```

- Note: the `image_digest` may arrive in the request body (a separate field), or be inferred from the deployment orchestrator metadata. The exact mechanism depends on the deployment platform's attestation integration.

#### 4.4 TCB Floor Check

```
IF attestation.tcb_version < contract.environment.min_tcb_version
  → REJECT (reason: tcb_floor)
ENDIF
```

- The TCB version is a single integer from the attestation report.
- Higher TCB versions are **accepted** (newer firmware is fine).
- This check prevents deployment on hardware running outdated, vulnerable firmware.

#### 4.5 Debug Disabled Check

```
IF contract.environment.require_no_debug == true 
   AND attestation.policy.debug_allowed == true
  → REJECT (reason: debug_disabled)
ENDIF
```

- If the workload owner has not set `require_no_debug`, an audited VM with debug enabled is acceptable (useful for staging environments).

#### 4.6 SMT State Check

```
IF contract.environment.require_no_smt == true 
   AND attestation.policy.smt_enabled == true
  → REJECT (reason: smt_check)
ENDIF
```

- SMT (simultaneous multithreading, aka Hyper-Threading) can be a side-channel vector. Some workloads may require it disabled.

#### 4.7 Cloud Platform Check

```
cloud_platform = extract from attestation report or VM metadata server (platform-specific)

IF cloud_platform NOT IN contract.environment.allowed_clouds
  → REJECT (reason: cloud_platform)
ENDIF

IF cloud_region NOT IN contract.environment.allowed_regions
  → REJECT (reason: cloud_region)
ENDIF
```

- The mechanism for extracting cloud platform information from the attestation report is platform-specific and may use the SNP Report's `HOST_DATA` field or a platform-provided metadata endpoint accessible only from within the VM.

#### 4.8 Required Checks Completeness

```
audited_checks = set of all checks that were performed and passed

IF contract.krs.required_checks NOT SUBSET OF audited_checks
  → REJECT (reason: incomplete_checks)
ENDIF
```

- This allows the workload owner to mandate specific checks that must be performed. If the KRS skips a required check (e.g., due to a configuration error), the verification fails.

---

### 5. Key Release (Only If ALL Checks Pass)

Once all attestation and policy checks pass, the KRS proceeds to the key release phase. The KRS wraps the CEK so that only the requesting VM can unwrap it.

#### 5.1 Generate KRS Ephemeral Key Pair

```
KRS_ephemeral_priv, KRS_ephemeral_pub = X25519_KEYGEN()
```

- A fresh X25519 key pair is generated for **every** key release.
- This ensures forward secrecy: if a VM's private key is later compromised, it cannot decrypt past CEK deliveries because the KRS ephemeral keys are discarded after each operation.

#### 5.2 ECDH Shared Secret

```
shared_secret = X25519(KRS_ephemeral_priv, VM_ephemeral_pub)
```

- `VM_ephemeral_pub` is taken from the verified request.
- The shared secret is 32 bytes.

#### 5.3 Derive Wrapping Key

```
wrapping_key = HKDF-SHA512(
    IKM = shared_secret,
    salt = "",
    info = "hpvs-krs-wrap/v1",
    L = 32   # AES-256 key length
)
```

- Uses HKDF as specified in RFC 5869.
- Salt is empty (zero-length).
- Info string binds the key derivation to this protocol version, preventing cross-protocol key reuse.

#### 5.4 Wrap CEK

```
wrapped_cek_nonce = RANDOM(12)  # 96 bits for GCM

wrapped_cek = AES-256-GCM(
    key = wrapping_key,
    nonce = wrapped_cek_nonce,
    plaintext = CEK,
    aad = contract_id  # or SHA-256(contract_id) if needed for byte-length
)
```

- `CEK` is the Customer Encryption Key fetched from the HSM/KMS.
- The CEK is a 256-bit key used to decrypt the confidential filesystem.
- AES-256-GCM provides authenticated encryption — the VM can detect tampering.

#### 5.5 Construct Response

```json
{
  "verified": true,
  "krs_ephemeral_pub": "base64-encoded X25519 public key",
  "wrapped_cek_nonce": "base64-encoded 12-byte nonce",
  "wrapped_cek": "base64-encoded ciphertext (includes GCM auth tag)",
  "krs_signature": "base64-encoded Ed25519 signature over all of the above"
}
```

#### 5.6 Sign Response

```
response_to_sign = canonical_json({
    "verified": true,
    "krs_ephemeral_pub": "...",
    "wrapped_cek_nonce": "...",
    "wrapped_cek": "..."
})

krs_signature = Ed25519_SIGN(KRS_private_key, SHA-512(response_to_sign))
```

- The VM must verify this signature using the KRS public key from the deployment contract before trusting the `wrapped_cek`.
- If the signature is invalid, the VM must discard the response and retry (up to 3 attempts, then alert).

#### 5.7 VM-Side Unwrapping

On the VM side, after receiving and verifying the KRS response:

```
shared_secret = X25519(VM_ephemeral_priv, krs_ephemeral_pub)
wrapping_key = HKDF-SHA512(shared_secret, "", "hpvs-krs-wrap/v1", 32)

CEK = AES-256-GCM_DECRYPT(
    key = wrapping_key,
    nonce = wrapped_cek_nonce,
    ciphertext = wrapped_cek,
    aad = contract_id
)
```

The VM now has the plaintext CEK and can decrypt the confidential workload.

---

### 6. Error Handling

#### 6.1 Universal Error Response

**Every attestation or policy failure returns exactly:**

```
HTTP 403 Forbidden
Content-Type: application/json

{
  "verified": false,
  "reason": "attestation rejected"
}
```

- The `reason` field is **always** `"attestation rejected"`, regardless of the actual failure.
- The response body is **identical** for all failure modes.
- The response time must be **constant** (the KRS should use a fixed-time delay that pads all failures to match the duration of a successful verification).
- These measures prevent an attacker from fingerprinting the failure reason through error messages or timing.

#### 6.2 Internal Failure Logging

Internally, the KRS **does** record the exact failure reason:

```
{
  "event": "verification_failed",
  "reason": "tcb_floor",
  "detail": "TCB version 16 < minimum 17",
  "contract_id": "...",
  "timestamp": "...",
  "client_ip": "...",
  "request_hash": "sha256:..."
}
```

This internal log is **never** exposed to the client. It is written to the KRS's structured logging output and shipped to the SIEM/audit system.

#### 6.3 Backoff on Consecutive Failures

If the same client (identified by client certificate fingerprint or source IP) has consecutive failures:

| Consecutive Failures | Backoff |
|---|---|
| 1–5 | No delay |
| 6–10 | 5-second delay before processing |
| 11–20 | 30-second delay |
| 21–50 | 300-second delay |
| 51+ | 3600-second delay (1 hour), and the client IP is flagged for operator review |

Backoff counters reset to zero after a single successful verification from the same client.

---

### 7. Audit Record

#### 7.1 Record Schema

Every verification attempt — successful or not — generates an audit record:

```json
{
  "record_id": "uuid",
  "record_sequence": 0,
  "contract_id": "uuid",
  "timestamp": "2026-06-18T14:30:00Z",
  "vm_measurement": "hex-encoded 48 bytes",
  "vm_tee_type": "sev-snp",
  "vm_chip_id": "hex...",
  "vm_tcb_version": 17,
  "vm_policy_flags": "0x00",
  "client_ip": "10.0.1.5",
  "client_cert_fingerprint": "sha256:...",
  "request_hash": "sha256:...",
  "checks_passed": [
    "amd_vcek_chain",
    "nonce_freshness",
    "report_data_binding",
    "measurement_allowlist",
    "tcb_floor",
    "debug_disabled",
    "image_digest_match"
  ],
  "checks_failed": [],
  "key_released": true,
  "session_duration_s": 1.23,
  "operator_identity": "gcp-sa:deployer@my-project.iam.gserviceaccount.com"
}
```

#### 7.2 Failed Verification Record

When verification fails, the record includes the checks that failed (but this detail is only in the audit log, never returned to the client):

```json
{
  "record_id": "uuid",
  "record_sequence": 1,
  "contract_id": "uuid",
  "timestamp": "2026-06-18T14:31:00Z",
  "vm_measurement": "hex...",
  "vm_tee_type": "sev-snp",
  "vm_chip_id": "unknown",
  "vm_tcb_version": 16,
  "vm_policy_flags": "0x00",
  "checks_passed": [
    "amd_vcek_chain",
    "nonce_freshness",
    "report_data_binding"
  ],
  "checks_failed": [
    {
      "check": "tcb_floor",
      "detail": "TCB version 16 < minimum 17"
    }
  ],
  "key_released": false,
  "session_duration_s": 0.89,
  "operator_identity": null
}
```

#### 7.3 Audit Record Signing

- Each audit record is signed with the KRS Ed25519 private key.
- The signature covers the canonical JSON serialisation of the record (excluding the signature field itself).
- The signature is prepended to the record before shipping:

```json
{
  "audit_record": { ... },
  "krs_signature": "base64...",
  "krs_key_id": "uuid-of-krs-signing-key"
}
```

#### 7.4 Audit Record Shipping

- Audit records are shipped **synchronously** to the auditor's `metadata.audit_log_endpoint` defined in the deployment contract.
- If the auditor endpoint is unreachable, the KRS buffers records in a local write-ahead log and retries with exponential backoff.
- The KRS may still release keys if the audit endpoint is down (operational continuity), but it must log a warning and retry shipping aggressively.
- The maximum buffer size is 1 GB or 100,000 records, whichever is reached first. If the buffer fills, the KRS enters **degraded mode** and refuses all new verifications until audit records drain.

#### 7.5 Sequence Number

- `record_sequence` is a monotonically increasing integer per KRS instance.
- The auditor can detect gaps in the sequence to identify deleted or tampered logs.
- Sequence numbers restart at 0 on KRS restart (acceptable since records also have UUIDs and timestamps; the auditor correlates by UUID across restarts).

---

### 8. Cryptographic Algorithms

| Purpose | Algorithm | Key Size | Notes |
|---|---|---|---|
| AMD attestation root of trust | ECDSA P-384 | 384-bit curve | AMD-specified |
| KRS response signature | Ed25519 | 256-bit key | RFC 8032 |
| VM↔KRS key agreement | X25519 | 256-bit key | RFC 7748 |
| Key derivation | HKDF-SHA512 | — | RFC 5869 |
| CEK wrapping | AES-256-GCM | 256-bit key | NIST SP 800-38D |
| Contract signing | Ed25519 | 256-bit key | All three personas |
| Image/content hashing | SHA-256 / SHA-512 | — | Context-dependent |
| Measurement (SNP) | SHA-384 | — | AMD-specified |

---

### 9. Operational Parameters

| Parameter | Value | Rationale |
|---|---|---|
| Nonce TTL in replay cache | 3600 seconds | Longer than max allowable timestamp skew × 2 |
| Max timestamp skew | 300 seconds | Allows NTP drift + VM boot time |
| Rate limit per VM per minute | 10 | Prevents brute-force attestation probing |
| Rate limit global per minute | 1000 | Protects KRS from overload |
| CEK size | 256 bits | Standard AES-256 key |
| KRS ephemeral key rotation | Every request | Forward secrecy |
| CRL refresh interval | 3600 seconds | Balances freshness vs. AMD KDS load |
| Max audit buffer size | 1 GB / 100k records | Operational resilience |
| KRS key rotation | Every 90 days | As specified in `DEPLOYMENT_CONTRACT.md` |
| Contract expiry | Configurable, default 90 days | Force regular review |

---

### 10. Failure Mode Reference

| Failure Point | Condition | Internal Reason |
|---|---|---|
| Transport | TLS < 1.3 | `tls_version` |
| Transport | Client cert not from pinned CA | `client_cert_ca` |
| Transport | Client cert expired or revoked | `client_cert_validity` |
| Transport | Channel binding mismatch | `channel_binding` |
| Transport | Rate limit exceeded | `rate_limit` (returns 429, not 403) |
| Request | JSON schema invalid | `request_schema` |
| Request | Contract not found or not active | `contract_state` |
| Request | Contract expired | `contract_expired` |
| Request | Ephemeral pubkey invalid | `ephemeral_pubkey_format` |
| Request | Ephemeral pubkey reused | `ephemeral_pubkey_reuse` |
| Request | Nonce invalid or replayed | `nonce_freshness` |
| Request | Timestamp outside 300s window | `timestamp_skew` |
| Request | Operator token invalid/expired | `operator_token` |
| Attestation | VCEK chain verification failed | `amd_vcek_chain` |
| Attestation | VCEK or ASK/ARK revoked | `amd_cert_revoked` |
| Attestation | Report signature invalid | `report_signature` |
| Policy | Measurement mismatch | `measurement_allowlist` |
| Policy | Report data binding mismatch | `report_data_binding` |
| Policy | Image digest mismatch | `image_digest_match` |
| Policy | TCB version too low | `tcb_floor` |
| Policy | Debug allowed when forbidden | `debug_disabled` |
| Policy | SMT enabled when forbidden | `smt_check` |
| Policy | Cloud/platform not allowed | `cloud_platform` |
| Policy | Required checks incomplete | `incomplete_checks` |

---

## References

- [AMD SEV-SNP ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 7748 — X25519](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8032 — Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)
- [RFC 9266 — TLS-Exporter / Channel Binding](https://datatracker.ietf.org/doc/html/rfc9266)
- [AMD Key Distribution System (KDS)](https://kdsintf.amd.com/)
- `DEPLOYMENT_CONTRACT.md` — Contract schema and signing protocol
- `DEPLOYMENT_RUNBOOK.md` — Operational runbook for deployment
