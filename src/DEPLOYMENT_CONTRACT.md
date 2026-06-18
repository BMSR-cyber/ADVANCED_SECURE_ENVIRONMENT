# Deployment Contract v1

## Overview

The deployment contract is a **signed JSON artifact** that formally binds all deployment personas and constraints together, closing the gap between the current ad-hoc KRS parameter passing and a cryptographically enforceable, multi-party-authorised deployment model.

No single persona can deploy or modify unilaterally. Every deployment requires consensus among:

| Persona | Role | Signing Scope |
|---|---|---|
| **Workload owner** | Builds, measures, and signs the workload identity | `workload` block |
| **Environment owner** | Controls where the workload may run | `environment` block |
| **Auditor** | Reviews and approves the complete contract | `signatures.auditor` |
| **KRS** | Loads contracts, enforces policy, releases keys | Trust anchor (verifies all signatures) |
| **Operator** | Triggers deployment (must match contract identity) | Identified via operator key but does not sign the contract directly — authorisation is implicit via KRS policy |

### Design Principles

- **Fail-closed**: any missing or invalid signature → key release refused.
- **Immutable identity**: workload identity is pinned to a digest and measurement, not a tag or label.
- **Time-bound**: contracts expire and must be rotated.
- **Replay-safe**: nonce freshness is contract-scoped, preventing re-use across deployments.
- **Observable**: every verification attempt is logged and shipped to the auditor.

---

## Schema

```json
{
  "contract_version": "1.0",
  "contract_id": "uuid",

  "workload": {
    "image_digest": "sha256:...",
    "expected_sev_measurement": "hex...",
    "expected_tdx_mrconfigid": "hex...",
    "entrypoint": "combined_runner.py",
    "sbom_hash": "sha256:..."
  },

  "environment": {
    "allowed_clouds": ["gcp"],
    "allowed_regions": ["us-central1"],
    "allowed_projects": ["my-project-id"],
    "required_tee": "sev-snp",
    "min_tcb_version": 17,
    "require_no_debug": true,
    "require_no_smt": false
  },

  "krs": {
    "endpoint": "https://krs.internal:8443/verify",
    "public_key": "base64...",
    "required_checks": [
      "amd_vcek_chain",
      "nonce_freshness",
      "report_data_binding",
      "measurement_allowlist",
      "tcb_floor",
      "debug_disabled",
      "image_digest_match"
    ]
  },

  "signatures": {
    "workload_owner": {
      "key_id": "eba05ac2-...",
      "signature": "base64..."
    },
    "environment_owner": {
      "key_id": "f1c884d3-...",
      "signature": "base64..."
    },
    "auditor": {
      "key_id": "a7e3b221-...",
      "signature": "base64..."
    }
  },

  "metadata": {
    "created": "2026-06-18T00:00:00Z",
    "expires": "2026-08-17T00:00:00Z",
    "rotation_policy": "30d",
    "audit_log_endpoint": "https://logs.internal:443"
  }
}
```

### Field Descriptions

#### `workload`

| Field | Type | Description |
|---|---|---|
| `image_digest` | `sha256:hex` | Content-addressable image identifier. Must match the digest visible to the container runtime at launch. |
| `expected_sev_measurement` | `hex` | 48-byte SNP launch measurement (offset 0x0A0 in attestation report). Computed offline by the workload owner using `sev-guest-get-report` or SEV-SNP measurement tooling. |
| `expected_tdx_mrconfigid` | `hex` | Intel TDX equivalent; only present for TDX deployments, otherwise null or omitted. |
| `entrypoint` | `string` | The first process executed inside the VM. Anchors the boot chain. |
| `sbom_hash` | `sha256:hex` | Hash of the Software Bill of Materials for the image. Enables supply-chain auditing. |

#### `environment`

| Field | Type | Description |
|---|---|---|
| `allowed_clouds` | `[string]` | Cloud provider identifiers (e.g., `gcp`, `aws`). The attestation report's platform fields must match at least one entry. |
| `allowed_regions` | `[string]` | Permitted deployment regions. Empty list means any region is acceptable (auditor must explicitly approve). |
| `allowed_projects` | `[string]` | Cloud project / account IDs. |
| `required_tee` | `enum` | `sev-snp`, `tdx`, or `none`. Must match the attested TEE type. |
| `min_tcb_version` | `integer` | Minimum acceptable TCB firmware version from the SNP attestation report. Higher is allowed; lower is rejected. |
| `require_no_debug` | `bool` | If `true`, the DEBUG flag in the attestation policy must be clear. |
| `require_no_smt` | `bool` | If `true`, simultaneous multithreading must be disabled (Hyper-Threading off). |

#### `krs`

| Field | Type | Description |
|---|---|---|
| `endpoint` | `url` | KRS API endpoint that services this contract. Contract-scoped; different workloads may use different KRS instances. |
| `public_key` | `base64` | KRS Ed25519 verifying key. Used to validate the KRS's signed response during CEK unwrapping. |
| `required_checks` | `[string]` | Ordered list of verification checks the KRS must execute. Allows workload owner to require check types the auditor cannot waive. |

#### `signatures`

Each signature is a detached Ed25519 signature over the **canonical JSON serialisation** of the contract without the `signatures` block (see Signing Protocol). Key IDs are stable UUIDs that reference long-lived keys stored in a hardware-backed key management system.

#### `metadata`

| Field | Type | Description |
|---|---|---|
| `created` | `ISO8601` | Contract creation timestamp. |
| `expires` | `ISO8601` | Contract expiry. After this time the KRS must reject all verifications against this contract. |
| `rotation_policy` | `duration` | Maximum interval between rotations. If a contract is not rotated within this window, KRS begins emitting pre-expiry warnings. |
| `audit_log_endpoint` | `url` | Where the KRS ships signed audit records. |

---

## Signing Protocol

### Canonical Form

Before signing, the contract is serialised to **canonical JSON**:
- All object keys are **sorted lexicographically**.
- No trailing commas.
- No insignificant whitespace.
- The `signatures` block is **removed entirely** before hashing.

The canonical form is then hashed: `SHA-512(raw_canonical_json)`.

### Step-by-Step Process

```
1. Workload Owner
   └── Builds image, computes SEV measurement offline
   └── Assembles workload block → canonical form
   └── Signs with workload_owner Ed25519 key
   └── Records signature in signatures.workload_owner

2. Environment Owner
   └── Reviews workload block
   └── Assembles environment block → canonical form
   └── Signs with environment_owner Ed25519 key
   └── Records signature in signatures.environment_owner

3. Auditor
   └── Reviews complete contract (both workload + environment)
   └── Verifies workload_owner and environment_owner signatures
   └── Signs complete canonical form with auditor Ed25519 key
   └── Records signature in signatures.auditor

4. KRS
   └── Loads contract
   └── Strips signatures block → recomputes canonical form
   └── Verifies all 3 signatures against canonical form
   └── If any signature is invalid or any signing key is revoked → REFUSE
   └── If contract has expired → REFUSE
   └── Otherwise → marks contract as ACTIVE

5. Rotation
   └── Same signing process as above
   └── New contract gets new contract_id
   └── Old contract remains valid until expires (unless explicitly revoked)
   └── Rotation must complete before expiration or deployments are blocked
```

### Signature Verification by KRS

For each persona:
1. Look up `key_id` in the trusted key registry (a signed, versioned key registry maintained by the auditor).
2. Verify that the key has not been revoked.
3. Compute `Ed25519.verify(canonical_hash, signature, public_key)`.
4. If any verification fails → log failure to audit log → return generic rejection.

### Operator Identity

The `operator` persona (the entity triggering deployment inside the environment) is **not a signer of the contract**. Instead:
- The operator's identity is attested via the deployment toolchain (e.g., GCP IAM, AWS IAM, Kubernetes service account).
- The KRS validates the operator's identity via a **transient authorisation token** included in the attestation request.
- The token must be signed by a key that the environment owner has pre-registered as an allowed operator.
- This decouples deployment authorisation from contract signing, allowing operators to change without re-signing the contract.

---

## Verification Flow

```
┌────────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────┐
│ SEV-SNP VM │     │   KRS Node   │     │ HSM/KMS   │     │  Auditor │
│ (workload) │     │              │     │           │     │          │
└─────┬──────┘     └──────┬───────┘     └─────┬─────┘     └────┬─────┘
      │                   │                   │                │
      │ 1. Attest+request │                   │                │
      │──────────────────>│                   │                │
      │                   │                   │                │
      │                   │ 2. Load contract  │                │
      │                   │ 3. Verify sigs    │                │
      │                   │                   │                │
      │                   │ 4. Verify report  │                │
      │                   │    against policy │                │
      │                   │                   │                │
      │                   │ 5. Wrap CEK       │                │
      │                   │──────────────────>│                │
      │                   │                   │                │
      │                   │ 6. Return wrapped_cek              │
      │                   │<──────────────────│                │
      │                   │                   │                │
      │ 7. Unwrap CEK     │                   │                │
      │    Decrypt FS     │                   │                │
      │    Start workload │                   │                │
      │                   │                   │                │
      │                   │ 8. Log audit      │                │
      │                   │───────────────────────────────────>│
      │                   │                   │                │
      │                   │                   │   9. Auditor   │
      │                   │                   │   verifies     │
      │                   │                   │   deployment   │
      │                   │                   │   record       │
```

### Detailed Step Descriptions

**Step 1** — The SEV-SNP VM (the workload host) boots and obtains an attestation report from the AMD PSP firmware. It constructs a verification request containing:
- `contract_id` — which contract governs this deployment.
- `ephemeral_pubkey` — a fresh X25519 public key generated by the VM (never re-used).
- `nonce` — a fresh random 256-bit value.
- `attestation_report` — the raw SNP attestation report binary (or base64-encoded).
- `vcek_certificate` — the VCEK certificate chain from the AMD KDS.
- `timestamp` — current VM time, used for freshness checks.
- `operator_token` — signed authorisation from the deployment orchestrator.

**Step 2** — KRS receives the request, validates transport security, then loads the contract identified by `contract_id` from its local cache (populated by a contract distribution service that polls a signed contract registry).

**Step 3** — KRS verifies all three contract signatures as described in [Signature Verification](#signature-verification-by-krs). Any failure → reject.

**Step 4** — KRS verifies the attestation report against the contract's environment and workload policies. The full verification checklist is defined in `KRS_POLICY.md`.

**Step 5** — All checks pass. KRS accesses the CEK from its backing HSM/KMS (the CEK is stored encrypted-at-rest, only the KRS can unwrap it). KRS wraps the CEK to the VM's ephemeral public key.

**Step 6** — KRS returns the wrapped CEK, signed with its Ed25519 key so the VM can authenticate the response.

**Step 7** — The VM uses its ephemeral private key to unwrap the CEK, then uses the CEK to decrypt the encrypted filesystem/image layers, and finally launches the actual workload.

**Step 8** — KRS constructs a signed audit record and ships it to the auditor's log endpoint.

**Step 9** — Auditor's systems ingest the audit record, verify the KRS signature, and if configured, alert on any anomaly (unexpected measurement, TCB drift, etc.).

---

## Auditor Access

### Capabilities

| Action | Mechanism |
|---|---|
| **Verify past deployments** | Query KRS audit log endpoint; every verification attempt produces a signed record |
| **Inspect contract state** | Read from the contract registry; all contracts are public within the trust domain |
| **Revoke a contract** | The auditor can submit a signed revocation notice to the KRS. Once revoked, no further CEK releases are permitted against that contract ID |
| **Require re-signing** | If a key is compromised or a vulnerability is discovered in the workload, the auditor can revoke their signature, forcing the workload owner to patch and re-sign |
| **Receive real-time alerts** | Subscribe to the audit log stream; any rejected attestation triggers an alert |

### Audit Log Record Format

See `KRS_POLICY.md` Section 7 for the full audit record schema. Each record is:
- Signed with the KRS Ed25519 key.
- Includes a sequential record ID for gap detection.
- Contains all checks performed and their pass/fail status (but the VM only receives a generic response).

### Revocation Protocol

```
1. Auditor constructs revocation notice:
   {
     "action": "revoke_contract",
     "contract_id": "uuid",
     "reason": "vulnerability CVE-2026-...",
     "timestamp": "iso8601"
   }

2. Auditor signs with their Ed25519 key

3. Auditor submits to KRS revocation endpoint

4. KRS verifies auditor signature
   └── Valid → marks contract as REVOKED
   └── Invalid → logs attempt, ignores

5. KRS publishes revocation event to audit log

6. Any in-flight verifications against revoked contract → rejected
```

---

## Contract Lifecycle

```
CREATED ──> ACTIVE ──> EXPIRED
              │              │
              └──> REVOKED ──┘
```

| State | Description | KRS Behaviour |
|---|---|---|
| `CREATED` | Contract exists in registry but has not been fully signed | KRS refuses to load it |
| `ACTIVE` | All 3 signatures valid, not expired | KRS processes verification requests |
| `EXPIRED` | `metadata.expires` has passed | KRS rejects all requests against this contract |
| `REVOKED` | Auditor has explicitly revoked | KRS rejects all requests against this contract |

### Expiry Window Warning

Starting 7 days before expiry, the KRS includes a warning header in every CEK response: `X-Contract-Expiry-Warning: 7d`. This allows the workload VM's monitoring to alert operators that rotation is required.

---

## Security Considerations

### Key Compromise Response

1. **Workload owner key compromised**: Auditor revokes their signature → no further deployments of that workload → workload owner regenerates key, rebuilds image, resigns new contract.
2. **Environment owner key compromised**: Auditor revokes → all contracts signed by that environment owner become REVOKED. Requires new environment owner keys and full contract re-signing for all affected workloads.
3. **Auditor key compromised**: An out-of-band recovery process rotates the auditor key in the trusted key registry. All existing contracts must be re-signed with the new auditor key.
4. **KRS key compromised**: The entire KRS instance must be reprovisioned. All contracts referencing the old KRS key must be updated.

### Multi-Region Deployments

A single contract should support deployment to multiple regions. The `environment.allowed_regions` list is the mechanism. If different regions require different SEV measurements (due to different AMD firmware versions), separate contracts should be used — one per firmware baseline.

### Contract Storage

Contracts are stored in an **append-only, tamper-evident registry** (e.g., Trillian / Rekor / a Git repository with signed commits). The KRS polls this registry and caches contracts locally. The registry itself is replicated across all cloud regions where KRS instances run.

---

## References

- [AMD SEV-SNP ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf) — Attestation report structure.
- `KRS_POLICY.md` — Complete verification policy specification for the KRS.
- `DEPLOYMENT_RUNBOOK.md` — Operational procedures for contract creation and rotation.
