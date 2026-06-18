# ADVANCED SECURE ENVIRONMENT

> **BMSR-cyber** — Confidential computing reference architecture for autonomous trading.
>
> **Status:** v3 staging candidate. Not production-hardened. See [Remaining Hardening](#remaining-hardening).

Replicates IBM Hyper Protect Virtual Servers (HPVS v2.1) security guarantees on
accessible cloud hardware using AMD SEV-SNP + external key-release service +
Nitrokey FIDO2 as human root-of-trust.

## Architecture

```
SIGNED CONTAINER IMAGE → SEV-SNP CONFIDENTIAL VM → ATTESTATION REPORT
     → EXTERNAL KEY-RELEASE SERVICE (TEE + Nitrokey) → WRAPPED CEK
     → DECRYPT STRATEGY INSIDE TEE → EMIT SIGNED ORDER INTENTS
     → cTrader/MT5/Freqtrade DUMB EXECUTOR
```

## Security Guarantees (mapped from IBM HPVS)

| HPVS Feature | Our Implementation | Mechanism |
|:---|:---|:---|
| Workload isolation from OS/hypervisor | AMD SEV-SNP | CPU-bound page tables encrypted |
| Multi-party encrypted contract | TEE attestation + KRS + Nitrokey | 3 anchors: hardware, service, human |
| Key binding to guest identity | ECDH(X25519) ephemeral key pair | CEK wrapped to attested VM only |
| Metadata secret injection | KRS wraps CEK after AMD VCEK chain verification | Config released only after attestation |
| Continuous attestation | 5-min PCR polling | Keylime-style monitor, zeroize on failure |
| Failsafe zeroization | mlock + MADV_DONTDUMP + memoryview | Secrets in non-swappable memory |

## Deployment Targets

| Platform | TEE | Nitrokey | Verdict |
|:---|:---|:---|:---|
| **GCP N2D (EPYC Milan)** | SEV-SNP | Via KRS (external service) | Production target |
| **GCP C3D (EPYC Genoa)** | SEV-SNP | Via KRS | Production target |
| **AWS m6a/c6a** | SEV-SNP | Via KRS (Nitro Enclave) | Production target |
| **IBM LinuxONE** | SEL (native HPVS) | Crypto Express HSM | Native HPVS |
| OCI Ampere A1 | **None** | N/A | **Incompatible** |
| Standard VMs | **None** | N/A | **Incompatible** |

GCP requires explicit SEV-SNP:
```bash
gcloud compute instances create ... \
  --confidential-compute-type=SEV_SNP \
  --min-cpu-platform="AMD Milan"
```

## Implementation

`src/cloud_protection.py` — v3 prototype:

| Class | Role |
|:---|:---|
| `ProtectedMemory` | mlock + MADV_DONTDUMP, memoryview reads (avoids key serialization) |
| `SecureZeroizer` | Signal handler → zeroize all memory → exit |
| `TEEAttestation` | SEV-SNP/TDX detection, ioctl SNP_GET_REPORT, measurement verification |
| `NitrokeyRoT` | FIDO2 hmac-secret via `fido2-assert -G` with credential + salt |
| `ContinuousAttestationMonitor` | Threaded 5-min PCR polling, zeroize on failure |
| `CloudProtection` | 8-step bootstrap orchestrator (KRS path + dev local path) |

## Remaining Hardening

The architecture is sound but the implementation requires these before production:

- [ ] Real SNP_GET_REPORT ioctl verified on GCP N2D SEV-SNP
- [ ] KRS verifies AMD VCEK/VLEK → ASK → ARK certificate chain
- [ ] KRS verifies nonce freshness, report_data, policy, TCB, and measurement allowlist
- [ ] KRS uses mTLS or signed HPKE response with pinned identity (currently urllib)
- [ ] Local attestation path refuses production mode (gated behind `--production` flag)
- [ ] Plaintext strategy written to tmpfs/LUKS, not persistent VM disk
- [ ] Tampered ciphertext, replayed quote, wrong measurement, wrong TCB all fail closed
- [ ] Key unwrap path eventually moved to Rust/Go/C for zero-copy guarantee

## Side-Channel Hardening (priority order)

The next threat layer is observable behavior → inferred strategy/keys:

1. **[x] Signed minimal order intents** — `src/signed_order_intent.py`. Only execution fields, coarse size bands, batch emission windows, Ed25519 signatures. Executor is a dumb pipe.
2. **[x] Hardened attestation binding** — `SNP_GET_EXT_REPORT` + cert blob. `report_data` binds `hash(pubkey||nonce||policy||image_digest)`.
3. **[x] tmpfs mandatory gate** — Production mode raises `AttestationError` if output_dir not on tmpfs/LUKS.
4. **[x] `mlockall(MCL_CURRENT|MCL_FUTURE)`** — All pages locked at bootstrap.
5. **[ ] KRS mTLS/HPKE with pinned identity** — Documented design, not yet implemented.
6. **[ ] SMT/co-tenancy** — Prefer no-sibling-sharing instances, dedicated KRS host.
7. **[ ] Key unwrap → Rust/Go/C** — Python stays as orchestrator only.
8. **[ ] Fail-closed test suite** — Replayed quote, wrong TCB, bad image digest, tampered ciphertext, bad KRS identity all fail closed.

Full hardening plan: `src/SIDE_CHANNEL_HARDENING.md`

## Source Documents

See `docs/` — IBM HPVS patents, NIST IR 8320, TEE survey, and OpenPOWER secure execution.

## Quick Start (Development)

```bash
python cloud_protection.py --check-only           # Detect TEE + Nitrokey
python cloud_protection.py --bootstrap --verbose   # Dev mode (local verify)
python cloud_protection.py --production --key-service-url https://krs:8443 # Prod
```

## License

See [LICENSE](LICENSE)
