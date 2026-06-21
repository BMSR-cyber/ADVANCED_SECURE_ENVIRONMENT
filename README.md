# ADVANCED SECURE ENVIRONMENT

> **BMSR-cyber** — Confidential computing reference architecture for autonomous trading.
>
> **Status:** v3.5 — trust-critical path implemented (real ioctl, snpguest
> chain/policy/TCB verification, mTLS+pinned KRS, `--production` gating, Rust
> unwrap). **Pending validation on real SEV-SNP hardware** before production use.
> See [Remaining Hardening](#remaining-hardening).

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
| Platform | TEE / attestation | Works with this code? |
|:---|:---|:---|
| **GCP N2D (Milan) / C3D (Genoa)** | SEV-SNP guest report | ✅ **Primary target** |
| **Azure DCas v5 / ECas v5** | SEV-SNP guest report | ✅ Yes (minor wiring) |
| **Bare-metal AMD EPYC 7003+** | SEV-SNP guest report | ✅ Yes |
| **AWS m6a/c6a** | **Nitro NSM** (AWS-signed, COSE/CBOR) | ⚠️ **Not as-is** — needs a Nitro adapter |
| IBM LinuxONE | SEL / HPVS native | ✅ (expensive mainframe) |
| OCI Ampere / standard VMs | none | ❌ Incompatible |

> **AWS Nitro Enclaves ≠ AMD SEV-SNP.** This repo verifies an AMD SEV-SNP *guest
> report* (`/dev/sev-guest` → `snpguest` → VCEK→ASK→ARK), which is native on GCP
> N2D and Azure DCas v5. AWS uses Nitro NSM attestation (a different, AWS-signed
> document) that this repo does not yet verify — so AWS needs a separate adapter.

GCP requires explicit SEV-SNP:
```bash
gcloud compute instances create ... \
  --confidential-compute-type=SEV_SNP \
  --min-cpu-platform="AMD Milan"
```

**Cost & platform selection:** cheapest platform that matches this code is
**GCP `n2d-standard-2`** (~$45–52/mo on-demand, ballpark — verify on the GCP
calculator). Spot/preemptible is testing-only (interruption destroys the enclave →
forced re-attestation + Nitrokey touch). Full breakdown: [`docs/DEPLOYMENT_COST.md`](docs/DEPLOYMENT_COST.md).

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

Implemented in this pass (see also `docs/ASE_REVIEW.md` for the review that drove it):

- [x] **Real `SNP_GET_REPORT` ioctl** — `snp_verify.fetch_report_ioctl()` uses the
  kernel uapi (`_IOWR('S',0,32)` on `/dev/sev-guest`). *Run-verify on N2D pending.*
- [x] **AMD VCEK → ASK → ARK chain verification** — delegated to `snpguest`
  (virtee) in `snp_verify.SnpVerifier.verify_signature_chain()`, NOT hand-rolled.
- [x] **report_data, policy (no-debug), TCB floor, measurement allowlist** verified
  in `SnpVerifier.verify()`. Also fixed a real bug: MEASUREMENT offset is **0x090**,
  not 0x0A0 (the old value never matched a real report).
- [x] **KRS mTLS + pinning** — `krs_client.KrsClient`: TLS 1.3 floor, client cert,
  pinned CA + pinned server-cert fingerprint, and a pinned Ed25519 signature over
  the KRS response (defeats TLS-terminating substitution). Replaces urllib.
- [x] **Local attestation path refuses production** — `--production` requires KRS;
  enforces lockdown, tmpfs, snpguest verification, and the Rust unwrap. Verified:
  prod-without-pins exits 2; dev/no-TEE fails closed (exit 1).
- [x] **Key unwrap moved to Rust** — `key_unwrap/` cdylib (HKDF-SHA512 + AES-256-GCM,
  key/subkey in `Zeroizing`); `rust_unwrap.py` ctypes binding; required in prod.
  Interop with the Python seal format tested (AAD + tamper rejected).

Still pending (need real hardware / ops):
- [ ] End-to-end run-verify on GCP N2D SEV-SNP (ioctl + snpguest against a live PSP)
- [ ] Reference **KRS server** implementing `KRS_POLICY.md` (client side done)
- [ ] RFC 9266 tls-exporter channel binding (needs Python 3.13+; cert-fpr binding used now)
- [ ] Plaintext strategy on tmpfs/LUKS confirmed on the deployed image
- [ ] Fail-closed suite on hardware: replayed quote, wrong TCB, bad image digest, bad KRS identity

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
