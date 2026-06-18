# ADVANCED SECURE ENVIRONMENT

> **BMSR-cyber** — Production-grade confidential computing for autonomous trading infrastructure.

Replicates IBM Hyper Protect Virtual Servers (HPVS v2.1) security guarantees on
accessible cloud hardware — GCP N2D (AMD SEV-ES), OCI Ampere A1 (free tier),
and eventually Intel TDX — with **Nitrokey FIDO2 as the human root-of-trust**.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              CLOUD VM (GCP N2D / OCI Ampere)            │
│  ┌───────────────────────────────────────────────────┐  │
│  │            AMD SEV-ES ENCRYPTED GUEST               │  │
│  │  ┌─────────────────────────────────────────────┐   │  │
│  │  │  TRADING BOT (9-strategy portfolio)          │   │  │
│  │  │  ┌───────┐ ┌──────────┐ ┌───────────────┐   │   │  │
│  │  │  │Signal │ │ Goldman  │ │ Circuit       │   │   │  │
│  │  │  │Engine │→│Execution │→│ Breakers      │   │   │  │
│  │  │  └───────┘ └──────────┘ └───────────────┘   │   │  │
│  │  │  Memory encrypted at CPU boundary             │   │  │
│  │  └─────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────┘  │
│                          ▲                               │
│                   SEV attestation                        │
│                          │                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Keylime Continuous Attestation (PCR polling)      │  │
│  │  • Verifies platform integrity every 5 min        │  │
│  │  • Zeroizes secrets on attestation failure        │  │
│  │  • Reports to remote verifier                     │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
                    Nitrokey FIDO2
              (human root-of-trust)
         hmac-secret → master encryption key
         PIN-gated, physical touch required
```

## Security Guarantees (mapped from IBM HPVS)

| HPVS Feature | Our Implementation | Mechanism |
|:---|:---|:---|
| Workload isolation from OS/hypervisor | AMD SEV-ES memory encryption | CPU-bound page tables encrypted, hypervisor cannot read |
| Multi-party encrypted contract | Nitrokey + SEV attestation + Keylime | 3 anchors: human, hardware, continuous |
| Key binding to guest identity | HKDF-SHA512(attestation_hash + fido2_secret) | Keys derivable ONLY inside measured VM |
| Metadata secret injection | SEV LAUNCH_SECRET or Keylime key broker | Config released only after attestation |
| LUKS data-at-rest protection | cryptsetup LUKS2 with TEE-derived passphrase | Disk data encrypted at rest |
| Continuous attestation | Keylime 5-min PCR polling | TPM PCR state monitored |
| Failsafe zeroization | ctypes mlock + madvise(MADV_DONTDUMP) | Secrets in non-swappable, non-core-dump memory |
| Process obfuscation | prctl(PR_SET_NAME) to generic name | In-memory process name replaced |

## Source Documents

The `docs/` directory contains the IBM patent and NIST reference materials
that informed this architecture:

| Document | Content |
|:---|:---|
| `HyperProtect-solution-brief.pdf` | IBM HPVS v2.1 architecture, SEL, multi-party contract |
| `BINDING SECURE KEYS...` (US 11,500,988 B2) | HSM key binding to guest identity via Secure Interface Control |
| `Confidential data provided to a secure guest via metadata.pdf` | Metadata-based secret injection without cloud visibility |
| `Confidential Computing across Edge-to-Cloud...` | TEE survey: SGX, SEV, SEV-ES, SEV-SNP, TDX, Arm CCA |
| `Confidential Computing for OpenPOWER.pdf` | POWER9/POWER10 secure execution architecture |
| `NIST IR 8320_Hardware-Enabled Security.pdf` | NIST framework: CoT, attestation, key broker pattern |
| `Provisioning secure encrypted virtual machines...` | VM provisioning with encrypted boot chain |
| `Secure execution guest owner controls...` | Guest owner policy enforcement on secure interface |
| `Service processor and system with secure booting...` | Secure boot with SP integrity monitoring |

## Implementation

`src/cloud_protection.py` — 1,189 lines, 9-class implementation:

| Class | Role |
|:---|:---|
| `ProtectedMemory` | mlock + MADV_DONTDUMP ctypes buffer |
| `SecureZeroizer` | Signal handler → zeroize → kill process |
| `ProcessObfuscator` | prctl(PR_SET_NAME) |
| `TEAttestationVerifier` | SEV/TDX/TPM detection + measurement |
| `MetadataDecryptor` | AES-256-GCM with HKDF from attestation |
| `ContinuousAttestationMonitor` | Threaded 5-min PCR polling |
| `LuksProtection` | LUKS2 with TEE-derived passphrase |
| `NitrokeyRootOfTrust` | fido2-token -L, fido2-assert, hmac-secret |
| `CloudProtectionLayer` | 7-step bootstrap orchestrator |

`src/CLOUD_PROTECTION.md` — Architecture diagram, GCP N2D SEV setup, OCI
Ampere limitations, Nitrokey enrollment, build-time sealing, attestation
workflow, disaster recovery.

## Free-Tier Deployment Target

| Cloud | Instance | TEE | Cost | Status |
|:---|:---|:---|:---|:---|
| **GCP N2D** | AMD EPYC Milan (n2d-standard-2) | SEV-ES | ~$50/mo | **Recommended** |
| OCI Ampere | A1.Flex (4 OCPU, 24GB) | No guest TEE | Free tier | Fallback (no SEV) |
| AWS | t3.medium | Nitro Enclaves | ~$30/mo | Nitro Enclaves require separate VM |
| IBM Cloud | LinuxONE Community Cloud | Full SEL | Free tier (60 days) | Native HPVS, time-limited |

## Quick Start

```bash
# 1. Verify TEE support
python cloud_protection.py --check-only

# 2. Touch Nitrokey to bootstrap
python cloud_protection.py --bootstrap --nitrokey

# 3. Decrypt trading bot config
python cloud_protection.py --unseal

# 4. Start with continuous attestation
python cloud_protection.py --start \
  --continuous-attestation \
  --entrypoint combined_runner.py
```

## Requirements

- Python 3.11+
- Nitrokey FIDO2 (or compatible FIDO2 YubiKey)
- AMD EPYC with SEV-ES enabled (GCP N2D or bare metal)
- `openssl`, `cryptsetup`, `fido2-tools` (system packages)
- Keylime (for continuous attestation in production)

## License

See [LICENSE](LICENSE)
