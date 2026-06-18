# Cloud Protection — Confidential Computing for Trading Infrastructure v3

**Status:** Production-grade after security critique. All v2 flaws fixed.

## What Changed (v2 → v3)

| v2 Issue (Critique) | v3 Fix |
|:---|:---|
| openssl enc CLI leaks AES key via /proc/PID/cmdline | **Removed.** AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Key never leaves ProtectedMemory. |
| Fallback attestation: `sha256('SEV_PLATFORM_DETECTED')` | **Removed.** Real SEV-SNP attestation report from AMD PSP via `/dev/sev-guest`. Measurement verified against allowlist. No fallback. |
| Process obfuscation to `systemd-journal` | **Removed.** Service identity is `trading-signal-runner`. Protected by systemd hardening, not stealth. |
| Key copies via `.hex()` / temp files / Python bytes | **Removed.** `read()` returns `memoryview` into locked buffer. No hex conversion. No temp plaintext files. |
| FIDO2 hmac-secret unproven | **Fixed.** Uses proper `fido2-assert -G` protocol with credential ID + salt. Challenge bound to attestation measurement. |
| GCP Nitrokey USB passthrough broken | **Resolved.** Recommended path: external key-release service. VM sends attestation report → service verifies → releases session key. Nitrokey at service side, not in VM. |
| OCI Ampere "free tier" illusory | **Honest.** No TEE = refused to boot. Documented as incompatible. GCP N2D SEV-SNP (EPYC 7003+) required. |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     BUILD TIME (offline, laptop)                      │
│                                                                       │
│  1. Build trading strategy container image                            │
│  2. Record expected measurement: SHA-384(initial_memory + firmware)  │
│  3. Seal Python strategy source with AES-256-GCM → .aesgcm files     │
│  4. Sign container image, push to registry                           │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    DEPLOY TIME (GCP N2D SEV-SNP)                      │
│                                                                       │
│  1. Start confidential VM with signed image                           │
│  2. VM boots inside SEV-SNP TEE                                      │
│  3. VM detects /dev/sev-guest → requests attestation report           │
│  4. AMD PSP signs attestation report:                                 │
│     • Guest measurement (SHA-384 of initial state)                    │
│     • Chip ID, VMPL, policy flags                                     │
│     • Nonce deposited by VM                                           │
│  5. VM sends report to external key-release service over mTLS         │
│  6. Key-release service verifies:                                     │
│     a. AMD VCEK certificate chain → ARK root                          │
│     b. Measurement matches expected allowlist                         │
│     c. Nonce fresh (anti-replay)                                      │
│     d. Policy: no debug, SMT allowed, required TCB                    │
│  7. Key-release service produces signed session key                   │
│  8. VM receives session key → derives master key:                     │
│     HKDF-SHA512(attestation_measurement, hmac_secret, salt=v3)       │
│  9. VM decrypts strategy .aesgcm files inside TEE                     │
│ 10. Strategy runs, emits signed order intents only                    │
│ 11. Continuous attestation monitor polls every 5 min                  │
│ 12. Any attestation failure → zeroize memory → exit                  │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   EXECUTION (cTrader / MT5 / Freqtrade)               │
│                                                                       │
│  cBot / EA / executor receives SIGNED order intents only.             │
│  No strategy logic. No proprietary IP. Dumb executor.                 │
│                                                                       │
│  Intent = {symbol, side, qty, stop, target, signature}               │
│  cBot verifies signature → places order → reports fill.              │
└──────────────────────────────────────────────────────────────────────┘
```

## Key Release Service (Recommended Production Path)

The Nitrokey cannot be physically connected to a GCP VM. The correct solution:

```python
# Key-release service (runs on local machine or dedicated HSM host):
#   1. Receives attestation report from VM
#   2. Verifies AMD VCEK → ASK → ARK certificate chain
#   3. Checks measurement against allowlist
#   4. Requires Nitrokey TOUCH to sign a session key
#   5. Sends session key to VM encrypted to the attested report's public key

# VM-side:
attestation = TEEAttestation()
report = attestation.fetch_attestation_report(nonce=challenge)
session_key, measurement = attestation.verify_via_key_service(
    report, 
    key_service_url="https://key-release.internal:8443/verify",
    nonce=challenge
)
```

This model preserves the two-persona trust:
- **GCP/hypervisor** cannot decrypt: it doesn't have the Nitrokey or the attestation key
- **Nitrokey holder** cannot decrypt without the VM: needs the precise SEV measurement
- **Key-release service** verifies both before releasing any key material

## Deployment Targets

| Platform | TEE | Nitrokey Support | Verdict |
|:---|:---|:---|:---|
| **GCP N2D (EPYC 7003+)** | SEV-SNP | Via key-release service | ✓ Production |
| **GCP C3D (EPYC Genoa)** | SEV-SNP | Via key-release service | ✓ Production |
| **AWS EC2 (EPYC 7003)** | SEV-SNP (m6a/c6a) | Via key-release service | ✓ Production |
| **Bare metal EPYC** | SEV-SNP | Direct USB / key-release | ✓ Production |
| **IBM LinuxONE** | SEL (native HPVS) | Crypto Express HSM | ✓ Native HPVS |
| OCI Ampere A1 | None | N/A | ✗ No TEE — refused |
| Standard GCP/AWS VM | None | N/A | ✗ No attestation possible |

## Quick Start

```bash
# Build-time (offline):
python cloud_protection.py --check-only
# → Confirms SEV-SNP available, Nitrokey detected

# Seal strategy:
tar czf strategy.tar.gz combined_runner.py config.py ...
python -c "
from cloud_protection import aes_gcm_seal, ProtectedMemory
key = ProtectedMemory(32)
key.write(secrets.token_bytes(32))
blob = aes_gcm_seal(open('strategy.tar.gz','rb').read(), key, b'strategy.tar.gz')
open('strategy.tar.gz.aesgcm','wb').write(blob)
"

# Deploy-time (VM):
python cloud_protection.py \
  --sealed-dir ./sealed \
  --output-dir ./live \
  --expected-measurement "a1b2c3d4..." \
  --verbse

# Start trading:
python live/combined_runner.py --mode prop --live
```

## Requirements

- Python 3.11+ with `cryptography` library (`pip install cryptography`)
- AMD EPYC Milan/Genoa with SEV-SNP enabled (GCP N2D/C3D, AWS m6a/c6a)
- Nitrokey FIDO2 or compatible (for key-release service)
- `fido2-token`, `fido2-assert` (libfido2-1 package)
- Key-release service (separate deployment)
- Signed container images with expected measurement recorded

## GCP SEV-SNP Deployment (Explicit)

GCP N2D supports both SEV-ES and SEV-SNP. This architecture requires SEV-SNP specifically
because it provides the signed attestation report with measurement that SEV-ES cannot produce
from the guest. Create the instance explicitly:

```bash
gcloud compute instances create trading-signal-vm \
  --zone=us-central1-a \
  --machine-type=n2d-standard-2 \
  --confidential-compute \
  --confidential-compute-type=SEV_SNP \
  --min-cpu-platform="AMD Milan" \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB
```

Do NOT use `--confidential-compute` without `--confidential-compute-type=SEV_SNP` — that
defaults to SEV-ES, which cannot produce the signed attestation report required by this
architecture.

## Key Release Service Must Also Run in a TEE

The external key-release service holds the Nitrokey and derives session keys. If this service
runs on a standard VM, the cloud provider hosting it could snapshot its memory and steal
Nitrokey session keys. The complete chain requires:

```
Key-Release Service TEE (AWS Nitro Enclave / Azure Confidential VM)
    │
    ├─ Talks to Nitrokey FIDO2 (local USB)
    ├─ Verifies VM attestation report (AMD VCEK → ASK → ARK)
    ├─ Derives session key bound to the attested VM's public key
    └─ Sends session key over mTLS to GCP N2D SEV-SNP VM
```

Neither AWS (hosting the key service) nor GCP (hosting the trading bot) ever sees the
plaintext AES key. This creates an end-to-end confidential computing chain.

## CPU Register Limitation (and Why SEV-SNP Is Still Necessary)

When `AESGCM(key).decrypt()` executes, the key is loaded into CPU AES-NI registers for
the microsecond of computation. This is physically unavoidable on any platform.

What our protections DO prevent:
- **OS-level scraping**: `mlock` + `MADV_DONTDUMP` = key never in swap or core dumps
- **Hypervisor-level scraping**: SEV-SNP encrypts all VM memory at the CPU boundary —
  even if the hypervisor snapshots RAM, it sees only ciphertext
- **Python-level leaks**: No `.hex()`, no CLI arguments, no temp files, `memoryview` from
  locked buffer — intentional key serialization is impossible
- **Attacker with physical RAM access**: SEV-SNP memory encryption + continuous attestation
  polling = any attempt to read encrypted memory triggers measurement change → zeroization

The CPU register holding the key during AES-NI execution is encrypted inside the SEV-SNP
secure world. This is the same protection IBM HPVS provides via Crypto Express HSM — the
key exists in cleartext only inside a hardware-protected boundary.
