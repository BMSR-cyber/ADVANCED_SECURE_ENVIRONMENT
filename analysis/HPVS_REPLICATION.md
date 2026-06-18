# HPVS Replication Analysis — Cross-Document Synthesis

## Core Insight

IBM Hyper Protect Virtual Servers (HPVS v2.1) provide these 5 security guarantees:

1. **Workload isolation** — Guest VM memory is encrypted; the hypervisor/OS cannot read it
2. **Multi-party encrypted contract** — Separate personas (workload owner, environment owner, auditor) each contribute encrypted secrets no other party can access
3. **Key binding to guest identity** — HSM keys are cryptographically bound to a specific guest VM, preventing cross-VM key theft
4. **Metadata secret injection** — Confidential data is injected into the guest at launch without cloud provider visibility
5. **Continuous attestation** — Platform state is continuously verified; any change → session teardown

These are implemented on IBM Z16 / LinuxONE 4 hardware ($500K+). Our goal: replicate
these guarantees on accessible cloud hardware using open standards.

## Guarantee-by-Guarantee Mapping

### 1. Workload Isolation

| IBM HPVS | Our Implementation |
|:---|:---|
| IBM Secure Execution for Linux (SEL) | AMD SEV-ES (Secure Encrypted Virtualization - Encrypted State) |
| Crypto Express 8S HSM (FIPS 140-2 L4) | CPU-bound memory encryption via AMD PSP |
| KVM guest with encrypted page tables | Same mechanism: SEV-ES encrypts all CPU registers + memory |
| LPAR → workload boundary move | VM isolation boundary at hypervisor level |

**Key difference:** SEL encrypts at the KVM guest level with HSM-backed keys.
SEV-ES encrypts at the CPU level with AMD PSP-managed keys. The security
guarantee is equivalent (hypervisor cannot read memory), but the key management
differs (HSM vs firmware).

**Free-tier target:** GCP N2D instances use AMD EPYC Milan with SEV-ES support.
Enable via: `gcloud compute instances create ... --confidential-compute`

### 2. Multi-Party Encrypted Contract

| IBM HPVS | Our Implementation |
|:---|:---|
| Workload owner's encrypted portion | Nitrokey FIDO2 hmac-secret (human root-of-trust) |
| Environment owner's encrypted portion | SEV attestation report (hardware root-of-trust) |
| Auditor's encrypted portion | Keylime continuous attestation log (third-party verification) |
| LUKS passphrase from independent seeds | HKDF-SHA512(attestation_hash, fido2_secret, salt="hpvs-portfolio/v1") |

**Key difference:** IBM uses 3 human personas with separate encryption keys.
We use 2 hardware roots (SEV + FIDO2) and 1 software verifier (Keylime).
The trust model is equivalent: no single party/device can decrypt the secrets.

### 3. Key Binding to Guest Identity (US 11,500,988 B2)

This patent describes a 5-phase mechanism where a Secure Interface Control (SC)
intercepts all HSM operations and binds session keys to a specific guest.

| Phase | IBM Implementation | Our Implementation |
|:---|:---|:---|
| Configuration | SC configures HSM for exclusive use | `luksProtection.configure()` — LUKS2 slot bound to TEE |
| Session Login Interception | SC replaces login data with secret from metadata | Metadata decrypted with SEV-derived key only |
| Session Code Replacement | SC generates new session codes, remaps internally | Session keys derived from HKDF(attestation + fido2) |
| Key Gen/Logout Interception | All ops intercepted; SC translates session codes | All key material in mlock-secured memory, zeroized on signal |
| Cleanup on Termination | HSM sessions closed, config removed | `SecureZeroizer` → overwrite + `os._exit(1)` |

**Key adaptation:** We don't have a hardware HSM. Instead, the AMD PSP acts as
the Secure Interface Control, and memory encryption serves as the "HSM" substitute.
Key material is in CPU-bound encrypted memory, inaccessible to any other VM.

### 4. Metadata Secret Injection

| IBM HPVS | Our Implementation |
|:---|:---|
| Integrity-protected metadata (SE header) | SEV attestation report with guest measurement |
| Secret encrypted by SC key | AES-256-GCM with key from HKDF(attestation_hash, fido2) |
| Cloud provider transmits but cannot decrypt | Metadata file on disk; cloud has filesystem access but no key |
| Cryptographically linked to guest image | AAD = guest measurement hash; wrong VM → decrypt fails |

**GCP-specific:** SEV-SNP on EPYC 7003+ supports `LAUNCH_SECRET`. On SEV-ES
(N2D), we use the attestation report hash as a proxy measurement. Keylime
provides the continuous verification layer.

### 5. Continuous Attestation

| IBM HPVS | Our Implementation |
|:---|:---|
| SE boot chain verification | TPM 2.0 PCR measurement at boot |
| Crypto Express HSM health monitoring | Keylime 5-min PCR polling |
| Violation → session teardown | `ContinuousAttestationMonitor` → `SecureZeroizer` |
| Auditor-signed attestation records | Keylime agent logs to remote verifier |

## Trust Model Comparison

```
IBM HPVS:
  Owner (human) ────► Encrypted Contract ◄──── Environment (IBM Cloud)
                           │
                           ▼
                      HSM-bound keys
                           │
                           ▼
                   Secure Guest (SEL)

Our Architecture:
  Owner (Nitrokey touch) ──► HKDF Key Derivation ◄── SEV Hardware (AMD PSP)
                                  │
                                  ▼
                           AES-256-GCM
                                  │
                                  ▼
                    SEV-ES Encrypted Guest (AMD EPYC)
                                  │
                                  ▼
                    Keylime Continuous Attestation
```

## Limitations vs Native HPVS

| Feature | HPVS | Our Replication |
|:---|:---|:---|
| HSM key storage | Crypto Express 8S (FIPS 140-2 L4) | SEV-ES encrypted memory (no dedicated HSM) |
| Secure boot chain | IBM Z SE + LPAR measured boot | UEFI Secure Boot + TPM 2.0 |
| Key theft across VMs | Prevented by SC + HSM binding | Prevented by SEV-ES memory encryption + mlock |
| Performance overhead | <2% (dedicated crypto adapters) | ~5-8% (SEV-ES memory encryption overhead) |
| Compliance certs | FIPS 140-2 L4, SOC 2, PCI-DSS | NIST SP 800-147B alignment (not certified) |
| Cost | $500K+ hardware | $50-100/mo GCP N2D |

## Future: Intel TDX

Intel TDX (Trust Domain Extensions) on Sapphire Rapids Xeons offers:
- Full VM isolation (like SEV but with integrity protection from launch)
- TDX Module (software equivalent to AMD PSP firmware)
- Attestation via Intel SGX quoting enclave

When GCP or AWS offer TDX on non-premium instances, this architecture can
migrate with minimal changes (swap `TEAttestationVerifier` to detect `TDX`).

## Production Roadmap

1. [x] Source materials collected (IBM patents, NIST standards, TEE survey)
2. [x] Architecture designed (SEV-ES + Nitrokey + Keylime)
3. [x] Core implementation (cloud_protection.py, 1,189 lines)
4. [ ] GCP N2D deployment with SEV-ES enabled
5. [ ] Keylime remote verifier on separate VM
6. [ ] Nitrokey FIDO2 enrollment for cloud VM
7. [ ] Trading bot integrated with cloud_protection layer
8. [ ] Penetration test (attempt to extract secrets from hypervisor)
9. [ ] TDX migration when available on free/cheap tiers
10. [ ] FIPS 140-2 certification path (if needed for institutional clients)
