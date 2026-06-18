# Cloud Protection Layer – Confidential Computing for Trading Bot

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                        CLOUD VM (SEV-ES / TDX)                      │
  │                                                                      │
  │  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
  │  │  Nitrokey    │    │  cloud_protection │    │  LUKS2 Volume    │  │
  │  │  FIDO2       │◄──►│  .py              │◄──►│  /mnt/hpvs_data  │  │
  │  │  (USB pass-  │    │                   │    │  (encrypted at   │  │
  │  │   through)   │    │  ┌─────────────┐  │    │   rest)          │  │
  │  └──────────────┘    │  │ TEE Verifier│  │    └───────────────────┘  │
  │                      │  │ (SEV/TPM)   │  │                           │
  │  ┌──────────────┐    │  └──────┬──────┘  │    ┌───────────────────┐  │
  │  │ /dev/sev     │    │         │         │    │  .aesgcm files    │  │
  │  │ /dev/sev-    │◄───┤  ┌──────▼──────┐  │    │  config.py.      │  │
  │  │   guest      │    │  │   HKDF      │  │    │  aesgcm           │  │
  │  │              │    │  │ SHA-512     │  │    │  combined_runner  │  │
  │  │ SEV Firmware │    │  │ key deriv.  │  │    │  .py.aesgcm       │  │
  │  └──────────────┘    │  └──────┬──────┘  │    │  ...              │  │
  │                      │         │         │    └───────────────────┘  │
  │  ┌──────────────┐    │  ┌──────▼──────┐  │                           │
  │  │ vTPM / TPM   │    │  │ AES-256-GCM │  │    ┌───────────────────┐  │
  │  │ /dev/tpm0    │    │  │  Decrypt    │──┼───►│ Protected Memory  │  │
  │  │ PCR Monitor  │◄───┤  └─────────────┘  │    │ (mlock +          │  │
  │  └──────────────┘    │                   │    │  MADV_DONTDUMP)   │  │
  │                      │  ┌─────────────┐  │    └───────────────────┘  │
  │                      │  │ Continuous  │  │                           │
  │                      │  │ Attestation │  │    ┌───────────────────┐  │
  │                      │  │ Monitor     │  │    │  Trading Bot      │  │
  │                      │  │ (5min poll) │  │    │  (combined_runner │  │
  │                      │  └──────┬──────┘  │    │   .py)            │  │
  │                      │         │         │    └───────────────────┘  │
  │                      │  ┌──────▼──────┐  │                           │
  │                      │  │ Secure      │  │                           │
  │                      │  │ Zeroizer    │  │                           │
  │                      │  │ (SIGUSR1    │  │                           │
  │                      │  │  handler)   │  │                           │
  │                      │  └─────────────┘  │                           │
  │                      └───────────────────┘                           │
  └──────────────────────────────────────────────────────────────────────┘
```

## Architecture

### Trust Chain

```
Nitrokey FIDO2 (physical root-of-trust)
    │
    ▼  hmac-secret
    │
Platform Attestation (SEV measurement / TPM PCR)
    │
    ▼  HKDF-SHA512(salt="hpvs-portfolio/v1")
    │
AES-256-GCM Decryption Key (32 bytes, in mlock'd memory)
    │
    ▼
Encrypted Config Files (.aesgcm) ───► Decrypted configs in Protected Memory
    │
    ▼
Trading Bot Execution
```

### Component Summary

| Component | Purpose |
|---|---|
| `TEAttestationVerifier` | Confirms platform is running in genuine SEV/TDX/TPM TEE |
| `NitrokeyRootOfTrust` | Retrieves FIDO2 hmac-secret from physical Nitrokey |
| `MetadataDecryptor` | AES-256-GCM decryption with HKDF-derived key |
| `ProtectedMemory` | mlock'd + MADV_DONTDUMP buffers for secrets |
| `ContinuousAttestationMonitor` | Polls platform state every 5 min; triggers zeroization on change |
| `LuksProtection` | LUKS2-encrypted loopback volume for data-at-rest |
| `SecureZeroizer` | Overwrites all secrets + force-exits on violation |
| `ProcessObfuscator` | Renames process to blend in with system daemons |

---

## GCP N2D SEV-ES Setup Instructions

The GCP N2D series (AMD EPYC) supports SEV-ES in the free/cheap tier.

### 1. Create SEV-ES VM

```bash
gcloud compute instances create hpvs-trading-bot \
  --zone=us-central1-a \
  --machine-type=n2d-standard-2 \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB \
  --boot-disk-type=pd-ssd \
  --confidential-compute \
  --maintenance-policy=TERMINATE \
  --scopes=cloud-platform
```

The `--confidential-compute` flag enables SEV-ES on N2D machines.

### 2. Verify SEV Inside the VM

```bash
# Check SEV sysfs parameter
cat /sys/module/kvm_amd/parameters/sev
# Should output: 1

# Check /dev/sev device
ls -la /dev/sev
# Should exist

# Install sevctl for detailed attestation
sudo apt-get install -y sevctl
sudo sevctl export --full
```

### 3. Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 python3-pip \
  openssl cryptsetup-bin \
  fido2-tools \
  tpm2-tools \
  usbutils

# Enable USB passthrough for Nitrokey (see Nitrokey section below)
```

### 4. Prepare Encrypted Config Files

On the build machine (not the cloud VM):

```bash
# Build-time: encrypt configs with platform key
python3 cloud_protection.py --seal config.py
python3 cloud_protection.py --seal combined_runner.py
python3 cloud_protection.py --seal prop_breakers.py
python3 cloud_protection.py --seal calibration_report.md
```

Copy the resulting `.aesgcm` files to the cloud VM.

### 5. Prepare LUKS Volume (optional, inside VM)

```bash
python3 cloud_protection.py --format-luks 256
```

### 6. Launch

```bash
python3 cloud_protection.py --data-dir /opt/trading-bot --verbose
```

---

## OCI Ampere Limitations

Oracle Cloud Infrastructure (OCI) Ampere A1 instances run on ARM-based
Ampere Altra processors. These do **not** expose a TEE to tenants:

| Feature | OCI Ampere | GCP N2D SEV-ES |
|---|---|---|
| Confidential computing | No | Yes (SEV-ES) |
| Memory encryption | No | Yes (hardware) |
| TPM available | Software vTPM only | vTPM + SEV attestation |
| Attestation | None verifiable | SEV report chain |
| Nitrokey passthrough | USB only | USB only |

### Using OCI Ampere as Fallback

OCI Ampere can serve as a **non-TEE fallback** for development/testing:

```bash
# OCI Ampere will fall through to TPM-only mode:
python3 cloud_protection.py --check-only
# Output: TEE attestation: FAIL (type=None)
#         Nitrokey present: PASS
# Result: Will refuse to decrypt production configs
```

To use OCI Ampere for **development only**:
1. Generate a separate development keypair (not derived from SEV measurement)
2. Use `--dev-mode` (not implemented in production code intentionally)
3. Accept that data is not protected by hardware TEE

**Security note**: Never deploy production trading bot configs to a non-TEE
platform. OCI Ampere lacks the hardware root-of-trust required for verifiable
confidential computing.

---

## Nitrokey Enrollment Procedure for Cloud VM

The Nitrokey FIDO2 device must be enrolled and have its hmac-secret
credential registered.

### 1. On a Secure Enrollment Workstation

```bash
# Install tools
sudo apt-get install fido2-tools libfido2-1

# Set a PIN on the Nitrokey (if not already done)
fido2-token -S /dev/hidrawX

# Create a new credential with hmac-secret extension
fido2-cred -M -r -i /tmp/cred_id \
  -t hmac-secret \
  /dev/hidrawX

# Save the credential ID
cp /tmp/cred_id /secure/location/credential_id.txt

# Create the fido2-key.sh script (placed alongside cloud_protection.py):
cat > fido2-key.sh << 'SCRIPT'
#!/bin/bash
# Pipe-based hmac-secret retrieval
RP_ID="hpvs-portfolio.local"
CRED_ID_FILE="$(dirname "$0")/credential_id.txt"
CRED_ID=$(cat "$CRED_ID_FILE" 2>/dev/null)

if [ -n "$CRED_ID" ]; then
    fido2-assert -G -r "$RP_ID" -i "$CRED_ID" -o /dev/stdout 2>/dev/null
else
    fido2-assert -G -r "$RP_ID" -o /dev/stdout 2>/dev/null
fi
SCRIPT
chmod +x fido2-key.sh
```

### 2. Transfer Credential ID to Cloud VM

```bash
# Securely copy the credential ID (not the secret itself)
scp credential_id.txt hpvs-vm:/opt/trading-bot/
```

### 3. USB Passthrough for Nitrokey on Cloud VM

**GCP**:
- GCP does not natively support USB passthrough to VMs
- Workaround: Use USB-over-IP (usbip) or a USB-to-network bridge
- Alternative: Keep Nitrokey on a local trusted host, run attestation
  verification there, and tunnel the hmac-secret over a mutually
  authenticated TLS channel

**Self-hosted / Bare-metal**:
- Direct USB access - just plug in the Nitrokey

**QEMU/KVM (local)**:
```bash
# Add USB device to VM
qemu-system-x86_64 ... \
  -usb -device usb-host,hostbus=X,hostaddr=Y
```

### 4. Verify Enrollment

```bash
python3 cloud_protection.py --check-only

# Expected output:
# TEE attestation: PASS (type=SEV)
# Nitrokey present: PASS
# hmac-secret: OBTAINED
```

---

## Build-Time Sealing Procedure

Config files must be encrypted **at build time** using the platform-derived key.

### Prerequisites

1. A reference SEV-ES VM running with known measurement
2. Nitrokey FIDO2 with enrolled hmac-secret credential
3. The `cloud_protection.py` protection layer

### Steps

```bash
# 1. On the trusted build VM (SEV-ES environment):

# Bootstrap the protection layer to derive the encryption key
python3 cloud_protection.py --verbose &
# Wait for bootstrap to complete and note the derived key is now in memory.
# The bootstrap process will verify:
#   - SEV attestation passes
#   - Nitrokey is present and yields hmac-secret
#   - HKDF-SHA512 derives the correct key

# 2. In another terminal, seal each config file:
python3 cloud_protection.py --seal config.py
# Output: Sealed: /opt/trading-bot/config.py.aesgcm

python3 cloud_protection.py --seal combined_runner.py
python3 cloud_protection.py --seal prop_breakers.py
python3 cloud_protection.py --seal calibration_report.md

# 3. Verify sealing was correct:
python3 cloud_protection.py --decrypt-to /tmp/verify-seal
diff config.py /tmp/verify-seal/config.py   # Should be identical
rm -rf /tmp/verify-seal

# 4. Transfer .aesgcm files to target deployment VM(s).
#    Only VMs with matching SEV measurement + Nitrokey can decrypt them.
```

### File Format

Each `.aesgcm` file:

```
┌──────────────────────────────────────────────────────┐
│  Bytes 0-11:     IV (random, 12 bytes)                │
│  Bytes 12-N-17:  AES-256-GCM ciphertext              │
│  Bytes N-16:N:   GCM authentication tag (16 bytes)    │
└──────────────────────────────────────────────────────┘
```

Key derivation:
```
HKDF-SHA512(
  IKM  = platform_measurement || fido2_hmac_secret,
  salt = "hpvs-portfolio/v1",
  info = "metadata-encryption-key",
  L    = 32
)
```

No plaintext key is ever written to disk -- it exists only in mlock'd
+ MADV_DONTDUMP protected memory.

---

## Attestation Verification Workflow

### Initial Bootstrap (diagram)

```
  Boot Sequence
      │
      ▼
  ┌─────────────────┐
  │ 1. Obfuscate     │   prctl(PR_SET_NAME, "systemd-journal")
  │    process name  │
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 2. Arm zeroizer  │   Register SIGUSR1/SIGINT/SIGTERM handlers
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 3. Verify TEE    │   Check /dev/sev, /sys/.../sev, /dev/tpm0
  │    attestation   │   Read SEV measurement or TPM PCRs
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 4. Check         │   fido2-token -L
  │    Nitrokey      │   Fail if absent → zeroize + exit
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 5. Get hmac-     │   fido2-assert -G -r hpvs-portfolio.local
  │    secret         │   or fido2-key.sh pipe
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 6. HKDF-SHA512   │   key = HKDF(measurement + hmac_secret,
  │    derive key    │         salt="hpvs-portfolio/v1", len=32)
  │    → mlock'd mem │
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 7. Decrypt       │   AES-256-GCM decrypt each .aesgcm file
  │    metadata      │   Store plaintext in ProtectedMemory
  │    configs       │   Fail if ANY auth tag fails → zeroize + exit
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 8. Open LUKS     │   cryptsetup luksOpen (optional)
  │    (optional)    │   mount /dev/mapper/hpvs_data → /mnt/hpvs_data
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 9. Start         │   Background thread polling SEV/TPM every 5 min
  │    continuous    │   On change → zeroize all memory → os._exit(1)
  │    attestation   │
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 10. Switch to    │   Log level: ERRORS only at runtime
  │     runtime mode │
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │ 11. Application  │   Trading bot runs with decrypted configs
  │     runs         │   All secrets in ProtectedMemory
  └─────────────────┘
```

### Continuous Attestation Loop

```
  Every 300 seconds (5 minutes):
      │
      ▼
  ┌──────────────────────┐
  │ Re-verify TEE state   │
  │ (reread SEV measure   │
  │  or TPM PCRs)         │
  └──────────┬───────────┘
             │
     ┌───────┴───────┐
     │               │
  [Match]        [Changed]
     │               │
     ▼               ▼
  Continue      ┌──────────────┐
                │ ZEROIZE ALL  │
                │ Overwrite    │
                │ ProtectedMem │
                │ with random  │
                │ bytes        │
                │              │
                │ os._exit(1)  │
                └──────────────┘
```

---

## Disaster Recovery: Nitrokey Is Lost or Destroyed

### Scenario

The Nitrokey FIDO2 device is lost, damaged, or stolen. The hmac-secret
is the master secret root-of-trust -- without it, the AES-256-GCM
decryption key cannot be derived, and all `.aesgcm` files are
permanently inaccessible.

### Recovery Options

#### Option A: Pre-provisioned Backup Nitrokey

During enrollment, create a **second Nitrokey** with an identical
hmac-secret credential:

```bash
# During initial enrollment (before deploying to cloud):
fido2-cred -M -r -i /tmp/cred_id_backup \
  -t hmac-secret \
  /dev/hidrawX   # Second Nitrokey device
```

Store the backup Nitrokey in a physical safe. Register both credential
IDs in the cloud VM so either Nitrokey can unlock the system.

#### Option B: Emergency Access Procedure

If no backup Nitrokey exists:

1. **Re-enroll** on a new SEV-ES VM with matching measurement:
   - Create a new VM from the same trusted base image
   - Enroll a new Nitrokey with a new hmac-secret credential
   - This produces a *new* decryption key -- old `.aesgcm` files are
     **not decryptable**

2. **Rebuild and re-seal** all config files with the new key:
   ```bash
   # On the new VM:
   python3 cloud_protection.py --seal config.py
   python3 cloud_protection.py --seal combined_runner.py
   # ... seal all files again
   ```

3. **Deploy** the new `.aesgcm` files to the target VM.

#### Option C: TEE-Only Recovery (Reduced Security)

Implement an emergency recovery path that uses **only** the platform
measurement (no Nitrokey) to derive the key. This reduces security
but allows recovery:

```python
# NOT IMPLEMENTED by default -- must be explicitly enabled
# and only for non-critical deployments.
#
# recovery_key = hkdf_sha512(
#     ikm=platform_measurement,
#     salt=b"hpvs-portfolio/v1",
#     info=b"recovery-key",
#     length=32,
# )
```

**Warning**: This defeats the two-factor nature of the design.
Only use for development/test instances.

### Prevention Checklist

- [ ] Create at least 2 enrolled Nitrokeys before deploying to production
- [ ] Store backup Nitrokey in a fireproof safe, geographically separated from the primary
- [ ] Document credential IDs in an offline, secure location
- [ ] Test recovery procedure quarterly
- [ ] Ensure build-time sealing procedure is documented and reproducible
- [ ] Keep a copy of the trusted base VM image for quick redeployment
- [ ] Set up alerting if Nitrokey USB device disappears from the VM

---

## Command Reference

```bash
# Check platform status only (no bootstrap)
python3 cloud_protection.py --check-only

# Full bootstrap + run
python3 cloud_protection.py --data-dir /opt/trading-bot --verbose

# Bootstrap + stay running (daemon mode)
python3 cloud_protection.py --quiet

# Format a new LUKS2 volume
python3 cloud_protection.py --format-luks 512

# Seal a file (encrypt with derived key)
python3 cloud_protection.py --seal config.py

# Decrypt all .aesgcm files to a directory
python3 cloud_protection.py --decrypt-to /tmp/decrypted-out

# Custom mount paths
python3 cloud_protection.py --mount /secure/data --luks-backing /secure/volume.luks
```

## Security Properties

| Property | Implementation |
|---|---|
| Confidentiality at rest | AES-256-GCM, key never on disk |
| Confidentiality in use | SEV-ES/TDX encrypted memory |
| Integrity | GCM authentication tag per file |
| Freshness | Attestation report timestamp via continuous monitor |
| Binding to platform | HKDF key binds decryption to specific SEV measurement |
| Binding to user | Nitrokey FIDO2 adds physical possession factor |
| Anti-forensics | ProtectedMemory zeroized on violation; MADV_DONTDUMP |
| Process stealth | Process name obfuscation via prctl |
| Data-at-rest | LUKS2 with passphrase derived inside TEE |

---

## Troubleshooting

### "No TEE capability detected"

- Verify you are on a SEV-capable instance (GCP N2D with `--confidential-compute`)
- Check `/sys/module/kvm_amd/parameters/sev` shows `1`
- If on bare metal, ensure SEV is enabled in BIOS

### "Nitrokey FIDO2 token not present"

- Run `fido2-token -L` to verify the device is detected
- Check USB passthrough configuration
- For GCP: use usbip or a local trusted host with TLS tunnel (see Nitrokey section)

### "AES-256-GCM authentication tag verification failed"

- The decryption key does not match what was used at seal time
- Verify the same Nitrokey + same SEV measurement as build time
- Rebuild and re-seal if platform measurement changed

### "Platform measurement changed"

- Continuous attestation detected a state change
- Possible causes: VM migration, kernel update, firmware change
- If legitimate change: rebuild and re-seal config files on the new platform
- If unexpected: assume compromise, rotate all credentials
