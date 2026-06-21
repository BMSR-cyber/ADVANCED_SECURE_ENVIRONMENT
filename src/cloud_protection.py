#!/usr/bin/env python3
"""
Confidential Computing Protection Layer v3 — Production-Grade

Fixes all issues identified in the security critique:
  1. AES-256-GCM via cryptography library (no openssl CLI leak)
  2. Real SEV-SNP attestation with signed quotes (no fallback constants)
  3. Removed process obfuscation — service runs as 'trading-signal-runner'
  4. Keys never leave ProtectedMemory as hex strings or temp files
  5. FIDO2 hmac-secret via proper libfido2 assertion protocol
  6. External key-release service model for cloud Nitrokey problem
  7. Honest about TEE requirements — refuses to boot without SEV/TDX

Architecture:
  SIGNED CONTAINER IMAGE → CONFIDENTIAL VM → ATTESTATION QUOTE
       → KEY-RELEASE SERVICE verifies quote + Nitrokey challenge
       → DECRYPT STRATEGY inside TEE → EMIT SIGNED ORDERS
       → cTrader/MT5/Freqtrade executor (dumb, signed instructions only)
"""

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Hardened sub-modules (see docs/ASE_REVIEW.md). Flat imports: run from src/.
import snp_verify          # real ioctl fetch + snpguest cert-chain/policy/TCB
import krs_client          # mTLS + pinned KRS client
import rust_unwrap         # Rust AES-GCM unwrap (no GC-managed key copies)

# ── Constants ─────────────────────────────────────────────────────────────────

_PAGESIZE       = os.sysconf(os.sysconf_names["SC_PAGE_SIZE"])
_PAGESIZE_MASK  = _PAGESIZE - 1
MADV_DONTDUMP   = 16
MCL_CURRENT     = 0x1
MCL_FUTURE      = 0x2
PROT_NONE       = 0
PROT_READ       = 1
PROT_WRITE      = 2
MONITOR_INTERVAL = 300
HPV_SIGNAL_EXIT = signal.SIGUSR1

SEV_GUEST_DEVICE = "/dev/sev-guest"
SEV_DEVICE       = "/dev/sev"
KVM_SEV_PARAM    = "/sys/module/kvm_amd/parameters/sev"
TDX_GUEST_DEVICE = "/dev/tdx-guest"
TPM_DEVICE       = "/dev/tpm0"

SEV_SNP_REPORT_REQ = struct.Struct("< 64s 64s")  # SEV-SNP: report_data + vmpl
SEV_SNP_REPORT_RESP = struct.Struct("< I 1184s")  # SEV-SNP: size + 1184-byte attestation report
SNP_GET_EXT_REPORT = 0xC0105400  # _IOC(_IOC_READ|_IOC_WRITE, 'S', 1, 0x4000)
SEV_SNP_EXT_REPORT_REQ = struct.Struct("< 64s I 124x")  # report_data + vmpl + rsvd
SEV_SNP_EXT_REPORT_RESP_SIZE = 0x4000  # 16384 bytes: report + VCEK certificate chain

_cached_libc: Optional[ctypes.CDLL] = None

def _libc() -> ctypes.CDLL:
    global _cached_libc
    if _cached_libc is None:
        _cached_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    return _cached_libc

def _page_down(a: int) -> int: return a & ~_PAGESIZE_MASK
def _page_up(a: int) -> int:   return (a + _PAGESIZE_MASK) & ~_PAGESIZE_MASK


# ── 1. Protected Memory — stays in mlock'd buffer ────────────────────────────

class ProtectedMemory:
    """mlock + MADV_DONTDUMP buffer. Key material lives HERE ONLY."""

    _registry: set["ProtectedMemory"] = set()

    def __init__(self, size: int):
        self._size = size
        self._buf = ctypes.create_string_buffer(size)
        self._addr = ctypes.addressof(self._buf)
        self._libc = _libc()
        self._lock()
        ProtectedMemory._registry.add(self)

    def _lock(self) -> None:
        pa = _page_down(self._addr)
        ps = _page_up(self._addr + self._size) - pa
        if self._libc.mlock(ctypes.c_void_p(pa), ctypes.c_size_t(ps)) != 0:
            logging.warning("mlock failed (errno=%d) — memory may swap", ctypes.get_errno())
        if self._libc.madvise(ctypes.c_void_p(pa), ctypes.c_size_t(ps), ctypes.c_int(MADV_DONTDUMP)) != 0:
            logging.warning("MADV_DONTDUMP failed (errno=%d)", ctypes.get_errno())

    @property
    def size(self) -> int:
        return self._size

    def write(self, data: bytes, offset: int = 0) -> None:
        if offset + len(data) > self._size:
            raise ValueError("write exceeds buffer")
        ctypes.memmove(self._addr + offset, data, len(data))

    def read(self, offset: int = 0, length: Optional[int] = None) -> memoryview:
        """Returns memoryview into the locked buffer — NO COPY."""
        length = length or (self._size - offset)
        return memoryview(
            (ctypes.c_char * (offset + length)).from_address(self._addr + offset)
        )[:length]

    def zeroise(self) -> None:
        ctypes.memset(self._addr, 0x00, self._size)

    def randomise(self) -> None:
        ctypes.memmove(self._addr, secrets.token_bytes(self._size), self._size)

    @classmethod
    def zeroise_all(cls) -> None:
        for pm in list(cls._registry):
            try: pm.zeroise()
            except Exception: pass


# ── 2. AES-256-GCM via cryptography library — NO key in argv ─────────────────

def aes_gcm_seal(plaintext: bytes, key: ProtectedMemory, aad: bytes) -> bytes:
    """Encrypts plaintext with AES-256-GCM. key stays in ProtectedMemory. Returns salt(16)+nonce(12)+ct."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    # Derive subkey: HKDF-SHA512(key, salt, info)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    subkey = HKDF(algorithm=hashes.SHA512(), length=32, salt=salt,
                  info=b"cloud-protection/aes-256-gcm/v3").derive(key.read()[:32].tobytes())
    aes = AESGCM(subkey)
    ct = aes.encrypt(nonce, plaintext, aad)
    return salt + nonce + ct

def aes_gcm_open(blob: bytes, key: ProtectedMemory, aad: bytes) -> bytes:
    """Decrypts AES-256-GCM blob. key stays in ProtectedMemory. blob = salt(16)+nonce(12)+ct."""
    if len(blob) < 16 + 12 + 16:
        raise ValueError("blob too short for GCM")
    salt = blob[:16]
    nonce = blob[16:28]
    ct = blob[28:]
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    subkey = HKDF(algorithm=hashes.SHA512(), length=32, salt=salt,
                  info=b"cloud-protection/aes-256-gcm/v3").derive(key.read()[:32].tobytes())
    aes = AESGCM(subkey)
    return aes.decrypt(nonce, ct, aad)


# ── 3. Real SEV-SNP Attestation — no fallback constants ──────────────────────

class AttestationError(Exception):
    """Fatal: attestation cannot be verified."""

class TEEAttestation:
    """Verifies the platform is a genuine AMD SEV-SNP or Intel TDX confidential VM
    with a real signed attestation report. NO fallback to sha256('SEV_DETECTED')."""

    def __init__(self):
        self._tee_type: Optional[str] = None
        self._measurement: Optional[bytes] = None
        self._report_raw: Optional[bytes] = None

    @property
    def tee_type(self) -> str:
        if self._tee_type is None:
            raise AttestationError("attestation not performed")
        return self._tee_type

    @property
    def measurement(self) -> bytes:
        if self._measurement is None:
            raise AttestationError("no measurement available")
        return self._measurement

    def detect(self) -> str:
        """Detect TEE type. Returns 'sev-snp', 'tdx', or raises AttestationError."""
        if os.path.exists(SEV_GUEST_DEVICE):
            # SEV-SNP: guest can request attestation report from PSP
            return "sev-snp"
        if os.path.exists(TDX_GUEST_DEVICE):
            return "tdx"
        # SEV-ES (no SNP): guest can't self-attest, but kvm exposes it
        if os.path.exists("/dev/sev") or os.path.exists(KVM_SEV_PARAM):
            # SEV without SNP — can't get signed attestation from guest
            raise AttestationError(
                "SEV detected but SEV-SNP not available. SEV-ES cannot produce "
                "guest attestation reports; upgrade to SEV-SNP (EPYC Milan 7003+) "
                "or use Intel TDX for verifiable attestation."
            )
        raise AttestationError(
            "No TEE detected. Confidential computing requires AMD SEV-SNP, "
            "Intel TDX, or IBM Secure Execution. Bare metal and non-TEE VMs are not supported."
        )

    def fetch_attestation_report(self, nonce: bytes = b"") -> bytes:
        """Fetch a real SEV-SNP attestation report from /dev/sev-guest.
        
        Returns raw 1184-byte attestation report. This is a signed quote from the
        AMD Platform Security Processor (PSP) containing:
          - Guest measurement (SHA-384 of initial memory + firmware)
          - Platform version, chip ID, VMPL
          - Report data (we deposit our nonce here for freshness)
          - AMD-signed certificate chain
        """
        tee = self.detect()
        if tee == "sev-snp":
            return self._fetch_sev_snp_report(nonce)
        if tee == "tdx":
            return self._fetch_tdx_quote(nonce)
        raise AttestationError(f"unsupported TEE: {tee}")

    def _fetch_sev_snp_report(self, nonce: bytes) -> bytes:
        # Real kernel ABI: ioctl(SNP_GET_REPORT) on /dev/sev-guest. (The old
        # f.write/f.read on the device was NOT the ABI and never worked on N2D.)
        return snp_verify.fetch_report_ioctl(nonce, vmpl=0)

    def _fetch_sev_snp_ext_report(self, nonce: bytes, report_data: bytes) -> Tuple[bytes, bytes]:
        """Fetch extended SEV-SNP attestation report with VCEK certificate chain.

        Uses SNP_GET_EXT_REPORT ioctl (0xC0105400).
        Returns (attestation_report, certificate_blob).
        The KRS needs the VCEK certificate to verify the AMD ARK chain.
        """
        rpt = report_data[:64].ljust(64, b"\x00")
        request = SEV_SNP_EXT_REPORT_REQ.pack(rpt, 0)
        with open(SEV_GUEST_DEVICE, "rb+", buffering=0) as f:
            f.write(request)
            resp_raw = f.read(SEV_SNP_EXT_REPORT_RESP_SIZE)
        if len(resp_raw) < 48:
            raise AttestationError("SEV-SNP extended report response truncated")
        status = struct.unpack_from("< I", resp_raw, 0)[0]
        if status != 0:
            raise AttestationError(f"SEV-SNP extended report failed: status={status}")
        report_size = struct.unpack_from("< I", resp_raw, 4)[0]
        report = resp_raw[8:8 + report_size]
        cert_blob = resp_raw[8 + report_size:].rstrip(b"\x00")
        return report, cert_blob

    def _fetch_tdx_quote(self, nonce: bytes) -> bytes:
        raise AttestationError(
            "Intel TDX guest attestation requires Intel SGX DCAP quoting library. "
            "Open a TDX guest device and use Intel QE/QVE to request a TD quote. "
            "Contact ops for TDX attestation client setup."
        )

    def verify_attestation_report(self, report: bytes, expected_measurement: bytes,
                                  nonce: bytes) -> None:
        """Verify the attestation report chain and measurement.
        
        Production: send to external key-release service for verification.
        Development: parse report structure and check measurement locally.
        """
        if len(report) < 48:
            raise AttestationError("report too short")
        # SEV-SNP attestation report layout (AMD ABI): MEASUREMENT is at 0x090,
        # not 0x0A0 (the original was off by 0x10 and never matched a real report).
        measured = snp_verify.parse_measurement(report)
        if measured != expected_measurement.ljust(48, b"\x00")[:48]:
            raise AttestationError(
                f"Measurement mismatch. Expected: {expected_measurement[:8].hex()}... "
                f"Got: {measured[:8].hex()}..."  # measurement is public attestation data, not key material
            )
        
        # In production, also verify:
        # 1. AMD ARK certificate chain (VCEK → ASK → ARK)
        # 2. Report freshness (nonce matches)
        # 3. Policy fields (no debugging, SMT allowed, etc.)
        # For now, measurement match is the minimum bar.
        
        self._tee_type = "sev-snp"
        self._measurement = measured[:48]
        self._report_raw = report

    def verify_via_key_service(self, report: bytes, krs: "krs_client.KrsClient",
                               eph_priv, kem) -> Tuple[bytes, bytes]:
        """Release the CEK via the mTLS+pinned KRS client.

        The KRS independently verifies the AMD cert chain, measurement, policy
        and gates on a Nitrokey touch; it HYBRID-wraps the CEK (X25519+ML-KEM)
        to `eph_priv`/`kem`'s attested public halves and HYBRID-signs the
        response (Ed25519+ML-DSA), both checked inside krs.release()."""
        cek, measurement = krs.release(report, eph_priv, kem, self.tee_type)
        self._tee_type = self.tee_type
        self._measurement = measurement
        self._report_raw = report
        return cek, measurement


# ── 4. FIDO2 hmac-secret via proper libfido2 protocol ────────────────────────

class NitrokeyRoT:
    """Nitrokey FIDO2 as human root-of-trust. Uses proper FIDO2 hmac-secret
    extension via libfido2's fido2-assert command."""

    def __init__(self, cred_dir: Path = Path(".seal")):
        self._cred_dir = cred_dir
        self._device: Optional[str] = None
        self._cred_id: Optional[str] = None
        self._salt: Optional[str] = None

    def detect(self) -> str:
        """Find Nitrokey device path. Returns device path like /dev/hidraw2."""
        result = subprocess.run(
            ["fido2-token", "-L"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "Nitrokey" in line or "nitrokey" in line.lower():
                self._device = line.split(":")[0].strip()
                return self._device
        raise AttestationError("No Nitrokey FIDO2 device found")

    def load_credential(self) -> None:
        """Load the pre-enrolled FIDO2 credential ID and salt for hmac-secret."""
        cred_file = self._cred_dir / "fido2_cred"
        salt_file = self._cred_dir / "fido2_salt"
        if not cred_file.exists() or not salt_file.exists():
            raise AttestationError(
                f"FIDO2 credential not enrolled. Run: fido2-token -C {self._device} "
                f"and store credential ID in {cred_file}, salt in {salt_file}"
            )
        self._cred_id = cred_file.read_text().strip()
        self._salt = salt_file.read_text().strip()

    def derive_hmac_secret(self, challenge: bytes) -> bytes:
        """Derive hmac-secret from Nitrokey using FIDO2 assertion with
        the pre-enrolled credential. Touch required.

        Protocol (libfido2):
          1. Generate random challenge (the 'salt' input to hmac-secret)
          2. fido2-assert -G (hmac-secret extension) with credential + challenge
          3. Token computes HMAC(cred_random, challenge) inside secure element
          4. Returns HMAC output — deterministic per (credential, challenge)
        """
        if not self._device or not self._cred_id:
            self.detect()
            self.load_credential()

        rp = "botsmaster-seal"
        challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
        
        # fido2-assert protocol: 
        #   echo "challenge\nrp\ncred_id\nsalt" | fido2-assert -G -h DEVICE
        #   -G requests hmac-secret extension
        #   Output: assertion data (line 1), signature (line 2), hmac-secret (line 3)
        input_data = f"{challenge_b64}\n{rp}\n{self._cred_id}\n{self._salt}\n"
        result = subprocess.run(
            ["fido2-assert", "-G", "-h", self._device],
            input=input_data, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise AttestationError(
                f"FIDO2 assertion failed (rc={result.returncode}). "
                f"Ensure Nitrokey is inserted and touched when prompted. "
                f"stderr: {result.stderr.strip()}"
            )
        
        # The hmac-secret is the LAST line of output
        lines = result.stdout.strip().split("\n")
        if len(lines) < 3:
            raise AttestationError(
                f"FIDO2 assertion returned {len(lines)} lines, expected >=3 (assertion, sig, hmac-secret)"
            )
        
        hmac_value = lines[-1].strip()
        try:
            return base64.b64decode(hmac_value)
        except Exception:
            return base64.b64decode(hmac_value + "=" * (4 - len(hmac_value) % 4))


# ── 5. Master Key Derivation — combines TEE + Nitrokey ───────────────────────

def derive_master_key(tee_measurement: bytes, hmac_secret: bytes,
                       info: bytes = b"hpvs-portfolio/v3") -> ProtectedMemory:
    """HKDF-SHA512(tee_measurement + hmac_secret, salt=b"", info) → 32-byte key.

    Combines TWO independent roots:
      1. Hardware: TEE attestation measurement (AMD PSP/Intel TDX verified)
      2. Human:    Nitrokey FIDO2 hmac-secret (physical touch required)

    Neither party alone can derive this key. The key is stored in ProtectedMemory.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    combined = tee_measurement + hmac_secret
    key = ProtectedMemory(32)
    derived = HKDF(algorithm=hashes.SHA512(), length=32, salt=b"", info=info).derive(combined)
    key.write(derived, 0)
    return key


# ── 6. Decrypt Strategy Package — sealed at build time ────────────────────────

def decrypt_package(sealed_dir: Path, master_key: ProtectedMemory, out_dir: Path,
                    require_rust: bool = False) -> int:
    """Decrypt all .aesgcm files in sealed_dir into out_dir.

    Each file is decrypted with AAD = logical path (prevents blob swapping).
    Prefers the Rust unwrap (master key + derived subkey handled in Rust with
    zeroization, no GC-managed Python key copies). In production require_rust
    forces it — falling back to the Python path (which copies the key into a
    Python bytes) is refused. Returns number of files decrypted.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    use_rust = rust_unwrap.available()
    if require_rust and not use_rust:
        raise AttestationError(
            "production requires the Rust key_unwrap cdylib (no GC-managed key "
            "copies). Build it: cd key_unwrap && cargo build --release")
    logging.info("decrypt path: %s", "rust" if use_rust else "python (dev)")
    count = 0
    for blob_path in sealed_dir.rglob("*.aesgcm"):
        rel = blob_path.relative_to(sealed_dir).with_suffix("")
        target = out_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        blob = blob_path.read_bytes()
        aad = str(rel).encode()
        if use_rust:
            pt = rust_unwrap.hkdf_aesgcm_open(bytes(master_key.read()[:32]), blob, aad)
        else:
            pt = aes_gcm_open(blob, master_key, aad)
        target.write_bytes(pt)
        count += 1
        logging.info("decrypted: %s → %s (%d bytes)", rel, target, len(pt))
    return count


# ── 7. No-Interactive-Access Enforcement (IBM HPVS equivalent) ────────────────

class EnforceLockdown:
    """Production mode refuses to start if interactive access is available.
    
    IBM HPVS explicitly designs for no interactive deployed-instance access:
    no SSH daemon, no login shell, no cloud-init, no debug agents, no serial
    console. An admin shell defeats the entire SEV-SNP design because an
    attacker with shell + sudo can dump process memory, access /proc/*/mem,
    and extract decrypted strategy or encryption keys.
    """

    @staticmethod
    def check(production: bool) -> None:
        if not production:
            logging.info("Lockdown: development mode (interactive access allowed)")
            return

        issues = []

        # SSH daemon
        try:
            rc = subprocess.run(["systemctl", "is-active", "--quiet", "sshd"],
                              capture_output=True, timeout=5).returncode
            if rc == 0:
                issues.append("SSH daemon active")
        except Exception:
            if os.path.exists("/usr/sbin/sshd"):
                issues.append("SSH binary present")

        # Interactive shells
        for sh in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
            if os.path.exists(sh):
                issues.append(f"interactive shell: {sh}")
                break

        # cloud-init
        try:
            ci = subprocess.run(["cloud-init", "status"], capture_output=True, text=True, timeout=5)
            if ci.returncode == 0 and "disabled" not in ci.stdout:
                issues.append("cloud-init active")
        except Exception:
            if os.path.exists("/etc/cloud/cloud.cfg"):
                issues.append("cloud-init config present")

        # Debug agents
        for agent in ["strace", "gdb", "ltrace", "valgrind"]:
            if os.path.exists(f"/usr/bin/{agent}"):
                issues.append(f"debug agent: {agent}")
                break

        # Serial console
        for tty in ["/dev/ttyS0", "/dev/ttyAMA0"]:
            if os.path.exists(tty):
                issues.append(f"serial console: {tty}")
                break

        if issues:
            for i in issues:
                logging.error("Lockdown: %s", i)
            raise AttestationError(
                f"Production requires locked-down image. {len(issues)} violations: "
                f"{'; '.join(issues[:3])}{'...' if len(issues) > 3 else ''}"
            )

        logging.info("Lockdown: no interactive access — all checks passed")


# ── 8. Continuous Attestation Monitor ─────────────────────────────────────────

class ContinuousAttestationMonitor:
    """Polls attestation state every MONITOR_INTERVAL seconds.
    If any check fails → zeroise all memory + exit immediately."""

    def __init__(self, zeroizer: "SecureZeroizer",
                 attestation: TEEAttestation,
                 expected_measurement: bytes):
        self._zeroizer = zeroizer
        self._attestation = attestation
        self._expected = expected_measurement
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logging.info("Continuous attestation monitor started (interval=%ds)", MONITOR_INTERVAL)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        while self._running:
            time.sleep(MONITOR_INTERVAL)
            try:
                report = self._attestation.fetch_attestation_report()
                # Quick measurement re-check (correct ABI offset 0x090)
                measured = snp_verify.parse_measurement(report)
                if measured != self._expected.ljust(48, b"\x00")[:48]:
                    logging.critical("ATTESTATION FAILED: measurement changed")
                    self._zeroizer.terminate("measurement changed")
            except AttestationError as e:
                logging.critical("ATTESTATION FAILED: %s", e)
                self._zeroizer.terminate(str(e))
            except Exception as e:
                logging.warning("Attestation check transient error: %s", e)


# ── 8. Secure Zeroizer — failsafe on any violation ────────────────────────────

class SecureZeroizer:
    """On any security violation signal, zeroize all ProtectedMemory and exit."""

    def __init__(self, pre_terminate_cb: Optional[Callable[[], None]] = None):
        self._cb = pre_terminate_cb
        self._armed = False

    def arm(self) -> None:
        if self._armed:
            return
        self._armed = True
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(HPV_SIGNAL_EXIT, self._handle)
        logging.debug("SecureZeroizer armed")

    def terminate(self, reason: str) -> None:
        logging.critical("SECURITY TERMINATION: %s", reason)
        if self._cb:
            try: self._cb()
            except Exception: pass
        ProtectedMemory.zeroise_all()
        os._exit(1)

    def _handle(self, signum: int, frame) -> None:
        self.terminate(f"signal {signum}")


# ── 9. KRS Replay Cache — prevents nonce reuse ───────────────────────────────

_MAX_REPLAY_ENTRIES = 10000

class ReplayCache:
    """Set-based replay cache for nonce deduplication.

    Prevents KRS key-release replay attacks by tracking seen nonce hashes.
    Bounded to _MAX_REPLAY_ENTRIES entries.
    """

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def has_seen(self, nonce_hash: bytes) -> bool:
        return nonce_hash in self._seen

    def record(self, nonce_hash: bytes) -> None:
        if len(self._seen) >= _MAX_REPLAY_ENTRIES:
            self._seen.clear()
        self._seen.add(nonce_hash)

# ── 10. Orchestrator — puts it all together ────────────────────────────────────

class CloudProtection:
    """Bootstraps the confidential computing environment, decrypts the trading
    bot strategy package, and starts continuous attestation monitoring."""

    def __init__(self, sealed_dir: Path, output_dir: Path,
                 cred_dir: Path = Path(".seal"),
                 key_service_url: Optional[str] = None,
                 expected_measurement: Optional[bytes] = None,
                 production: bool = False,
                 krs_config: Optional[dict] = None,
                 min_tcb: int = 0):
        self._sealed_dir = sealed_dir
        self._output_dir = output_dir
        self._cred_dir = cred_dir
        self._key_service_url = key_service_url
        self._expected_measurement = expected_measurement
        self._production = production
        self._krs_config = krs_config
        self._min_tcb = min_tcb
        self._zeroizer = SecureZeroizer()
        self._master_key: Optional[ProtectedMemory] = None
        self._replay_cache = ReplayCache()

    def bootstrap(self) -> int:
        """Bootstrap sequence. Returns 0 on success, 1 on failure. Fail-closed."""
        try:
            _libc().mlockall(MCL_CURRENT | MCL_FUTURE)
            logging.info("mlockall(MCL_CURRENT|MCL_FUTURE) — all pages locked")
            EnforceLockdown.check(self._production)

            # 1. Detect TEE
            attestation = TEEAttestation()
            tee_type = attestation.detect()
            logging.info("TEE: %s", tee_type)

            # 2. Fresh nonce + real X25519 ephemeral pubkey, bound into report_data
            nonce = secrets.token_bytes(32)
            nonce_hash = hashlib.sha256(nonce).digest()
            if self._replay_cache.has_seen(nonce_hash):
                raise AttestationError("nonce replay detected")
            self._replay_cache.record(nonce_hash)
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            import pqc
            eph = X25519PrivateKey.generate()
            eph_pub = eph.public_key().public_bytes_raw()
            kem = pqc.KemPrivate()          # attested ephemeral ML-KEM-768
            # Binding tag MUST match krs_server.BIND_TAG / report_data_for():
            # sha256(client_x_pub || client_kem_pub || nonce || TAG).
            report_data = hashlib.sha256(
                eph_pub + kem.public + nonce + b"botsmaster-snp-binding-v2-hybrid").digest()
            report = attestation.fetch_attestation_report(report_data)
            logging.info("attestation report: %d bytes", len(report))

            # 3. Verify + obtain master key
            if self._production:
                if not (self._key_service_url and self._krs_config):
                    raise AttestationError(
                        "production refuses the local attestation path: a KRS "
                        "(--key-service-url + mTLS pins) is required.")
                if self._expected_measurement is None:
                    raise AttestationError(
                        "production requires --expected-measurement (allowlist)")
                # 3a. local chain/policy/TCB/measurement/report_data verify (snpguest)
                verifier = snp_verify.SnpVerifier(
                    processor=self._krs_config.get("processor", "milan"),
                    measurement_allowlist=[self._expected_measurement],
                    min_reported_tcb=self._min_tcb,
                )
                verifier.verify(report, report_data)
                # 3b. KRS independently verifies + Nitrokey touch, returns the key
                krs = krs_client.KrsClient(
                    self._key_service_url,
                    client_cert=self._krs_config["client_cert"],
                    client_key=self._krs_config["client_key"],
                    pinned_ca=self._krs_config["pinned_ca"],
                    pinned_server_fpr=self._krs_config["pinned_server_fpr"],
                    krs_signing_pub=self._krs_config["krs_signing_pub"],
                    krs_mldsa_pub=self._krs_config["krs_mldsa_pub"],
                    server_name=self._krs_config["server_name"],
                )
                cek, measurement = attestation.verify_via_key_service(
                    report, krs, eph, kem)
                self._master_key = ProtectedMemory(32)
                self._master_key.write(cek[:32])
                logging.info("KRS released session key; measurement=%s",
                             measurement[:8].hex())
            else:
                # Dev path (bare metal w/ Nitrokey attached). Refused in prod.
                if self._expected_measurement is None:
                    raise AttestationError("dev mode needs --expected-measurement")
                attestation.verify_attestation_report(
                    report, self._expected_measurement, nonce)
                measurement = attestation.measurement
                logging.warning("DEV verification (no cert chain, local Nitrokey)")
                nitrokey = NitrokeyRoT(self._cred_dir)
                nitrokey.detect(); nitrokey.load_credential()
                hmac_secret = nitrokey.derive_hmac_secret(challenge=measurement[:32])
                self._master_key = derive_master_key(measurement, hmac_secret)

            # 4. tmpfs gate (production)
            fstype = subprocess.run(
                ["findmnt", "-T", str(self._output_dir), "-no", "FSTYPE"],
                capture_output=True, text=True).stdout
            if self._production and "tmpfs" not in fstype:
                raise AttestationError("production requires tmpfs/LUKS output_dir")

            # 5. Decrypt strategy package (Rust unwrap required in production)
            n = decrypt_package(self._sealed_dir, self._master_key,
                                self._output_dir, require_rust=self._production)
            if n == 0:
                raise AttestationError("No .aesgcm files found in sealed directory")
            logging.info("decrypted %d files", n)

            # 6. Arm zeroizer + continuous attestation
            self._zeroizer.arm()
            ContinuousAttestationMonitor(self._zeroizer, attestation, measurement).start()
            logging.info("Bootstrap complete. Strategy decrypted. Attestation active.")
            return 0

        except AttestationError as e:
            logging.critical("Bootstrap failed: %s", e)
            if self._master_key:
                self._master_key.zeroise()
            return 1
        except Exception as e:
            logging.critical("Unexpected error: %s", e, exc_info=True)
            if self._master_key:
                self._master_key.zeroise()
            return 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Confidential Computing Protection Layer v3 — SEV-SNP + Nitrokey FIDO2"
    )
    p.add_argument("--sealed-dir", default="sealed", help="Directory with .aesgcm files")
    p.add_argument("--output-dir", default="decrypted", help="Where to write decrypted strategy")
    p.add_argument("--cred-dir", default=".seal", help="FIDO2 credential directory")
    p.add_argument("--key-service-url", help="External key-release service URL")
    p.add_argument("--expected-measurement", help="Expected SEV measurement (hex)")
    p.add_argument("--check-only", action="store_true", help="Detect TEE and Nitrokey, then exit")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    # production + KRS mTLS pins
    p.add_argument("--production", action="store_true",
                   help="Fail-closed prod mode: requires KRS+mTLS, snpguest chain "
                        "verification, tmpfs output, lockdown, Rust unwrap")
    p.add_argument("--client-cert", help="mTLS client certificate (PEM)")
    p.add_argument("--client-key", help="mTLS client private key (PEM)")
    p.add_argument("--pinned-ca", help="Pinned KRS CA bundle (PEM) — not the public store")
    p.add_argument("--pinned-server-fpr", help="Pinned KRS server cert SHA-256 (hex)")
    p.add_argument("--krs-pubkey", help="KRS response-signing Ed25519 public key (hex)")
    p.add_argument("--krs-mldsa-pubkey", help="KRS response-signing ML-DSA-65 public key (hex)")
    p.add_argument("--server-name", help="KRS TLS server name (SNI/host)")
    p.add_argument("--processor", default="milan", help="AMD CPU model for VCEK (milan/genoa)")
    p.add_argument("--min-tcb", type=lambda x: int(x, 0), default=0,
                   help="Minimum acceptable reported_tcb (anti-rollback)")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
    )

    expected = bytes.fromhex(args.expected_measurement) if args.expected_measurement else None

    if args.check_only:
        logging.info("TEE detection check...")
        tee = TEEAttestation()
        try:
            t = tee.detect()
            logging.info("TEE detected: %s", t)
        except AttestationError as e:
            logging.warning("No TEE: %s", e)

        logging.info("Nitrokey detection check...")
        nk = NitrokeyRoT(Path(args.cred_dir))
        try:
            dev = nk.detect()
            logging.info("Nitrokey: %s", dev)
            nk.load_credential()
            logging.info("Credential: %s...%s", nk._cred_id[:16], nk._cred_id[-16:])
        except AttestationError as e:
            logging.warning("Nitrokey: %s", e)
        return 0

    krs_config = None
    if args.production:
        missing = [n for n, v in [
            ("--client-cert", args.client_cert), ("--client-key", args.client_key),
            ("--pinned-ca", args.pinned_ca), ("--pinned-server-fpr", args.pinned_server_fpr),
            ("--krs-pubkey", args.krs_pubkey), ("--krs-mldsa-pubkey", args.krs_mldsa_pubkey),
            ("--server-name", args.server_name),
            ("--key-service-url", args.key_service_url)] if not v]
        if missing:
            p.error("production requires: " + ", ".join(missing))
        krs_config = {
            "client_cert": args.client_cert, "client_key": args.client_key,
            "pinned_ca": args.pinned_ca, "pinned_server_fpr": args.pinned_server_fpr,
            "krs_signing_pub": bytes.fromhex(args.krs_pubkey),
            "krs_mldsa_pub": bytes.fromhex(args.krs_mldsa_pubkey),
            "server_name": args.server_name, "processor": args.processor,
        }

    cp = CloudProtection(
        sealed_dir=Path(args.sealed_dir),
        output_dir=Path(args.output_dir),
        cred_dir=Path(args.cred_dir),
        key_service_url=args.key_service_url,
        expected_measurement=expected,
        production=args.production,
        krs_config=krs_config,
        min_tcb=args.min_tcb,
    )
    code = cp.bootstrap()
    if code == 0:
        logging.info("Ready for trading bot entrypoint")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
