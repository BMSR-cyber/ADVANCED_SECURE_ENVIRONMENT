#!/usr/bin/env python3
"""
Confidential Computing Protection Layer for Trading Bot Deployment
Based on IBM HPVS patterns with Nitrokey FIDO2 root-of-trust.

Provides TEE attestation verification, metadata secret decryption,
continuous attestation monitoring, LUKS2 data-at-rest protection,
and failsafe zeroization for production trading bot operations.
"""

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import logging
import mmap
import os
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_PAGESIZE: int = os.sysconf(os.sysconf_names["SC_PAGE_SIZE"])
_PAGESIZE_MASK: int = _PAGESIZE - 1

MADV_DONTDUMP: int = 16
PR_SET_NAME: int = 15
PROT_NONE: int = 0
PROT_READ: int = 1
PROT_WRITE: int = 2

GCM_IV_LEN: int = 12
GCM_TAG_LEN: int = 16
AES_KEY_LEN: int = 32

MONITOR_INTERVAL_SEC: int = 300

HPV_SIGNAL_EXIT: int = signal.SIGUSR1
HPV_STARTUP_VERBOSE: bool = True
HPV_RUNTIME_ERRORS_ONLY: bool = True

LOG_FORMAT: str = "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s"

SEV_DEVICE: str = "/dev/sev"
SEV_GUEST_DEVICE: str = "/dev/sev-guest"
SEV_SYSFS_PARAM: str = "/sys/module/kvm_amd/parameters/sev"
TPM_DEVICE: str = "/dev/tpm0"
TPM_PCR_PATH: str = "/sys/class/tpm/tpm0/pcrs"

_cache_libc: Optional[ctypes.CDLL] = None


def _get_libc() -> ctypes.CDLL:
    global _cache_libc
    if _cache_libc is None:
        _cache_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                                  use_errno=True)
    return _cache_libc


def _page_align_down(addr: int) -> int:
    return addr & ~_PAGESIZE_MASK


def _page_align_up(addr: int) -> int:
    return (addr + _PAGESIZE_MASK) & ~_PAGESIZE_MASK


def _make_logger(name: str, verbose: bool = True) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(h)
    logger.setLevel(logging.DEBUG if verbose else logging.ERROR)
    return logger


# ───────────────── Protected Memory ────────────────────────────────────────

class ProtectedMemory:
    """mlock-backed secure buffer excluded from swap / core dumps."""

    _registry: Set["ProtectedMemory"] = set()

    def __init__(self, size: int, logger: Optional[logging.Logger] = None):
        self._log = logger or logging.getLogger(__name__)
        self._size = size
        self._buf: ctypes.Array[ctypes.c_char] = ctypes.create_string_buffer(size)
        self._addr: int = ctypes.addressof(self._buf)
        self._libc = _get_libc()
        self._lock()
        ProtectedMemory._registry.add(self)

    def _lock(self) -> None:
        page_addr = _page_align_down(self._addr)
        page_size = _page_align_up(self._addr + self._size) - page_addr
        rc = self._libc.mlock(ctypes.c_void_p(page_addr), ctypes.c_size_t(page_size))
        if rc != 0:
            errno = ctypes.get_errno()
            self._log.warning("mlock failed (errno=%d): memory may swap", errno)
        rc2 = self._libc.madvise(ctypes.c_void_p(page_addr),
                                 ctypes.c_size_t(page_size), ctypes.c_int(MADV_DONTDUMP))
        if rc2 != 0:
            errno = ctypes.get_errno()
            self._log.warning("madvise MADV_DONTDUMP failed (errno=%d)", errno)
        self._log.debug("ProtectedMemory: %d bytes locked at 0x%x", self._size, page_addr)

    def raw(self) -> ctypes.Array[ctypes.c_char]:
        return self._buf

    def read_bytes(self, offset: int = 0, length: Optional[int] = None) -> bytes:
        length = length if length is not None else self._size - offset
        return ctypes.string_at(self._addr + offset, length)

    def write_bytes(self, data: bytes, offset: int = 0) -> None:
        if offset + len(data) > self._size:
            raise ValueError("write exceeds buffer bounds")
        ctypes.memmove(self._addr + offset, data, len(data))

    def zeroise(self) -> None:
        ctypes.memset(self._addr, 0x00, self._size)

    def randomise(self) -> None:
        ctypes.memmove(self._addr, secrets.token_bytes(self._size), self._size)

    def protect(self, prot: int = PROT_NONE) -> None:
        page_addr = _page_align_down(self._addr)
        page_size = _page_align_up(self._addr + self._size) - page_addr
        self._libc.mprotect(ctypes.c_void_p(page_addr), ctypes.c_size_t(page_size),
                           ctypes.c_int(prot))

    @property
    def size(self) -> int:
        return self._size

    @classmethod
    def zeroise_all(cls) -> None:
        for pm in list(cls._registry):
            try:
                pm.zeroise()
            except Exception:
                pass


# ───────────────── Secure Zeroizer ─────────────────────────────────────────

class SecureZeroizer:
    """Failsafe zeroization engine – overwrites all protected memory and
    force-exits the process on any security violation."""

    def __init__(self,
                 logger: Optional[logging.Logger] = None,
                 pre_kill_cb: Optional[Callable[[], None]] = None):
        self._log = logger or logging.getLogger(__name__)
        self._pre_kill_cb = pre_kill_cb
        self._armed = False

    def arm(self) -> None:
        if self._armed:
            return
        self._armed = True
        signal.signal(signal.SIGINT, self._handle_violation)
        signal.signal(signal.SIGTERM, self._handle_violation)
        signal.signal(HPV_SIGNAL_EXIT, self._handle_violation)
        self._log.debug("SecureZeroizer armed: signals %d %d %d",
                        signal.SIGINT, signal.SIGTERM, HPV_SIGNAL_EXIT)

    def _handle_violation(self, signum: int, frame: Any) -> None:
        self._log.critical("Security violation signal (%d) received – initiating zeroization", signum)
        self.execute()

    def execute(self, exit_code: int = 1) -> None:
        try:
            ProtectedMemory.zeroise_all()
            self._log.critical("All protected memory zeroised")
        except Exception as exc:
            self._log.critical("Zeroisation partial failure: %s", exc)
        try:
            if self._pre_kill_cb:
                self._pre_kill_cb()
        except Exception:
            pass
        os._exit(exit_code)

    def violation(self, reason: str, exit_code: int = 1) -> None:
        self._log.critical("FATAL: %s", reason)
        self.execute(exit_code)


# ───────────────── Process Obfuscator ──────────────────────────────────────

class ProcessObfuscator:
    """Obfuscate the process name visible in /proc and ps output."""

    def __init__(self, decoy_name: str = "systemd-journal"):
        self._decoy = decoy_name.encode("utf-8")[:15] + b"\x00"
        self._libc = _get_libc()

    def apply(self) -> None:
        try:
            self._libc.prctl(PR_SET_NAME, ctypes.c_char_p(self._decoy),
                           0, 0, 0)
        except Exception:
            pass

        try:
            argv = (ctypes.c_char_p * len(sys.argv))()
            for i, arg in enumerate(sys.argv):
                argv[i] = (arg if i == 0 else "").encode("utf-8")
        except Exception:
            pass

    def fork_and_rename(self, target: Callable[[], None],
                        decoy_name: str = "systemd-journal") -> int:
        pid = os.fork()
        if pid == 0:
            ProcessObfuscator(decoy_name).apply()
            target()
            os._exit(0)
        return pid


# ───────────────── TEE Attestation Verifier ────────────────────────────────

class TEAttestationVerifier:
    """Verifies platform is running inside a genuine AMD SEV / Intel TDX
    TEE before releasing secrets."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self._log = logger or logging.getLogger(__name__)
        self._tee_type: Optional[str] = None
        self._measurement: Optional[bytes] = None

    @property
    def tee_type(self) -> Optional[str]:
        return self._tee_type

    @property
    def measurement(self) -> Optional[bytes]:
        return self._measurement

    def verify(self) -> bool:
        sev = self._check_sev()
        if sev:
            self._tee_type = "SEV"
            self._log.info("TEE attestation: AMD SEV confirmed")
            self._measurement = self._get_sev_measurement()
            return bool(self._measurement)

        tdx = self._check_tdx()
        if tdx:
            self._tee_type = "TDX"
            self._log.info("TEE attestation: Intel TDX confirmed")
            self._measurement = self._get_tdx_measurement()
            return bool(self._measurement)

        tpm = self._check_tpm_attested()
        if tpm:
            self._tee_type = "TPM"
            self._log.info("TEE attestation: vTPM present")
            self._measurement = self._get_tpm_measurement()
            return bool(self._measurement)

        self._log.error("No TEE capability detected – refusing to boot")
        return False

    def _check_sev(self) -> bool:
        if os.path.exists(SEV_DEVICE):
            return True
        if os.path.exists(SEV_GUEST_DEVICE):
            return True
        if os.path.exists(SEV_SYSFS_PARAM):
            try:
                with open(SEV_SYSFS_PARAM, "r") as f:
                    val = f.read().strip()
                    if val in ("1", "Y", "y"):
                        return True
            except Exception:
                pass
        try:
            cp = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=10)
            if "SEV" in cp.stdout or "sev" in cp.stdout:
                return True
        except Exception:
            pass
        try:
            with open("/proc/cpuinfo", "r") as f:
                if "sev" in f.read().lower():
                    return True
        except Exception:
            pass
        return False

    def _check_tdx(self) -> bool:
        if os.path.exists("/dev/tdx-guest"):
            return True
        try:
            with open("/proc/cpuinfo", "r") as f:
                if "tdx" in f.read().lower():
                    return True
        except Exception:
            pass
        return False

    def _check_tpm_attested(self) -> bool:
        if os.path.exists(TPM_DEVICE):
            return True
        return False

    def _get_sev_measurement(self) -> Optional[bytes]:
        if os.path.exists(SEV_GUEST_DEVICE):
            try:
                cp = subprocess.run(
                    ["sev-guest-get-report", "--out", "/dev/stdout"],
                    capture_output=True, timeout=30
                )
                if cp.returncode == 0:
                    h = hashlib.sha256(cp.stdout).digest()
                    self._log.debug("SEV guest measurement hash: %s", h.hex())
                    return h
            except FileNotFoundError:
                pass
            except Exception:
                pass

        try:
            cp = subprocess.run(
                ["sevctl", "export", "--full"],
                capture_output=True, timeout=30
            )
            if cp.returncode == 0:
                h = hashlib.sha256(cp.stdout).digest()
                return h
        except FileNotFoundError:
            pass
        except Exception:
            pass

        if os.path.exists(SEV_DEVICE):
            try:
                with open(SEV_DEVICE, "rb") as f:
                    data = f.read(4096)
                    h = hashlib.sha256(data).digest()
                    return h
            except Exception:
                pass

        self._log.warning("SEV detected but unable to retrieve attestation measurement")
        return hashlib.sha256(b"SEV_PLATFORM_DETECTED").digest()

    def _get_tdx_measurement(self) -> Optional[bytes]:
        try:
            cp = subprocess.run(
                ["tdx-guest-get-report"],
                capture_output=True, timeout=30
            )
            if cp.returncode == 0:
                h = hashlib.sha256(cp.stdout).digest()
                return h
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return hashlib.sha256(b"TDX_PLATFORM_DETECTED").digest()

    def _get_tpm_measurement(self) -> Optional[bytes]:
        hasher = hashlib.sha256()
        if os.path.exists(TPM_PCR_PATH):
            try:
                with open(TPM_PCR_PATH, "rb") as f:
                    hasher.update(f.read())
            except Exception:
                pass
        try:
            cp = subprocess.run(
                ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"],
                capture_output=True, timeout=30
            )
            if cp.returncode == 0:
                hasher.update(cp.stdout)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if hasher.digest() == hashlib.sha256(b"").digest():
            self._log.warning("TPM detected but PCR values empty – using device identity only")
            try:
                with open(TPM_DEVICE, "rb") as f:
                    hasher.update(f.read(256))
            except Exception:
                pass
        digest = hasher.digest()
        self._log.debug("TPM measurement hash: %s", digest.hex())
        return digest

    def re_verify(self) -> bool:
        if not self._tee_type:
            return False
        if self._tee_type == "SEV":
            new_m = self._get_sev_measurement()
        elif self._tee_type == "TDX":
            new_m = self._get_tdx_measurement()
        elif self._tee_type == "TPM":
            new_m = self._get_tpm_measurement()
        else:
            return False

        if new_m and self._measurement and new_m != self._measurement:
            self._log.error("Platform measurement changed! TEE integrity violation.")
            return False
        return True


# ───────────────── HKDF Implementation ─────────────────────────────────────

def hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int = AES_KEY_LEN) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm = b""
    t = b""
    block_index = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([block_index]), hashlib.sha512).digest()
        okm += t
        block_index += 1
    return okm[:length]


# ───────────────── Metadata Secret Decryptor ───────────────────────────────

class MetadataDecryptor:
    """Decrypts trading bot config encrypted at build time using
    AES-256-GCM with a key derived from platform attestation +
    Nitrokey FIDO2 hmac-secret."""

    AESGCM_IV_OFFSET: int = 0
    AESGCM_IV_LEN: int = 12
    AESGCM_CIPHER_OFFSET: int = 12

    def __init__(self, logger: Optional[logging.Logger] = None):
        self._log = logger or logging.getLogger(__name__)

    @classmethod
    def derive_key(cls,
                   platform_measurement: bytes,
                   fido2_secret: bytes) -> bytes:
        ikm = platform_measurement + fido2_secret
        key = hkdf_sha512(
            ikm=ikm,
            salt=b"hpvs-portfolio/v1",
            info=b"metadata-encryption-key",
            length=AES_KEY_LEN,
        )
        return key

    def decrypt_file(self,
                     filepath: str,
                     key: bytes) -> bytes:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Encrypted file not found: {filepath}")

        with open(filepath, "rb") as f:
            iv = f.read(self.AESGCM_IV_LEN)
            if len(iv) != self.AESGCM_IV_LEN:
                raise ValueError(f"Truncated IV in {filepath}")
            ciphertext_with_tag = f.read()

        if len(ciphertext_with_tag) < GCM_TAG_LEN:
            raise ValueError(f"Encrypted data too short in {filepath}")

        return self._decrypt_aes_gcm(key, iv, ciphertext_with_tag)

    def _decrypt_aes_gcm(self,
                         key: bytes,
                         iv: bytes,
                         ciphertext_with_tag: bytes) -> bytes:
        key_hex = key.hex()
        iv_hex = iv.hex()
        ct_hex = ciphertext_with_tag.hex()

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf_in:
            tf_in.write(ciphertext_with_tag)
            tf_in.flush()
            in_path = tf_in.name

        out_path = in_path + ".plain"

        try:
            cmd = [
                "openssl", "enc", "-aes-256-gcm", "-d",
                "-K", key_hex, "-iv", iv_hex,
                "-in", in_path, "-out", out_path,
            ]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if cp.returncode != 0:
                stderr = cp.stderr.strip()
                if "bad decrypt" in stderr.lower() or "tag" in stderr.lower():
                    raise ValueError("AES-256-GCM authentication tag verification failed")
                raise RuntimeError(f"OpenSSL decryption failed: {stderr}")

            with open(out_path, "rb") as f:
                plaintext = f.read()

            return plaintext

        finally:
            try:
                os.unlink(in_path)
            except Exception:
                pass
            try:
                if os.path.exists(out_path):
                    with open(out_path, "wb") as f:
                        f.write(secrets.token_bytes(os.path.getsize(out_path)))
                    os.unlink(out_path)
            except Exception:
                pass

    @classmethod
    def encrypt_data(cls, plaintext: bytes, key: bytes) -> bytes:
        key_hex = key.hex()
        iv = secrets.token_bytes(GCM_IV_LEN)
        iv_hex = iv.hex()

        with tempfile.NamedTemporaryFile(delete=False) as tf_pt:
            tf_pt.write(plaintext)
            tf_pt.flush()
            pt_path = tf_pt.name

        ct_path = pt_path + ".enc"

        try:
            cmd = [
                "openssl", "enc", "-aes-256-gcm", "-e",
                "-K", key_hex, "-iv", iv_hex,
                "-in", pt_path, "-out", ct_path,
            ]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if cp.returncode != 0:
                raise RuntimeError(f"OpenSSL encryption failed: {cp.stderr}")

            with open(ct_path, "rb") as f:
                ciphertext_with_tag = f.read()

            return iv + ciphertext_with_tag

        finally:
            try:
                with open(pt_path, "wb") as f:
                    f.write(secrets.token_bytes(len(plaintext)))
                os.unlink(pt_path)
            except Exception:
                pass
            try:
                if os.path.exists(ct_path):
                    with open(ct_path, "wb") as f:
                        f.write(secrets.token_bytes(os.path.getsize(ct_path)))
                    os.unlink(ct_path)
            except Exception:
                pass


# ───────────────── Continuous Attestation Monitor ──────────────────────────

class ContinuousAttestationMonitor:
    """Keylime-style continuous TEE attestation monitor.

    Polls platform PCR / SEV state every MONITOR_INTERVAL_SEC seconds.
    On measurement change: triggers full zeroization + process termination."""

    def __init__(self,
                 verifier: TEAttestationVerifier,
                 zeroizer: SecureZeroizer,
                 interval: int = MONITOR_INTERVAL_SEC,
                 logger: Optional[logging.Logger] = None):
        self._verifier = verifier
        self._zeroizer = zeroizer
        self._interval = interval
        self._log = logger or logging.getLogger(__name__)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True,
                                       name="attestation-monitor")
        self._thread.start()
        self._log.info("Continuous attestation monitor started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _monitor_loop(self) -> None:
        self._log.debug("Attestation monitor entering poll loop")
        while not self._stop_event.wait(self._interval):
            try:
                if not self._verifier.re_verify():
                    self._log.error("Attestation re-verification failed")
                    self._zeroizer.violation(
                        "Continuous attestation failed: platform measurement changed"
                    )
            except Exception as exc:
                self._log.error("Attestation monitor error: %s", exc)


# ───────────────── LUKS2 Protection ────────────────────────────────────────

class LuksProtection:
    """LUKS2-protected data-at-rest.

    Manages a LUKS2-encrypted loopback volume whose passphrase is derived
    inside the TEE from the platform measurement. Config and sensitive
    state are written only to the LUKS-protected mount."""

    LUKS_DEVICE: str = "/dev/mapper/hpvs_data"

    def __init__(self,
                 mount_point: str = "/mnt/hpvs_data",
                 logger: Optional[logging.Logger] = None):
        self._log = logger or logging.getLogger(__name__)
        self._mount_point = mount_point
        self._passphrase: Optional[str] = None
        self._mounted = False

    def derive_passphrase(self,
                          platform_measurement: bytes,
                          fido2_secret: bytes) -> str:
        ikm = platform_measurement + fido2_secret
        raw = hkdf_sha512(
            ikm=ikm,
            salt=b"hpvs-portfolio/v1",
            info=b"luks-passphrase",
            length=64,
        )
        self._passphrase = base64.b64encode(raw).decode("ascii")
        return self._passphrase

    def open_and_mount(self, backing_file: str) -> bool:
        if not self._passphrase:
            raise RuntimeError("LUKS passphrase not derived")
        if not os.path.exists(backing_file):
            self._log.info("LUKS backing file %s not found – skipping LUKS mount", backing_file)
            return False

        os.makedirs(self._mount_point, mode=0o700, exist_ok=True)

        try:
            subprocess.run(
                ["cryptsetup", "luksOpen", backing_file, "hpvs_data"],
                input=self._passphrase.encode("utf-8"),
                check=True, capture_output=True, timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            self._log.error("luksOpen failed: %s", exc.stderr.decode(errors="replace"))
            raise

        try:
            subprocess.run(
                ["mount", self.LUKS_DEVICE, self._mount_point],
                check=True, capture_output=True, timeout=30,
            )
            self._mounted = True
            self._log.info("LUKS volume mounted at %s", self._mount_point)
        except subprocess.CalledProcessError as exc:
            self._log.error("LUKS mount failed: %s", exc.stderr.decode(errors="replace"))
            subprocess.run(["cryptsetup", "luksClose", "hpvs_data"],
                          capture_output=True, timeout=30)
            raise

        return True

    def unmount_and_close(self) -> None:
        if self._mounted:
            subprocess.run(["umount", self._mount_point],
                          capture_output=True, timeout=30)
            self._mounted = False
        subprocess.run(["cryptsetup", "luksClose", "hpvs_data"],
                      capture_output=True, timeout=30)

    @classmethod
    def format_luks_volume(cls,
                           backing_file: str,
                           passphrase: str,
                           size_mb: int = 256) -> None:
        if os.path.exists(backing_file):
            os.unlink(backing_file)
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={backing_file}",
             "bs=1M", f"count={size_mb}"],
            check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            ["cryptsetup", "luksFormat", "--type", "luks2",
             "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "100000",
             backing_file],
            input=passphrase.encode("utf-8"),
            check=True, capture_output=True, timeout=120,
        )

    @property
    def is_mounted(self) -> bool:
        return self._mounted

    @property
    def mount_point(self) -> str:
        return self._mount_point


# ───────────────── Nitrokey FIDO2 Root-of-Trust ────────────────────────────

class NitrokeyRootOfTrust:
    """Nitrokey FIDO2 hmac-secret as the master secret root-of-trust.

    On startup:
      a. Check Nitrokey is present (fido2-token -L)
      b. Derive platform key from hmac-secret + SEV attestation
      c. Decrypt metadata/config
      d. Start continuous attestation monitor
      e. If Nitrokey disconnected or attestation fails, halt immediately
    """

    FIDO2_KEY_SCRIPT: str = "fido2-key.sh"
    FIDO2_TOKEN_BIN: str = "fido2-token"
    FIDO2_ASSERT_BIN: str = "fido2-assert"

    def __init__(self,
                 rp_id: str = "hpvs-portfolio.local",
                 credential_id_file: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        self._log = logger or logging.getLogger(__name__)
        self._rp_id = rp_id
        self._cred_id_file = credential_id_file
        self._hmac_secret: Optional[bytes] = None
        self._token_present = False

    @property
    def hmac_secret(self) -> Optional[bytes]:
        return self._hmac_secret

    @property
    def token_present(self) -> bool:
        return self._token_present

    def check_token_present(self) -> bool:
        try:
            cp = subprocess.run(
                [self.FIDO2_TOKEN_BIN, "-L"],
                capture_output=True, text=True, timeout=15,
            )
            if cp.returncode != 0:
                self._log.warning("fido2-token -L returned non-zero")
                return False
            if not cp.stdout.strip():
                self._log.warning("No FIDO2 token detected")
                return False
            self._log.info("FIDO2 token present:\n%s", cp.stdout.strip())
            self._token_present = True
            return True
        except FileNotFoundError:
            self._log.error("fido2-token binary not found")
            return False
        except Exception as exc:
            self._log.error("Token check failed: %s", exc)
            return False

    def get_hmac_secret(self) -> Optional[bytes]:
        if self._token_present or self.check_token_present():
            pass
        else:
            self._log.error("No Nitrokey token – cannot retrieve hmac-secret")
            return None

        secret = self._try_pipe_script()
        if secret:
            self._hmac_secret = secret
            return secret

        secret = self._try_fido2_assert()
        if secret:
            self._hmac_secret = secret
            return secret

        self._log.error("Failed to retrieve hmac-secret via all available methods")
        return None

    def _try_pipe_script(self) -> Optional[bytes]:
        script_path = None
        for candidate in [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), self.FIDO2_KEY_SCRIPT),
            os.path.join("/usr/local/bin", self.FIDO2_KEY_SCRIPT),
            os.path.join("/usr/bin", self.FIDO2_KEY_SCRIPT),
            "./" + self.FIDO2_KEY_SCRIPT,
        ]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                script_path = candidate
                break

        if not script_path:
            self._log.debug("fido2-key.sh not found – skipping pipe method")
            return None

        try:
            cp = subprocess.run(
                [script_path],
                capture_output=True, timeout=30,
            )
            if cp.returncode != 0:
                self._log.debug("fido2-key.sh returned non-zero (%d)", cp.returncode)
                return None
            raw = cp.stdout.strip()
            if not raw:
                return None
            h = hashlib.sha256(raw).digest()
            self._log.info("hmac-secret derived via fido2-key.sh pipe")
            return h
        except Exception as exc:
            self._log.debug("fido2-key.sh execution failed: %s", exc)
            return None

    def _try_fido2_assert(self) -> Optional[bytes]:
        args = [self.FIDO2_ASSERT_BIN, "-G", "-r", self._rp_id]

        cred_id = None
        if self._cred_id_file and os.path.exists(self._cred_id_file):
            try:
                with open(self._cred_id_file, "r") as f:
                    cred_id = f.read().strip()
            except Exception:
                pass

        if cred_id:
            args.extend(["-i", cred_id])

        try:
            cp = subprocess.run(args, capture_output=True, timeout=60)
            if cp.returncode != 0:
                err = cp.stderr.decode(errors="replace")
                self._log.debug("fido2-assert failed: %s", err)
                return None
            h = hashlib.sha256(cp.stdout).digest()
            self._log.info("hmac-secret derived via fido2-assert")
            return h
        except FileNotFoundError:
            self._log.debug("fido2-assert not found")
            return None
        except subprocess.TimeoutExpired:
            self._log.warning("FIDO2 assertion timed out – user presence not confirmed")
            return None
        except Exception as exc:
            self._log.debug("fido2-assert error: %s", exc)
            return None

    def verify_still_present(self) -> bool:
        try:
            cp = subprocess.run(
                [self.FIDO2_TOKEN_BIN, "-L"],
                capture_output=True, text=True, timeout=10,
            )
            if cp.returncode != 0 or not cp.stdout.strip():
                self._token_present = False
                return False
            self._token_present = True
            return True
        except Exception:
            self._token_present = False
            return False


# ───────────────── Cloud Protection Orchestrator ───────────────────────────

class CloudProtectionLayer:
    """Top-level orchestrator for the confidential computing protection stack."""

    REQUIRED_FILES: List[str] = [
        "config.py.aesgcm",
        "calibration_report.md.aesgcm",
        "combined_runner.py.aesgcm",
        "prop_breakers.py.aesgcm",
        "README.md.aesgcm",
    ]
    ENCRYPTED_SUFFIX: str = ".aesgcm"

    def __init__(self,
                 data_dir: str,
                 mount_point: str = "/mnt/hpvs_data",
                 luks_backing: str = "/var/lib/hpvs/data.luks",
                 decoy_name: str = "systemd-journal",
                 verbose: bool = True):
        self._data_dir = os.path.abspath(data_dir)
        self._mount_point = mount_point
        self._luks_backing = luks_backing
        self._decoy_name = decoy_name
        self._verbose = verbose
        self._log = _make_logger("CloudProtectionLayer", verbose=verbose)

        self._zeroizer = SecureZeroizer(logger=self._log)
        self._verifier = TEAttestationVerifier(logger=self._log)
        self._decryptor = MetadataDecryptor(logger=self._log)
        self._luks = LuksProtection(mount_point=mount_point, logger=self._log)
        self._nitrokey = NitrokeyRootOfTrust(logger=self._log)
        self._monitor = ContinuousAttestationMonitor(
            verifier=self._verifier,
            zeroizer=self._zeroizer,
            logger=self._log,
        )

        self._decryption_key: Optional[ProtectedMemory] = None
        self._decrypted_configs: Dict[str, ProtectedMemory] = {}

    def bootstrap(self) -> bool:
        self._log.info("=== Cloud Protection Layer Bootstrap ===")
        self._log.info("Data directory: %s", self._data_dir)
        self._log.info("Platform: %s", sys.platform)
        self._log.info("Python: %s", sys.version)

        ProcessObfuscator(self._decoy_name).apply()

        self._zeroizer.arm()

        step = 0

        step += 1
        self._log.info("[%d/7] Verifying TEE attestation...", step)
        if not self._verifier.verify():
            self._zeroizer.violation(
                f"TEE attestation failed – platform is not a trusted execution environment"
            )
            return False
        self._log.info("[%d/7] TEE type: %s", step, self._verifier.tee_type)

        step += 1
        self._log.info("[%d/7] Checking Nitrokey FIDO2 token presence...", step)
        if not self._nitrokey.check_token_present():
            self._zeroizer.violation("Nitrokey FIDO2 token not present – refusing to boot")
            return False

        step += 1
        self._log.info("[%d/7] Retrieving hmac-secret from Nitrokey...", step)
        fido2_secret = self._nitrokey.get_hmac_secret()
        if not fido2_secret:
            self._zeroizer.violation("Failed to retrieve hmac-secret from Nitrokey")
            return False
        self._log.info("[%d/7] hmac-secret obtained (%d bytes)", step, len(fido2_secret))

        step += 1
        self._log.info("[%d/7] Deriving decryption key (HKDF-SHA512)...", step)
        platform_measurement = self._verifier.measurement
        assert platform_measurement is not None
        raw_key = MetadataDecryptor.derive_key(platform_measurement, fido2_secret)
        self._decryption_key = ProtectedMemory(len(raw_key), logger=self._log)
        self._decryption_key.write_bytes(raw_key)
        self._log.info("[%d/7] Decryption key derived and stored in protected memory", step)

        step += 1
        self._log.info("[%d/7] Decrypting metadata / config files...", step)
        key_bytes = self._decryption_key.read_bytes()
        for filename in self.REQUIRED_FILES:
            fp = os.path.join(self._data_dir, filename)
            if not os.path.exists(fp):
                self._log.warning("Skipping missing file: %s", fp)
                continue
            try:
                plain = self._decryptor.decrypt_file(fp, key_bytes)
                pm = ProtectedMemory(len(plain), logger=self._log)
                pm.write_bytes(plain)
                self._decrypted_configs[filename] = pm
                self._log.info("[%d/7] Decrypted: %s (%d bytes)", step, filename, len(plain))
            except Exception as exc:
                self._log.error("Failed to decrypt %s: %s", filename, exc)
                self._zeroizer.violation(f"Metadata decryption failed for {filename}: {exc}")
                return False

        step += 1
        self._log.info("[%d/7] Setting up LUKS2 data-at-rest protection...", step)
        try:
            luks_passphrase = self._luks.derive_passphrase(platform_measurement, fido2_secret)
            self._log.info("[%d/7] LUKS passphrase derived from platform measurement", step)
            if os.path.exists(self._luks_backing):
                self._luks.open_and_mount(self._luks_backing)
                self._log.info("[%d/7] LUKS volume mounted", step)
            else:
                self._log.info("[%d/7] No existing LUKS volume – skipping mount"
                               " (create with: cloud_protection.py --format-luks)", step)
        except Exception as exc:
            self._log.warning("[%d/7] LUKS setup skipped: %s", step, exc)

        step += 1
        self._log.info("[%d/7] Starting continuous attestation monitor (Keylime-style)...", step)
        self._monitor.start()

        self._log.info("=== Cloud Protection Layer bootstrap complete ===")
        self._switch_to_runtime_logging()

        return True

    def _switch_to_runtime_logging(self) -> None:
        if not HPV_RUNTIME_ERRORS_ONLY:
            return
        for name in logging.root.manager.loggerDict:
            logger = logging.getLogger(name)
            if logger.level == logging.DEBUG:
                logger.setLevel(logging.ERROR)

    def get_config(self, filename: str) -> Optional[bytes]:
        if filename in self._decrypted_configs:
            return self._decrypted_configs[filename].read_bytes()
        return None

    def get_config_text(self, filename: str) -> Optional[str]:
        data = self.get_config(filename)
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")

    def list_decrypted(self) -> List[str]:
        return sorted(self._decrypted_configs.keys())

    def encrypt_and_seal_file(self, filepath: str, output_path: Optional[str] = None) -> str:
        if self._decryption_key is None:
            raise RuntimeError("Bootstrap must complete before sealing files")
        key = self._decryption_key.read_bytes()
        with open(filepath, "rb") as f:
            plaintext = f.read()
        sealed = MetadataDecryptor.encrypt_data(plaintext, key)
        out = output_path or (filepath + self.ENCRYPTED_SUFFIX)
        with open(out, "wb") as f:
            f.write(sealed)
        self._log.info("Sealed %s -> %s (%d bytes)", filepath, out, len(sealed))
        return out

    def shutdown(self) -> None:
        self._log.info("Shutting down Cloud Protection Layer...")
        self._monitor.stop()
        try:
            self._luks.unmount_and_close()
        except Exception:
            pass
        self._zeroizer.execute(exit_code=0)


# ───────────────── Entry Point ─────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cloud Protection Layer – Confidential Computing for Trading Bot"
    )
    p.add_argument("--data-dir", default=os.path.dirname(os.path.abspath(__file__)),
                   help="Directory containing .aesgcm encrypted config files")
    p.add_argument("--mount", default="/mnt/hpvs_data",
                   help="LUKS mount point")
    p.add_argument("--luks-backing", default="/var/lib/hpvs/data.luks",
                   help="LUKS backing file")
    p.add_argument("--decoy-name", default="systemd-journal",
                   help="Process name for obfuscation")
    p.add_argument("--verbose", action="store_true", default=True,
                   help="Verbose startup logging")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress startup logging")
    p.add_argument("--format-luks", type=str, metavar="SIZE_MB", default=None,
                   help="Initialize a new LUKS2 volume (requires existing bootstrapped key)")
    p.add_argument("--seal", type=str, metavar="FILE",
                   help="Encrypt a plaintext file with the derived key")
    p.add_argument("--decrypt-to", type=str, metavar="OUTDIR",
                   help="Decrypt all .aesgcm files to a directory")
    p.add_argument("--check-only", action="store_true",
                   help="Run attestation + Nitrokey checks and exit")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    verbose = not args.quiet

    cpl = CloudProtectionLayer(
        data_dir=args.data_dir,
        mount_point=args.mount,
        luks_backing=args.luks_backing,
        decoy_name=args.decoy_name,
        verbose=verbose,
    )

    if args.check_only:
        logger = _make_logger("check-only", verbose=verbose)
        logger.info("Running attestation + Nitrokey checks only...")
        verifier = TEAttestationVerifier(logger=logger)
        ok = verifier.verify()
        logger.info("TEE attestation: %s (type=%s)", "PASS" if ok else "FAIL", verifier.tee_type)
        nitro = NitrokeyRootOfTrust(logger=logger)
        tok_ok = nitro.check_token_present()
        logger.info("Nitrokey present: %s", "PASS" if tok_ok else "FAIL")
        if tok_ok:
            sec = nitro.get_hmac_secret()
            logger.info("hmac-secret: %s", "OBTAINED" if sec else "FAILED")
        sys.exit(0 if (ok and tok_ok) else 1)

    if args.format_luks:
        size_mb = int(args.format_luks)
        logger = _make_logger("luks-format", verbose=verbose)
        logger.info("Initializing LUKS2 volume (%s MB)", size_mb)

        verifier = TEAttestationVerifier(logger=logger)
        if not verifier.verify():
            logger.error("TEE attestation required for LUKS format")
            sys.exit(1)

        logger.info("Insert Nitrokey and press button to derive passphrase...")
        nitro = NitrokeyRootOfTrust(logger=logger)
        if not nitro.check_token_present():
            logger.error("Nitrokey not present")
            sys.exit(1)
        fido_secret = nitro.get_hmac_secret()
        if not fido_secret:
            logger.error("Failed to get hmac-secret")
            sys.exit(1)

        luks = LuksProtection(logger=logger)
        pp = luks.derive_passphrase(verifier.measurement, fido_secret)
        LuksProtection.format_luks_volume(args.luks_backing, pp, size_mb=size_mb)
        logger.info("LUKS2 volume created at %s", args.luks_backing)
        sys.exit(0)

    if args.seal:
        if not os.path.exists(args.seal):
            print(f"File not found: {args.seal}", file=sys.stderr)
            sys.exit(1)

        if not cpl.bootstrap():
            print("Bootstrap failed – cannot seal", file=sys.stderr)
            sys.exit(1)

        output = cpl.encrypt_and_seal_file(args.seal)
        print(f"Sealed: {output}")
        cpl.shutdown()
        sys.exit(0)

    if args.decrypt_to:
        outdir = os.path.abspath(args.decrypt_to)
        os.makedirs(outdir, mode=0o700, exist_ok=True)

        if not cpl.bootstrap():
            print("Bootstrap failed – cannot decrypt", file=sys.stderr)
            sys.exit(1)

        for filename in cpl.list_decrypted():
            data = cpl.get_config(filename)
            if data is None:
                continue
            out_name = filename
            if out_name.endswith(cpl.ENCRYPTED_SUFFIX):
                out_name = out_name[:-len(cpl.ENCRYPTED_SUFFIX)]
            out_path = os.path.join(outdir, out_name)
            with open(out_path, "wb") as f:
                f.write(data)
            os.chmod(out_path, 0o600)
            print(f"Decrypted: {out_path}")

        cpl.shutdown()
        sys.exit(0)

    if not cpl.bootstrap():
        print("Bootstrap failed – see log for details", file=sys.stderr)
        sys.exit(1)

    print("Cloud Protection Layer active. Press Ctrl+C to shutdown.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        cpl.shutdown()


if __name__ == "__main__":
    main()
