#!/usr/bin/env python3
"""
SEV-SNP attestation: real ioctl fetch + cert-chain/policy/TCB verification.

Two deliberate design choices, per review:
  * FETCH uses the real kernel ABI: ioctl(SNP_GET_REPORT) on /dev/sev-guest
    (the repo's previous f.write/f.read on the device was not the ABI). This is
    the documented uapi, not hand-rolled crypto.
  * VERIFY of the AMD signature chain (VCEK -> ASK -> ARK) is delegated to AMD's
    `snpguest` (virtee), NOT reimplemented here. Hand-rolling cert-chain crypto
    is exactly how attestation gets silently broken. We only parse the report's
    public fields (measurement, report_data, policy, TCB) to enforce policy.

ABI offsets (AMD SEV-SNP ATTESTATION_REPORT, v2/v3):
    0x008 POLICY        u64
    0x038 CURRENT_TCB   u64
    0x050 REPORT_DATA   64 bytes   (we bind nonce||pubkey here)
    0x090 MEASUREMENT   48 bytes   (<-- repo had 0x0A0, WRONG; off by 0x10)
    0x180 REPORTED_TCB  u64
Fail-closed: any check that cannot be completed raises AttestationError.
"""
from __future__ import annotations

import ctypes
import fcntl
import logging
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

SEV_GUEST_DEVICE = "/dev/sev-guest"

# report field offsets
OFF_POLICY = 0x008
OFF_CURRENT_TCB = 0x038
OFF_REPORT_DATA = 0x050
OFF_MEASUREMENT = 0x090
OFF_REPORTED_TCB = 0x180
REPORT_LEN = 1184

# guest POLICY bit for DEBUG (1 = debugging allowed → must be 0)
POLICY_DEBUG_BIT = 19
POLICY_SMT_BIT = 16

# ioctl: SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
#   struct snp_guest_request_ioctl { u8 msg_version; u64 req_data; u64 resp_data;
#                                    u64 fw_err; }  -> 32 bytes (8-aligned)
_IOC_WRITE, _IOC_READ = 1, 2
def _IOWR(t, nr, size):
    return (_IOC_WRITE | _IOC_READ) << 30 | size << 16 | ord(t) << 8 | nr
SNP_GET_REPORT = _IOWR("S", 0x0, 32)


class AttestationError(Exception):
    """Fatal: attestation cannot be verified. Always fail closed."""


# ── real ioctl fetch ─────────────────────────────────────────────────────────

def fetch_report_ioctl(report_data: bytes, vmpl: int = 0) -> bytes:
    """Request a signed SEV-SNP attestation report via the real kernel ioctl.

    `report_data` (<=64 bytes) is bound into the report by the PSP and is how we
    prove freshness + key binding. Returns the 1184-byte attestation report.
    """
    if not os.path.exists(SEV_GUEST_DEVICE):
        raise AttestationError(f"{SEV_GUEST_DEVICE} absent — not a SEV-SNP guest")
    rd = report_data[:64].ljust(64, b"\x00")

    # struct snp_report_req { u8 user_data[64]; u32 vmpl; u8 rsvd[28]; } = 96B
    req = ctypes.create_string_buffer(96)
    ctypes.memmove(req, rd, 64)
    struct.pack_into("<I", req, 64, vmpl)
    # struct snp_report_resp { u8 data[4000]; }
    resp = ctypes.create_string_buffer(4000)

    # ioctl arg struct (mutable so fw_err is readable after the call)
    arg = bytearray(struct.pack("<BxxxxxxxQQQ", 1,
                                ctypes.addressof(req),
                                ctypes.addressof(resp), 0))
    try:
        with open(SEV_GUEST_DEVICE, "rb", buffering=0) as f:
            fcntl.ioctl(f.fileno(), SNP_GET_REPORT, arg, True)
    except OSError as e:
        raise AttestationError(f"SNP_GET_REPORT ioctl failed: {e}") from e

    fw_err = struct.unpack_from("<Q", arg, 24)[0]
    if fw_err != 0:
        raise AttestationError(f"PSP firmware error: 0x{fw_err:x}")

    # snp_report_resp.data: u32 status; u32 report_size; u8 rsvd[24]; report...
    status, report_size = struct.unpack_from("<II", resp, 0)
    if status != 0:
        raise AttestationError(f"report status nonzero: {status}")
    if report_size < REPORT_LEN:
        raise AttestationError(f"report too small: {report_size}")
    return bytes(resp[32:32 + REPORT_LEN])


# ── field parsing (public data only) ─────────────────────────────────────────

def parse_measurement(report: bytes) -> bytes:
    if len(report) < OFF_MEASUREMENT + 48:
        raise AttestationError("report truncated (measurement)")
    return report[OFF_MEASUREMENT:OFF_MEASUREMENT + 48]

def parse_report_data(report: bytes) -> bytes:
    return report[OFF_REPORT_DATA:OFF_REPORT_DATA + 64]

def parse_policy(report: bytes) -> int:
    return struct.unpack_from("<Q", report, OFF_POLICY)[0]

def parse_reported_tcb(report: bytes) -> int:
    return struct.unpack_from("<Q", report, OFF_REPORTED_TCB)[0]


# ── cert-chain verification via snpguest (NOT hand-rolled) ────────────────────

class SnpVerifier:
    def __init__(self, *, snpguest: str = "snpguest", processor: str = "milan",
                 measurement_allowlist: Iterable[bytes],
                 min_reported_tcb: int = 0,
                 require_no_debug: bool = True,
                 require_smt_disabled: bool = False,
                 cert_dir: Optional[str] = None):
        self.snpguest = snpguest
        self.processor = processor
        self.allow = {bytes(m).ljust(48, b"\x00")[:48] for m in measurement_allowlist}
        self.min_reported_tcb = min_reported_tcb
        self.require_no_debug = require_no_debug
        self.require_smt_disabled = require_smt_disabled
        self.cert_dir = cert_dir

    def _snpguest(self, *args) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.snpguest, *args], capture_output=True,
                                  text=True, timeout=60)
        except FileNotFoundError as e:
            raise AttestationError(
                "snpguest not installed — required to verify the AMD VCEK->ASK->"
                "ARK chain. Install from https://github.com/virtee/snpguest. "
                "Refusing to accept attestation without chain verification."
            ) from e

    def verify_signature_chain(self, report_path: str) -> None:
        """Fetch CA + VCEK and verify the report's AMD signature chain via snpguest."""
        cdir = self.cert_dir or tempfile.mkdtemp(prefix="snp_certs_")
        Path(cdir).mkdir(parents=True, exist_ok=True)
        steps = [
            ("fetch", "ca", "pem", self.processor, cdir),
            ("fetch", "vcek", "pem", self.processor, cdir, report_path),
            ("verify", "certs", cdir),
            ("verify", "attestation", cdir, report_path),
        ]
        for step in steps:
            r = self._snpguest(*step)
            if r.returncode != 0:
                raise AttestationError(
                    f"snpguest {' '.join(step)} failed (rc={r.returncode}): "
                    f"{(r.stderr or r.stdout).strip()[:200]}")
        logging.info("snpguest: VCEK->ASK->ARK chain + report signature verified")

    def verify(self, report: bytes, expected_report_data: bytes) -> bytes:
        """Full fail-closed verification. Returns the verified measurement."""
        if len(report) < REPORT_LEN:
            raise AttestationError("report too short")

        # 1. signature chain (delegated to AMD snpguest)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(report)
            rp = tf.name
        try:
            self.verify_signature_chain(rp)
        finally:
            os.unlink(rp)

        # 2. report_data binding (freshness + key/image binding)
        rd = parse_report_data(report)
        if rd != expected_report_data[:64].ljust(64, b"\x00"):
            raise AttestationError("report_data mismatch (stale/forwarded report)")

        # 3. measurement allowlist
        meas = parse_measurement(report)
        if meas not in self.allow:
            raise AttestationError(f"measurement not in allowlist: {meas[:8].hex()}...")

        # 4. policy: debugging must be disabled
        policy = parse_policy(report)
        if self.require_no_debug and (policy >> POLICY_DEBUG_BIT) & 1:
            raise AttestationError("guest policy permits DEBUG — refused")
        if self.require_smt_disabled and (policy >> POLICY_SMT_BIT) & 1:
            raise AttestationError("guest policy permits SMT — refused")

        # 5. TCB floor (anti-rollback to vulnerable firmware)
        rtcb = parse_reported_tcb(report)
        if rtcb < self.min_reported_tcb:
            raise AttestationError(
                f"reported_tcb 0x{rtcb:x} below floor 0x{self.min_reported_tcb:x}")

        logging.info("attestation verified: measurement=%s policy=0x%x tcb=0x%x",
                     meas[:8].hex(), policy, rtcb)
        return meas
