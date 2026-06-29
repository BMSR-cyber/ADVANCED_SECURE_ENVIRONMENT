#!/usr/bin/env python3
"""
Synthetic SEV-SNP attestation report builder — TEST ONLY (never production).

Generating a *real* signed report needs the AMD PSP on SEV-SNP hardware. But the trust-critical FIELD
verification in snp_verify.SnpVerifier.verify() (report_data binding, measurement allowlist, policy
debug/SMT bits, TCB floor, length) is pure data logic and can be exercised off-hardware against crafted
reports. This builder writes those public fields at the exact offsets snp_verify parses, so the
fail-closed suite can prove each rejection path without a PSP. It does NOT (and cannot) produce a valid
AMD signature chain — that single step stays delegated to `snpguest` on real hardware.
"""
from __future__ import annotations

import struct

from snp_verify import (OFF_POLICY, OFF_CURRENT_TCB, OFF_REPORT_DATA, OFF_MEASUREMENT,
                        OFF_REPORTED_TCB, REPORT_LEN, POLICY_DEBUG_BIT, POLICY_SMT_BIT)

# AMD SEV-SNP guest policy bit 17 is reserved and must be 1; a minimal "good" policy has no DEBUG/SMT.
POLICY_GOOD = 1 << 17


def make_report(*, policy: int = POLICY_GOOD, report_data: bytes = b"",
                measurement: bytes = b"\x11" * 48, reported_tcb: int = 0) -> bytes:
    """Build a 1184-byte report with the given public fields at snp_verify's offsets."""
    buf = bytearray(REPORT_LEN)
    struct.pack_into("<Q", buf, OFF_POLICY, policy & 0xFFFFFFFFFFFFFFFF)
    rd = report_data[:64].ljust(64, b"\x00")
    buf[OFF_REPORT_DATA:OFF_REPORT_DATA + 64] = rd
    m = measurement[:48].ljust(48, b"\x00")
    buf[OFF_MEASUREMENT:OFF_MEASUREMENT + 48] = m
    struct.pack_into("<Q", buf, OFF_REPORTED_TCB, reported_tcb & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", buf, OFF_CURRENT_TCB, reported_tcb & 0xFFFFFFFFFFFFFFFF)
    return bytes(buf)


def with_debug(policy: int = POLICY_GOOD) -> int:
    return policy | (1 << POLICY_DEBUG_BIT)


def with_smt(policy: int = POLICY_GOOD) -> int:
    return policy | (1 << POLICY_SMT_BIT)
