#!/usr/bin/env python3
"""
Fail-closed attestation suite (no SEV hardware) — the pending "Fail-closed test suite" item.

Proves SnpVerifier.verify() REJECTS every tampered/stale/rolled-back/wrong-image report, and that it fails
closed when the AMD signature chain cannot be verified. Only the snpguest chain step is mocked for the
field-logic cases (it needs hardware); the chain-unverifiable case is tested for REAL (snpguest absent →
refuse). Maps the README's required cases: replayed quote, wrong TCB, bad image digest, bad signer.

Run:  python3 snp_failclosed_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging
logging.disable(logging.CRITICAL)

import snp_verify as V
from snp_verify import SnpVerifier, AttestationError
from snp_fakereport import make_report, with_debug, with_smt, POLICY_GOOD

GOOD_MEAS = b"\x11" * 48
WRONG_MEAS = b"\x22" * 48
RD = b"bind:hash(pubkey||nonce||policy||image)"     # the expected report_data (freshness/key binding)
TCB_FLOOR = 0x0808080808080808


def _verifier(**kw):
    base = dict(measurement_allowlist=[GOOD_MEAS], min_reported_tcb=TCB_FLOOR, require_no_debug=True)
    base.update(kw)
    v = SnpVerifier(**base)
    v.verify_signature_chain = lambda report_path: None   # mock ONLY the hardware/snpguest step
    return v


def _expect_reject(name, report, expected_rd=RD, **vkw):
    v = _verifier(**vkw)
    try:
        v.verify(report, expected_rd)
    except AttestationError as e:
        print(f"  PASS  {name}: rejected ({str(e)[:60]})")
        return True
    print(f"  FAIL  {name}: was ACCEPTED but should have been rejected", file=sys.stderr)
    return False


def main() -> int:
    ok = True
    print("== fail-closed attestation suite (off-hardware) ==")

    # baseline: a fully-valid report (chain mocked) must VERIFY and return the measurement
    good = make_report(policy=POLICY_GOOD, report_data=RD, measurement=GOOD_MEAS, reported_tcb=TCB_FLOOR)
    try:
        meas = _verifier().verify(good, RD)
        assert meas == GOOD_MEAS
        print("  PASS  valid report accepted (measurement returned)")
    except Exception as e:
        print(f"  FAIL  valid report rejected: {e}", file=sys.stderr); ok = False

    # 1. replayed/forwarded quote -> report_data mismatch
    ok &= _expect_reject("replayed/stale quote (report_data mismatch)",
                         make_report(report_data=b"OLD-NONCE", measurement=GOOD_MEAS, reported_tcb=TCB_FLOOR))
    # 2. bad image digest -> measurement not in allowlist
    ok &= _expect_reject("bad image digest (measurement not allowlisted)",
                         make_report(report_data=RD, measurement=WRONG_MEAS, reported_tcb=TCB_FLOOR))
    # 3. wrong/rolled-back TCB -> below floor
    ok &= _expect_reject("rolled-back firmware (TCB below floor)",
                         make_report(report_data=RD, measurement=GOOD_MEAS, reported_tcb=TCB_FLOOR - 1))
    # 4. debug-enabled guest policy
    ok &= _expect_reject("guest policy permits DEBUG",
                         make_report(policy=with_debug(), report_data=RD, measurement=GOOD_MEAS, reported_tcb=TCB_FLOOR))
    # 5. SMT-enabled policy when SMT must be disabled
    ok &= _expect_reject("guest policy permits SMT (require_smt_disabled)",
                         make_report(policy=with_smt(), report_data=RD, measurement=GOOD_MEAS, reported_tcb=TCB_FLOOR),
                         require_smt_disabled=True)
    # 6. truncated report
    ok &= _expect_reject("truncated report", make_report(report_data=RD, measurement=GOOD_MEAS,
                                                         reported_tcb=TCB_FLOOR)[:512])

    # 7. REAL fail-closed: chain unverifiable (snpguest absent) -> refuse. NOT mocked.
    v_real = SnpVerifier(measurement_allowlist=[GOOD_MEAS], min_reported_tcb=TCB_FLOOR,
                         snpguest="snpguest-definitely-not-installed-xyz")
    try:
        v_real.verify(good, RD)
        print("  FAIL  chain-unverifiable was accepted (should fail closed)", file=sys.stderr); ok = False
    except AttestationError as e:
        print(f"  PASS  chain unverifiable -> fail closed ({str(e)[:50]})")

    print("ALL FAIL-CLOSED TESTS PASSED" if ok else "FAIL-CLOSED SUITE HAD FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
