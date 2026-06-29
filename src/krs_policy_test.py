#!/usr/bin/env python3
"""
KRS server policy-enforcement test (no SEV hardware) — drives the reference KRS in PRODUCTION mode against
SYNTHETIC attested reports, with only the AMD chain step mocked. Proves the KRS_POLICY.md gating:
  * valid attested report (correct report_data binding, allowlisted measurement, TCB ok) -> 200 release
  * bad image digest (measurement not allowlisted)                                        -> 403
  * replayed nonce                                                                         -> 403
  * rate limit exceeded (§1.4)                                                             -> 429 (not 403)
The crypto/channel path is covered by krs_selftest.py; this isolates the SERVER's authorization policy.

Run:  python3 krs_policy_test.py     (needs the venv with cryptography + liboqs)
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import secrets
import ssl
import sys
import threading
import time
from pathlib import Path
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging
logging.disable(logging.CRITICAL)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import krs_server
import pqc
import snp_verify
from snp_fakereport import make_report, POLICY_GOOD
from krs_selftest import _gen_ca, _gen_leaf   # reuse cert helpers

GOOD_MEAS = b"\x11" * 48
WRONG_MEAS = b"\x22" * 48
TCB_FLOOR = 0x0808080808080808


def _x25519_pub() -> bytes:
    return X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _start_server(tmp: Path, *, rate_per_client: int):
    cek = secrets.token_bytes(32)
    os.environ["BMSR_CEK_HEX"] = cek.hex()
    verifier = snp_verify.SnpVerifier(measurement_allowlist=[GOOD_MEAS], min_reported_tcb=TCB_FLOOR)
    verifier.verify_signature_chain = lambda report_path: None      # mock ONLY the hardware/snpguest step
    cfg = krs_server.KrsConfig(signing_key=Ed25519PrivateKey.generate(),
                               mldsa_sk=pqc.sig_generate()[1], cek=cek, verifier=verifier,
                               production=True, rate_per_client=rate_per_client)
    httpd = krs_server.serve(cfg, host="127.0.0.1", port=0,
                             server_cert=str(tmp / "localhost.pem"), server_key=str(tmp / "localhost.key"),
                             client_ca=str(tmp / "ca.pem"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.15)
    return httpd, httpd.socket.getsockname()[1]


def _post(tmp: Path, port: int, *, measurement=GOOD_MEAS, nonce=None, tcb=TCB_FLOOR, policy=POLICY_GOOD) -> int:
    x_pub = _x25519_pub()
    kem = pqc.KemPrivate(); kem_pub = kem.public
    nonce = nonce or secrets.token_bytes(32)
    rd = krs_server.report_data_for(x_pub, kem_pub, nonce)
    report = make_report(policy=policy, report_data=rd, measurement=measurement, reported_tcb=tcb)
    body = json.dumps({"report": report.hex(), "client_x_pub": x_pub.hex(),
                       "client_kem_pub": kem_pub.hex(), "nonce": base64.b64encode(nonce).decode()}).encode()
    ctx = ssl.create_default_context(cafile=str(tmp / "ca.pem"))
    ctx.load_cert_chain(str(tmp / "client.pem"), str(tmp / "client.key"))
    conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=10)
    try:
        conn.request("POST", "/verify", body, {"Content-Type": "application/json", "Connection": "close"})
        return conn.getresponse().status
    finally:
        conn.close()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="krs_policy_"))
    ca_key, ca_cert = _gen_ca(tmp)
    _gen_leaf(tmp, "localhost", ca_key, ca_cert, san=True)
    _gen_leaf(tmp, "client", ca_key, ca_cert, san=False)
    ok = True
    print("== KRS server policy enforcement (production mode, chain mocked) ==")

    httpd, port = _start_server(tmp, rate_per_client=50)
    try:
        # 1. valid attested report -> 200
        s = _post(tmp, port)
        print(f"  {'PASS' if s==200 else 'FAIL'}  valid attested report -> {s} (want 200)"); ok &= s == 200
        # 2. bad image digest -> 403
        s = _post(tmp, port, measurement=WRONG_MEAS)
        print(f"  {'PASS' if s==403 else 'FAIL'}  bad image digest -> {s} (want 403)"); ok &= s == 403
        # 3. rolled-back TCB -> 403
        s = _post(tmp, port, tcb=TCB_FLOOR - 1)
        print(f"  {'PASS' if s==403 else 'FAIL'}  rolled-back TCB -> {s} (want 403)"); ok &= s == 403
        # 4. replayed nonce -> first 200, replay 403
        n = secrets.token_bytes(32)
        s1 = _post(tmp, port, nonce=n); s2 = _post(tmp, port, nonce=n)
        print(f"  {'PASS' if (s1==200 and s2==403) else 'FAIL'}  replay nonce -> {s1} then {s2} (want 200,403)")
        ok &= (s1 == 200 and s2 == 403)
    finally:
        httpd.shutdown()

    # 5. rate limit (§1.4): exceed per-client -> 429 (separate server, low limit)
    httpd2, port2 = _start_server(tmp, rate_per_client=3)
    try:
        codes = [_post(tmp, port2) for _ in range(5)]
        got429 = 429 in codes
        print(f"  {'PASS' if got429 else 'FAIL'}  rate limit -> {codes} (want a 429 after 3)"); ok &= got429
    finally:
        httpd2.shutdown()

    print("ALL KRS POLICY TESTS PASSED" if ok else "KRS POLICY SUITE HAD FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
