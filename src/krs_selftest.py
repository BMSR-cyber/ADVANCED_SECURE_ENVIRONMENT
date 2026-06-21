#!/usr/bin/env python3
"""
End-to-end KRS self-test (no SEV hardware needed): generates a CA + server/client
certs, runs krs_server in DEV mode (attestation skipped), and drives krs_client
through the full mTLS handshake + ECDH CEK unwrap + Ed25519 response-signature
check. Validates the channel + crypto; the SNP attestation itself needs hardware.
"""
from __future__ import annotations

import datetime
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import krs_server
import krs_client


def _name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _gen_ca(tmp: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(_name("test-ca"))
            .issuer_name(_name("test-ca")).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    (tmp / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _gen_leaf(tmp: Path, cn: str, ca_key, ca_cert, san: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.utcnow()
    b = (x509.CertificateBuilder().subject_name(_name(cn))
         .issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
    cert = b.sign(ca_key, hashes.SHA256())
    (tmp / f"{cn}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / f"{cn}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="krs_test_"))
    ca_key, ca_cert = _gen_ca(tmp)
    server_cert = _gen_leaf(tmp, "localhost", ca_key, ca_cert, san=True)
    _gen_leaf(tmp, "client", ca_key, ca_cert, san=False)

    import hashlib
    server_fpr = hashlib.sha256(
        server_cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    cek = secrets.token_bytes(32)
    os.environ["BMSR_CEK_HEX"] = cek.hex()
    sign_key = Ed25519PrivateKey.generate()
    krs_pub = sign_key.public_key().public_bytes_raw()

    cfg = krs_server.KrsConfig(signing_key=sign_key, cek=cek, verifier=None,
                               production=False)
    httpd = krs_server.serve(cfg, host="127.0.0.1", port=0,
                             server_cert=str(tmp / "localhost.pem"),
                             server_key=str(tmp / "localhost.key"),
                             client_ca=str(tmp / "ca.pem"))
    port = httpd.socket.getsockname()[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    time.sleep(0.2)
    try:
        client = krs_client.KrsClient(
            f"https://localhost:{port}/verify",
            client_cert=str(tmp / "client.pem"), client_key=str(tmp / "client.key"),
            pinned_ca=str(tmp / "ca.pem"), pinned_server_fpr=server_fpr,
            krs_signing_pub=krs_pub, server_name="localhost")

        eph = X25519PrivateKey.generate()
        got, meas = client.release(b"\x00" * 1184, eph)
        assert got == cek, "CEK did not round-trip through ECDH wrap/unwrap"
        print("OK  full mTLS + ECDH CEK unwrap + signature verify")
        assert len(meas) == 48
        print("OK  measurement returned (dev placeholder, 48B)")

        # negative: wrong pinned fingerprint must fail
        bad = krs_client.KrsClient(
            f"https://localhost:{port}/verify",
            client_cert=str(tmp / "client.pem"), client_key=str(tmp / "client.key"),
            pinned_ca=str(tmp / "ca.pem"), pinned_server_fpr="00" * 32,
            krs_signing_pub=krs_pub, server_name="localhost")
        try:
            bad.release(b"\x00" * 1184, X25519PrivateKey.generate())
            print("FAIL fingerprint pin not enforced"); return 1
        except krs_client.KrsError:
            print("OK  server cert pin enforced")

        # negative: wrong KRS signing key must fail signature check
        wrong = krs_client.KrsClient(
            f"https://localhost:{port}/verify",
            client_cert=str(tmp / "client.pem"), client_key=str(tmp / "client.key"),
            pinned_ca=str(tmp / "ca.pem"), pinned_server_fpr=server_fpr,
            krs_signing_pub=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            server_name="localhost")
        try:
            wrong.release(b"\x00" * 1184, X25519PrivateKey.generate())
            print("FAIL KRS signature not verified"); return 1
        except krs_client.KrsError:
            print("OK  KRS response signature enforced")
    finally:
        httpd.shutdown()
    print("\nALL KRS SELFTESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
