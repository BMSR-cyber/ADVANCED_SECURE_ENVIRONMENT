#!/usr/bin/env python3
"""
Reference Key-Release Service (server side of krs_client.py).

Implements the trust-critical KRS flow from KRS_POLICY.md for the SEV-SNP
guest-report platform this repo targets (GCP N2D / Azure DCas v5 / bare-metal
EPYC — see docs/DEPLOYMENT_COST.md). It is NOT for AWS Nitro (different
attestation; would need an NSM adapter).

Flow per request (POST /verify, mTLS):
  1. mTLS already enforced by the SSL context (client cert vs pinned CA, TLS1.3).
  2. Parse {report, client_eph_pub, nonce, channel_binding, tee_type}.
  3. Anti-replay on nonce.
  4. snpguest VCEK->ASK->ARK chain + policy(no-debug) + TCB floor + measurement
     allowlist + report_data == sha256(client_eph_pub||nonce||BIND_TAG).
  5. Authorize CEK release (prod: Nitrokey touch; dev: env CEK).
  6. ECDH-wrap the CEK to the client's attested ephemeral X25519 pubkey
     (forward-secret, bound to THIS attested VM).
  7. Sign (krs_eph_pub||wrapped||measurement||nonce) with the KRS Ed25519 key.
Any failure -> identical HTTP 403 (no oracle about which check failed).

CEK = the master key the strategy package was sealed with at build time. The KRS
is the only party that holds/derives it; the VM never has it until attested.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import snp_verify

BIND_TAG = b"botsmaster-snp-binding-v1"   # must match cloud_protection bootstrap
WRAP_INFO = b"botsmaster/krs-cek-wrap/v1"


def report_data_for(client_eph_pub: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(client_eph_pub + nonce + BIND_TAG).digest()


class _ReplayCache:
    def __init__(self, cap: int = 100_000):
        self._seen: set[bytes] = set()
        self._cap = cap
        self._lock = threading.Lock()

    def fresh(self, h: bytes) -> bool:
        with self._lock:
            if h in self._seen:
                return False
            if len(self._seen) >= self._cap:
                self._seen.clear()
            self._seen.add(h)
            return True


class KrsConfig:
    def __init__(self, *, signing_key: Ed25519PrivateKey, cek: bytes,
                 verifier: "snp_verify.SnpVerifier | None", production: bool):
        self.signing_key = signing_key
        if len(cek) != 32:
            raise ValueError("CEK must be 32 bytes")
        self.cek = cek
        self.verifier = verifier
        self.production = production
        self.replay = _ReplayCache()


def _wrap_cek_to(client_eph_pub: bytes, cek: bytes) -> tuple[bytes, bytes]:
    """ECDH(KRS ephemeral, client eph) -> HKDF -> AES-GCM wrap. Returns
    (krs_eph_pub, nonce||ct)."""
    krs_eph = X25519PrivateKey.generate()
    krs_eph_pub = krs_eph.public_key().public_bytes_raw()
    shared = krs_eph.exchange(X25519PublicKey.from_public_bytes(client_eph_pub))
    wrap_key = HKDF(algorithm=hashes.SHA512(), length=32,
                    salt=client_eph_pub + krs_eph_pub, info=WRAP_INFO).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(wrap_key).encrypt(nonce, cek, None)
    return krs_eph_pub, nonce + ct


def _make_handler(cfg: KrsConfig):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet default logging
            pass

        def _deny(self):
            body = json.dumps({"verified": False, "reason": "denied"}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/verify":
                return self._deny()
            try:
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n))
                report = bytes.fromhex(req["report"])
                client_eph_pub = bytes.fromhex(req["client_eph_pub"])
                nonce = base64.b64decode(req["nonce"])
                if len(client_eph_pub) != 32 or len(nonce) != 32:
                    raise ValueError("bad params")

                if not cfg.replay.fresh(hashlib.sha256(nonce).digest()):
                    raise ValueError("replay")

                expected_rd = report_data_for(client_eph_pub, nonce)
                if cfg.production:
                    if cfg.verifier is None:
                        raise ValueError("no verifier in production")
                    measurement = cfg.verifier.verify(report, expected_rd)
                else:
                    # DEV ONLY: skip SNP attestation (no hardware/snpguest).
                    logging.warning("DEV KRS: skipping SNP attestation")
                    measurement = b"\xde\xad" * 24  # 48-byte placeholder

                krs_eph_pub, wrapped = _wrap_cek_to(client_eph_pub, cfg.cek)
                signed = krs_eph_pub + wrapped + measurement + nonce
                sig = cfg.signing_key.sign(signed)

                body = json.dumps({
                    "verified": True,
                    "krs_eph_pub": krs_eph_pub.hex(),
                    "session_key": base64.b64encode(wrapped).decode(),
                    "measurement": measurement.hex(),
                    "nonce_echo": base64.b64encode(nonce).decode(),
                    "krs_signature": base64.b64encode(sig).decode(),
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:                  # uniform denial, no oracle
                logging.info("verify denied: %s", e)
                self._deny()

    return Handler


def serve(cfg: KrsConfig, *, host: str, port: int, server_cert: str,
          server_key: str, client_ca: str) -> ThreadingHTTPServer:
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED                 # require client cert
    ctx.load_verify_locations(cafile=client_ca)         # pinned client CA only
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    httpd = ThreadingHTTPServer((host, port), _make_handler(cfg))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    logging.info("KRS listening on %s:%d (mTLS, production=%s)",
                 host, port, cfg.production)
    return httpd


def main():
    p = argparse.ArgumentParser(description="Reference Key-Release Service (SEV-SNP)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--server-cert", required=True)
    p.add_argument("--server-key", required=True)
    p.add_argument("--client-ca", required=True, help="pinned CA for client certs")
    p.add_argument("--signing-key", required=True, help="KRS Ed25519 private key (hex, 32B)")
    p.add_argument("--processor", default="milan")
    p.add_argument("--measurement", action="append", default=[],
                   help="allowed measurement (hex); repeatable")
    p.add_argument("--min-tcb", type=lambda x: int(x, 0), default=0)
    p.add_argument("--production", action="store_true")
    p.add_argument("--cek-env", default="BMSR_CEK_HEX",
                   help="env var holding the 32-byte CEK (hex). Prod: derive from "
                        "a Nitrokey touch instead and feed it here at start.")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

    cek = bytes.fromhex(os.environ[args.cek_env])
    verifier = None
    if args.production:
        if not args.measurement:
            p.error("production requires at least one --measurement")
        verifier = snp_verify.SnpVerifier(
            processor=args.processor,
            measurement_allowlist=[bytes.fromhex(m) for m in args.measurement],
            min_reported_tcb=args.min_tcb)
    cfg = KrsConfig(signing_key=Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(args.signing_key)), cek=cek, verifier=verifier,
        production=args.production)
    httpd = serve(cfg, host=args.host, port=args.port, server_cert=args.server_cert,
                  server_key=args.server_key, client_ca=args.client_ca)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
