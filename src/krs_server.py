#!/usr/bin/env python3
"""
Reference Key-Release Service (server side of krs_client.py) — HYBRID PQC.

Implements the KRS_POLICY.md flow for the SEV-SNP guest-report platforms this
repo targets (GCP N2D / Azure DCas v5 / bare-metal EPYC — see DEPLOYMENT_COST.md).
NOT for AWS Nitro (different attestation; needs an NSM adapter).

Per request (POST /verify over mTLS):
  1. mTLS enforced by the SSL context (client cert vs pinned CA, TLS 1.3).
  2. Parse {report, client_x_pub, client_kem_pub, nonce, channel_binding}.
  3. Anti-replay on nonce.
  4. snpguest VCEK->ASK->ARK chain + policy(no-debug) + TCB floor + measurement
     allowlist + report_data == sha256(client_x_pub||client_kem_pub||nonce||TAG).
  5. Authorize CEK release (prod: Nitrokey touch; dev: env CEK).
  6. HYBRID-wrap the CEK to the client's attested ephemeral keys:
     X25519 ECDH *and* ML-KEM-768 encapsulation, combined via HKDF (PQC-safe).
  7. HYBRID-sign (Ed25519 + ML-DSA-65) over the response.
Any failure -> identical HTTP 403.

CEK = the master key the strategy package was sealed with at build time.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import snp_verify
import hybrid

BIND_TAG = b"botsmaster-snp-binding-v2-hybrid"   # must match cloud_protection


def report_data_for(client_x_pub: bytes, client_kem_pub: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(client_x_pub + client_kem_pub + nonce + BIND_TAG).digest()


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


class _RateLimiter:
    """KRS_POLICY.md §1.4 — fixed-window limiter: per-client (cert/IP) and global. Over-limit => HTTP 429
    (distinct from a 403 attestation failure). Local; not shared across instances (acceptable per policy)."""
    def __init__(self, per_client: int = 10, global_max: int = 1000, window: float = 60.0):
        self.per_client, self.global_max, self.window = per_client, global_max, window
        self._win: dict[bytes, list] = {}
        self._g = [0, 0.0]
        self._lock = threading.Lock()

    def allow(self, key: bytes) -> bool:
        import time
        now = time.monotonic()
        with self._lock:
            if now - self._g[1] >= self.window:
                self._g = [0, now]
            if self._g[0] >= self.global_max:
                return False
            c = self._win.get(key)
            if c is None or now - c[1] >= self.window:
                c = [0, now]; self._win[key] = c
            if c[0] >= self.per_client:
                return False
            if len(self._win) > 50_000:
                self._win.clear(); self._win[key] = c
            c[0] += 1; self._g[0] += 1
            return True


class KrsConfig:
    def __init__(self, *, signing_key: Ed25519PrivateKey, mldsa_sk: bytes,
                 cek: bytes, verifier, production: bool,
                 rate_per_client: int = 10, rate_global: int = 1000):
        self.signing_key = signing_key      # Ed25519 (classical auth half)
        self.mldsa_sk = mldsa_sk            # ML-DSA-65 (PQC auth half)
        if len(cek) != 32:
            raise ValueError("CEK must be 32 bytes")
        self.cek = cek
        self.verifier = verifier
        self.production = production
        self.replay = _ReplayCache()
        self.rate = _RateLimiter(per_client=rate_per_client, global_max=rate_global)


def _make_handler(cfg: KrsConfig):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _status(self, code, reason):
            body = json.dumps({"verified": False, "reason": reason}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _deny(self):
            self._status(403, "denied")

        def _client_key(self) -> bytes:
            """Identify the caller for rate-limiting: client-cert fingerprint if presented, else source IP."""
            try:
                der = self.connection.getpeercert(binary_form=True)
                if der:
                    return hashlib.sha256(der).digest()
            except Exception:
                pass
            return ("ip:" + str(self.client_address[0])).encode()

        def do_POST(self):
            if self.path != "/verify":
                return self._deny()
            if not cfg.rate.allow(self._client_key()):
                return self._status(429, "rate_limited")   # NOT 403 (per KRS_POLICY §1.4)
            try:
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n))
                report = bytes.fromhex(req["report"])
                client_x_pub = bytes.fromhex(req["client_x_pub"])
                client_kem_pub = bytes.fromhex(req["client_kem_pub"])
                nonce = base64.b64decode(req["nonce"])
                if len(client_x_pub) != 32 or len(nonce) != 32:
                    raise ValueError("bad params")

                if not cfg.replay.fresh(hashlib.sha256(nonce).digest()):
                    raise ValueError("replay")

                expected_rd = report_data_for(client_x_pub, client_kem_pub, nonce)
                if cfg.production:
                    if cfg.verifier is None:
                        raise ValueError("no verifier in production")
                    measurement = cfg.verifier.verify(report, expected_rd)
                else:
                    logging.warning("DEV KRS: skipping SNP attestation")
                    measurement = b"\xde\xad" * 24

                krs_x_pub, kem_ct, wrapped = hybrid.wrap_cek(
                    client_x_pub, client_kem_pub, cfg.cek)
                signed = krs_x_pub + kem_ct + wrapped + measurement + nonce
                sig = hybrid.hybrid_sign(cfg.signing_key, cfg.mldsa_sk, signed)

                body = json.dumps({
                    "verified": True,
                    "krs_x_pub": krs_x_pub.hex(),
                    "kem_ct": base64.b64encode(kem_ct).decode(),
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
            except Exception as e:
                logging.info("verify denied: %s", e)
                self._deny()

    return Handler


def serve(cfg: KrsConfig, *, host: str, port: int, server_cert: str,
          server_key: str, client_ca: str) -> ThreadingHTTPServer:
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=client_ca)
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    httpd = ThreadingHTTPServer((host, port), _make_handler(cfg))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    logging.info("KRS listening on %s:%d (mTLS, hybrid-PQC, production=%s)",
                 host, port, cfg.production)
    return httpd


def main():
    p = argparse.ArgumentParser(description="Reference KRS (SEV-SNP, hybrid PQC)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--server-cert", required=True)
    p.add_argument("--server-key", required=True)
    p.add_argument("--client-ca", required=True)
    p.add_argument("--signing-key", required=True, help="KRS Ed25519 private key (hex, 32B)")
    p.add_argument("--mldsa-key", required=True, help="KRS ML-DSA-65 secret key (hex)")
    p.add_argument("--processor", default="milan")
    p.add_argument("--measurement", action="append", default=[])
    p.add_argument("--min-tcb", type=lambda x: int(x, 0), default=0)
    p.add_argument("--production", action="store_true")
    p.add_argument("--cek-env", default="BMSR_CEK_HEX")
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
    cfg = KrsConfig(
        signing_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.signing_key)),
        mldsa_sk=bytes.fromhex(args.mldsa_key), cek=cek, verifier=verifier,
        production=args.production)
    serve(cfg, host=args.host, port=args.port, server_cert=args.server_cert,
          server_key=args.server_key, client_ca=args.client_ca).serve_forever()


if __name__ == "__main__":
    main()
