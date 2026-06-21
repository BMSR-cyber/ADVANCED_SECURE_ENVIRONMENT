#!/usr/bin/env python3
"""
KRS client over mutually-authenticated, pinned TLS 1.3 — HYBRID PQC.

Guarantees:
  * TLS 1.3 floor; mutual auth; pinned CA + pinned server-cert SHA-256.
  * The KRS response is HYBRID-signed (Ed25519 + ML-DSA-65) with pinned keys —
    so even a TLS-terminating proxy cannot substitute a key, and authenticity
    survives a break of either signature scheme.
  * The CEK is HYBRID-wrapped (X25519 ECDH + ML-KEM-768) to the VM's attested
    ephemeral keys — confidentiality survives a break of either KEM, and a
    harvest-now-decrypt-later adversary cannot recover it.

Note (RFC 9266 tls-exporter): not available on this Python/OpenSSL; we bind to
the pinned peer-cert fingerprint, which with cert pinning + the hybrid-signed
response closes the request-forwarding gap. See docs/PQC_TLS.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import pqc
import hybrid


class KrsError(Exception):
    pass


class KrsClient:
    def __init__(self, url: str, *, client_cert: str, client_key: str,
                 pinned_ca: str, pinned_server_fpr: str,
                 krs_signing_pub: bytes, krs_mldsa_pub: bytes, server_name: str):
        self.host, self.port = self._split(url)
        self.server_name = server_name
        self.pinned_server_fpr = pinned_server_fpr.lower().replace(":", "")
        self.krs_ed_pub = Ed25519PublicKey.from_public_bytes(krs_signing_pub)
        self.krs_mldsa_pub = krs_mldsa_pub
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=pinned_ca)
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
        self.ctx = ctx

    @staticmethod
    def _split(url: str) -> Tuple[str, int]:
        u = url.split("://", 1)[-1]
        host, _, port = u.partition("/")[0].partition(":")
        return host, int(port or 443)

    def release(self, report: bytes, x_eph: X25519PrivateKey,
                kem: "pqc.KemPrivate", tee_type: str = "sev-snp") -> Tuple[bytes, bytes]:
        """POST report → receive the CEK (hybrid-unwrapped) + measurement.

        `x_eph` + `kem` are the VM's attested ephemeral X25519 / ML-KEM keys;
        their public halves are bound into the report's report_data, so the KRS
        wraps the CEK to exactly this attested VM. Fail-closed on any check."""
        client_x_pub = x_eph.public_key().public_bytes_raw()
        client_kem_pub = kem.public
        import os
        nonce = os.urandom(32)
        raw = socket.create_connection((self.host, self.port), timeout=30)
        try:
            tls = self.ctx.wrap_socket(raw, server_hostname=self.server_name)
            peer = tls.getpeercert(binary_form=True)
            if hashlib.sha256(peer).hexdigest() != self.pinned_server_fpr:
                raise KrsError("server cert fingerprint mismatch")
            channel_binding = hashlib.sha256(peer).digest()

            body = json.dumps({
                "report": report.hex(),
                "client_x_pub": client_x_pub.hex(),
                "client_kem_pub": client_kem_pub.hex(),
                "nonce": base64.b64encode(nonce).decode(),
                "channel_binding": base64.b64encode(channel_binding).decode(),
                "tee_type": tee_type,
            }).encode()
            req = (f"POST /verify HTTP/1.1\r\nHost: {self.server_name}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                   ).encode() + body
            tls.sendall(req)
            resp = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                resp += chunk
        finally:
            raw.close()

        _, _, payload = resp.partition(b"\r\n\r\n")
        result = json.loads(payload)
        if not result.get("verified"):
            raise KrsError(f"KRS refused: {result.get('reason')}")

        krs_x_pub = bytes.fromhex(result["krs_x_pub"])
        kem_ct = base64.b64decode(result["kem_ct"])
        wrapped = base64.b64decode(result["session_key"])
        measurement = bytes.fromhex(result["measurement"])
        sig = base64.b64decode(result["krs_signature"])

        # hybrid-verify (Ed25519 AND ML-DSA) over the response.
        signed = krs_x_pub + kem_ct + wrapped + measurement + nonce
        if not hybrid.hybrid_verify(self.krs_ed_pub, self.krs_mldsa_pub, signed, sig):
            raise KrsError("KRS response hybrid signature invalid")
        if base64.b64decode(result.get("nonce_echo", "")) != nonce:
            raise KrsError("KRS nonce echo mismatch (replay?)")

        try:
            cek = hybrid.unwrap_cek(x_eph, kem, client_x_pub, client_kem_pub,
                                    krs_x_pub, kem_ct, wrapped)
        except Exception as e:
            raise KrsError(f"CEK hybrid unwrap failed: {e}") from e
        return cek, measurement
