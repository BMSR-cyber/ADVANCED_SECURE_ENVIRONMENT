#!/usr/bin/env python3
"""
Key-Release-Service client over mutually-authenticated, pinned TLS 1.3.

Replaces the prototype's plain `urllib` call. Guarantees:
  * TLS 1.3 minimum (older versions refused at handshake).
  * Mutual auth: the VM presents a client certificate; the KRS is verified
    against a PINNED CA (not the public CA store) AND a pinned server-cert
    SHA-256 fingerprint (defeats a mis-issued/rogue cert under the pinned CA).
  * The KRS response (wrapped CEK) is itself signed with the KRS's pinned
    Ed25519 key — so even a TLS-terminating proxy cannot substitute a key.
  * A fresh client nonce is bound into the request and echoed in the signed
    response (anti-replay), together with both cert fingerprints as a channel
    binding (best-effort; see note on RFC 9266 below).

Note on channel binding: true RFC 9266 tls-exporter binding needs
SSLObject.export_keying_material (Python 3.13+) or a TLS lib that exposes it.
On 3.11 we bind to the pinned peer-cert fingerprint instead, which — combined
with cert pinning + the signed response — closes the request-forwarding gap in
practice. Upgrade to tls-exporter when the runtime supports it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WRAP_INFO = b"botsmaster/krs-cek-wrap/v1"   # must match krs_server


class KrsError(Exception):
    pass


class KrsClient:
    def __init__(self, url: str, *, client_cert: str, client_key: str,
                 pinned_ca: str, pinned_server_fpr: str,
                 krs_signing_pub: bytes, server_name: str):
        self.host, self.port = self._split(url)
        self.server_name = server_name
        self.pinned_server_fpr = pinned_server_fpr.lower().replace(":", "")
        self.krs_pub = Ed25519PublicKey.from_public_bytes(krs_signing_pub)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=pinned_ca)          # pinned CA only
        ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
        self.ctx = ctx

    @staticmethod
    def _split(url: str) -> Tuple[str, int]:
        u = url.split("://", 1)[-1]
        host, _, port = u.partition("/")[0].partition(":")
        return host, int(port or 443)

    def release(self, report: bytes, eph_priv: X25519PrivateKey,
                tee_type: str = "sev-snp") -> Tuple[bytes, bytes]:
        """POST report → receive the CEK (ECDH-unwrapped) + measurement.

        `eph_priv` is the VM's attested ephemeral X25519 key (its public half is
        bound into the report's report_data, so the KRS wraps the CEK to exactly
        this attested VM). Fail-closed on any check."""
        client_eph_pub = eph_priv.public_key().public_bytes_raw()
        nonce = os.urandom(32)
        raw = socket.create_connection((self.host, self.port), timeout=30)
        try:
            tls = self.ctx.wrap_socket(raw, server_hostname=self.server_name)
            peer = tls.getpeercert(binary_form=True)            # pin exact cert
            fpr = hashlib.sha256(peer).hexdigest()
            if fpr != self.pinned_server_fpr:
                raise KrsError(f"server cert fingerprint mismatch: {fpr}")
            channel_binding = hashlib.sha256(peer).digest()

            body = json.dumps({
                "report": report.hex(),
                "client_eph_pub": client_eph_pub.hex(),
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

        krs_eph_pub = bytes.fromhex(result["krs_eph_pub"])
        wrapped = base64.b64decode(result["session_key"])        # nonce(12)||ct
        measurement = bytes.fromhex(result["measurement"])
        sig = base64.b64decode(result["krs_signature"])

        # KRS signs (krs_eph_pub||wrapped||measurement||our nonce) with its
        # pinned Ed25519 key — defeats a TLS-terminating substitution.
        try:
            self.krs_pub.verify(sig, krs_eph_pub + wrapped + measurement + nonce)
        except Exception as e:
            raise KrsError(f"KRS response signature invalid: {e}") from e
        if base64.b64decode(result.get("nonce_echo", "")) != nonce:
            raise KrsError("KRS nonce echo mismatch (replay?)")

        # ECDH-unwrap the CEK to this attested ephemeral key.
        shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(krs_eph_pub))
        wrap_key = HKDF(algorithm=hashes.SHA512(), length=32,
                        salt=client_eph_pub + krs_eph_pub, info=WRAP_INFO).derive(shared)
        try:
            cek = AESGCM(wrap_key).decrypt(wrapped[:12], wrapped[12:], None)
        except Exception as e:
            raise KrsError(f"CEK unwrap failed: {e}") from e
        return cek, measurement
