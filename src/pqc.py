#!/usr/bin/env python3
"""
Hybrid post-quantum primitives (liboqs / oqs), shared by the split channel and
the ASE KRS.

Posture: HYBRID. Every asymmetric operation combines a classical primitive
(X25519 / Ed25519) with a PQC one (ML-KEM-768 / ML-DSA-65) so the result is
secure if EITHER remains unbroken — protects against both "Shor breaks the
classical half" and a future break of the PQC half. Symmetric crypto
(AES-256-GCM, HKDF-SHA512) is already quantum-safe and is unchanged.

This module is the PQC half only; callers combine it with the classical half via
`combine()`. If liboqs is unavailable, `available()` is False and callers decide
(prod: hard-require PQC; dev: may fall back to classical with a loud warning).
"""
from __future__ import annotations

import importlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "ML-KEM-768"     # FIPS 203
SIG_ALG = "ML-DSA-65"      # FIPS 204

_oqs = None


def _load():
    global _oqs
    if _oqs is None:
        # Point the wrapper at the locally-built liboqs if not already configured.
        import os
        if not os.environ.get("OQS_INSTALL_PATH"):
            default = os.path.expanduser("~/_oqs")
            if os.path.isdir(default):
                os.environ["OQS_INSTALL_PATH"] = default
                os.environ["LD_LIBRARY_PATH"] = (
                    default + "/lib:" + os.environ.get("LD_LIBRARY_PATH", ""))
        _oqs = importlib.import_module("oqs")
    return _oqs


def available() -> bool:
    try:
        _load()
        return True
    except Exception:
        return False


# ── KEM (ephemeral, per session) ─────────────────────────────────────────────

class KemPrivate:
    """An ephemeral ML-KEM keypair. Keep alive to decapsulate, then free()."""

    def __init__(self):
        self._kem = _load().KeyEncapsulation(KEM_ALG)
        self.public: bytes = self._kem.generate_keypair()

    def decap(self, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)

    def free(self) -> None:
        try:
            self._kem.free()
        except Exception:
            pass


def kem_encap(peer_public: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to a peer's ML-KEM public key → (ciphertext, shared_secret)."""
    kem = _load().KeyEncapsulation(KEM_ALG)
    try:
        return kem.encap_secret(peer_public)
    finally:
        try:
            kem.free()
        except Exception:
            pass


# ── Signatures (long-term identity) ──────────────────────────────────────────

def sig_generate() -> Tuple[bytes, bytes]:
    """Generate an ML-DSA identity → (public_key, secret_key) bytes."""
    sig = _load().Signature(SIG_ALG)
    try:
        pub = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pub, sk
    finally:
        try:
            sig.free()
        except Exception:
            pass


def sig_sign(secret_key: bytes, message: bytes) -> bytes:
    sig = _load().Signature(SIG_ALG, secret_key=secret_key)
    try:
        return sig.sign(message)
    finally:
        try:
            sig.free()
        except Exception:
            pass


def sig_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    sig = _load().Signature(SIG_ALG)
    try:
        return bool(sig.verify(message, signature, public_key))
    finally:
        try:
            sig.free()
        except Exception:
            pass


# ── Hybrid combiner ──────────────────────────────────────────────────────────

def combine(*secrets: bytes, salt: bytes = b"",
            info: bytes = b"botsmaster/hybrid-kem/v1", length: int = 32) -> bytes:
    """HKDF-SHA512 over the concatenation of the classical + PQC shared secrets.
    Order-sensitive: callers must pass secrets in a fixed order on both ends."""
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt,
                info=info).derive(b"".join(secrets))
