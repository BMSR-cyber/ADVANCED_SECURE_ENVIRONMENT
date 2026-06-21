#!/usr/bin/env python3
"""
Hybrid (classical + PQC) signature + KEM-wrap helpers for the KRS.

Authentication = Ed25519 AND ML-DSA-65 (both must verify). CEK confidentiality =
X25519 ECDH AND ML-KEM-768 encapsulation, combined via HKDF. Secure if EITHER
half of each pair is unbroken. Symmetric AES-256-GCM is already quantum-safe.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import pqc

WRAP_INFO = b"botsmaster/krs-cek-hybrid-wrap/v1"


def frame(parts):
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def unframe(blob):
    out, i = [], 0
    while i < len(blob):
        (n,) = struct.unpack(">I", blob[i:i + 4]); i += 4
        out.append(blob[i:i + n]); i += n
    return out


# ── hybrid signatures ────────────────────────────────────────────────────────

def hybrid_sign(ed_priv: Ed25519PrivateKey, mldsa_sk: bytes, msg: bytes) -> bytes:
    return frame([ed_priv.sign(msg), pqc.sig_sign(mldsa_sk, msg)])


def hybrid_verify(ed_pub: Ed25519PublicKey, mldsa_pub: bytes,
                  msg: bytes, sig_blob: bytes) -> bool:
    """True only if BOTH the Ed25519 and the ML-DSA signature verify."""
    parts = unframe(sig_blob)
    if len(parts) != 2:
        return False
    ed_sig, mldsa_sig = parts
    try:
        ed_pub.verify(ed_sig, msg)
    except Exception:
        return False
    return pqc.sig_verify(mldsa_pub, msg, mldsa_sig)


# ── hybrid CEK wrap (KRS side) / unwrap (VM side) ────────────────────────────

def _wrap_key(ss_classical: bytes, ss_pqc: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=salt,
                info=WRAP_INFO).derive(ss_classical + ss_pqc)


def wrap_cek(client_x_pub: bytes, client_kem_pub: bytes, cek: bytes):
    """KRS side: returns (krs_x_pub, kem_ct, wrapped=nonce||ct)."""
    krs_x = X25519PrivateKey.generate()
    krs_x_pub = krs_x.public_key().public_bytes_raw()
    ss_classical = krs_x.exchange(X25519PublicKey.from_public_bytes(client_x_pub))
    kem_ct, ss_pqc = pqc.kem_encap(client_kem_pub)
    salt = client_x_pub + client_kem_pub + krs_x_pub
    import os
    nonce = os.urandom(12)
    ct = AESGCM(_wrap_key(ss_classical, ss_pqc, salt)).encrypt(nonce, cek, None)
    return krs_x_pub, kem_ct, nonce + ct


def unwrap_cek(x_eph: X25519PrivateKey, kem: "pqc.KemPrivate",
               client_x_pub: bytes, client_kem_pub: bytes,
               krs_x_pub: bytes, kem_ct: bytes, wrapped: bytes) -> bytes:
    """VM side: reverse of wrap_cek using the attested ephemeral keys."""
    ss_classical = x_eph.exchange(X25519PublicKey.from_public_bytes(krs_x_pub))
    ss_pqc = kem.decap(kem_ct)
    salt = client_x_pub + client_kem_pub + krs_x_pub
    return AESGCM(_wrap_key(ss_classical, ss_pqc, salt)).decrypt(
        wrapped[:12], wrapped[12:], None)
