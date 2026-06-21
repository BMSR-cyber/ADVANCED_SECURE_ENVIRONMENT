#!/usr/bin/env python3
"""
ctypes binding to the Rust key_unwrap cdylib.

Performs HKDF-SHA512 + AES-256-GCM open in Rust, where the master key, derived
subkey and HKDF state are `Zeroizing` (wiped on drop) instead of GC-managed
Python bytes. Python passes the master key straight through from a locked buffer
and receives only the final plaintext.

Blob format matches aes_gcm_seal in cloud_protection.py: salt(16)||nonce(12)||ct.

If the library is not built, `available()` is False; callers decide whether to
fall back (development) or fail closed (production).
"""
from __future__ import annotations

import ctypes
from pathlib import Path
from typing import Optional

_LIB_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "key_unwrap" / "target" / "release" / "libkey_unwrap.so",
    Path("/usr/local/lib/libkey_unwrap.so"),
]

_lib: Optional[ctypes.CDLL] = None


def _load() -> Optional[ctypes.CDLL]:
    global _lib
    if _lib is not None:
        return _lib
    for p in _LIB_CANDIDATES:
        if p.exists():
            lib = ctypes.CDLL(str(p))
            lib.bmsr_hkdf_aesgcm_open.restype = ctypes.c_int32
            lib.bmsr_hkdf_aesgcm_open.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,   # master
                ctypes.c_char_p, ctypes.c_size_t,   # salt
                ctypes.c_char_p, ctypes.c_size_t,   # nonce
                ctypes.c_char_p, ctypes.c_size_t,   # ct
                ctypes.c_char_p, ctypes.c_size_t,   # aad
                ctypes.c_char_p, ctypes.c_size_t,   # out, out_cap
                ctypes.POINTER(ctypes.c_size_t),    # out_len
            ]
            _lib = lib
            return _lib
    return None


def available() -> bool:
    return _load() is not None


class RustUnwrapError(RuntimeError):
    pass


def hkdf_aesgcm_open(master: bytes, blob: bytes, aad: bytes) -> bytes:
    """Open salt||nonce||ct using the Rust path. `master` >= 32 bytes."""
    lib = _load()
    if lib is None:
        raise RustUnwrapError("libkey_unwrap.so not built; run `cargo build "
                              "--release` in key_unwrap/")
    if len(blob) < 16 + 12 + 16:
        raise RustUnwrapError("blob too short")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    out_cap = len(ct) - 16
    out = ctypes.create_string_buffer(max(out_cap, 1))
    out_len = ctypes.c_size_t(0)
    rc = lib.bmsr_hkdf_aesgcm_open(
        master, len(master),
        salt, len(salt),
        nonce, len(nonce),
        ct, len(ct),
        aad, len(aad),
        out, out_cap, ctypes.byref(out_len),
    )
    if rc != 0:
        raise RustUnwrapError(f"rust unwrap failed: code {rc}")
    return out.raw[:out_len.value]
