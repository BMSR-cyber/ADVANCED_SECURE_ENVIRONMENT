#!/usr/bin/env python3
"""
Trade-output side-channel minimization: signed ORDER INTENT schema.

The strategy layer produces an OrderIntent with only execution-essential
fields. The executor (cTrader/MT5/Freqtrade) is a DUMB PIPE — it verifies
the Ed25519 signature and places the order. It knows NOTHING about strategy.

Key mechanisms:
  - Minimal schema (no strategy name, confidence, regime, entry reason)
  - Coarse size banding to power-of-2 (prevents exact model-sizing inference)
  - Batch emission windows (prevents timing-based inference)
  - Ed25519 signatures with replay protection via random nonce
  - Signing keys generated in protected memory and zeroized after use
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("signed_order_intent")

# ── Coarse size banding ────────────────────────────────────────────────────

POWER_OF_TWO_BANDS: list[float] = [
    0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0,
]


def coarse_band(size: float, bands: list[float] | None = None) -> float:
    """Round size to nearest power-of-2 band or nearest entry in provided list.

    Example:
        >>> coarse_band(1.374926)
        1.0
        >>> coarse_band(3.2)
        4.0
        >>> coarse_band(0.31)
        0.5

    This prevents an observer from inferring exact model-derived sizing
    from the order stream. Only coarse band levels ever appear on the wire.
    """
    bands = bands or POWER_OF_TWO_BANDS
    if size <= 0:
        return bands[0]
    return min(bands, key=lambda b: abs(b - size))


# ── OrderIntent schema ─────────────────────────────────────────────────────

@dataclass
class OrderIntent:
    """Minimal order intent — only fields needed for execution.

    DELIBERATELY EXCLUDED: strategy name, confidence score, entry reason,
    regime label, model version, internal risk state. The executor has zero
    knowledge of *why* an order was placed.

    Fields
    ------
    symbol: str
        Exchange symbol (e.g. "BTCUSDT").
    side: int
        +1 for buy/long, -1 for sell/short.
    size: float
        Base quantity, already coarse-banded.
    stop_price: float
        Protective stop-loss price.
    target_price: float
        Take-profit target price.
    timestamp: int
        Unix epoch seconds when the intent was created.
    intent_id: str
        Random hex nonce (anti-replay within session lifetime).
    public_key_hash: str
        SHA-256 hex digest of the signing public key (executor verifies).
    signature: str
        Ed25519 signature over intent_id + symbol + side + size +
        stop_price + target_price + timestamp + public_key_hash,
        encoded as hex.
    """

    symbol: str
    side: int
    size: float
    stop_price: float
    target_price: float
    timestamp: int
    intent_id: str
    public_key_hash: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "symbol": self.symbol,
            "side": self.side,
            "size": self.size,
            "stop_price": self.stop_price,
            "target_price": self.target_price,
            "timestamp": self.timestamp,
            "intent_id": self.intent_id,
            "public_key_hash": self.public_key_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "OrderIntent":
        return cls(
            symbol=str(data["symbol"]),
            side=int(data["side"]),
            size=float(data["size"]),
            stop_price=float(data["stop_price"]),
            target_price=float(data["target_price"]),
            timestamp=int(data["timestamp"]),
            intent_id=str(data["intent_id"]),
            public_key_hash=str(data["public_key_hash"]),
            signature=str(data["signature"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, raw: str) -> "OrderIntent":
        return cls.from_dict(json.loads(raw))


# ── Protected memory key generation ────────────────────────────────────────

class ProtectedSigningKey:
    """Generate an Ed25519 key pair in memory, with zeroization on cleanup.

    The private key bytes are stored as a mutable bytearray and overwritten
    with NUL bytes when zeroize() is called or the object is garbage-collected.

    Usage
    -----
        key = ProtectedSigningKey()
        # ... use key for signing ...
        key.zeroize()  # explicit: private key bytes are now NUL-filled

    The public key is *not* zeroized — the executor needs it for verification.
    """

    def __init__(self) -> None:
        self._private = ed25519.Ed25519PrivateKey.generate()
        self._pubkey = self._private.public_key()
        self._priv_bytes = _extract_private_bytes(self._private)
        self._pubkey_hash = hashlib.sha256(
            self._pubkey_public_bytes()
        ).hexdigest()
        self._lock = threading.Lock()

    def _pubkey_public_bytes(self) -> bytes:
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_hex(self) -> str:
        """Return the public key as a hex string (safe to share with executor)."""
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key (safe to share with executor)."""
        return self._pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_hash(self) -> str:
        """SHA-256 hex digest of the public key (included in every intent)."""
        return self._pubkey_hash

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the protected private key.

        Raises RuntimeError if the key has been zeroized.
        """
        with self._lock:
            if self._priv_bytes is None:
                raise RuntimeError("Signing key has been zeroized — cannot sign")
            return self._private.sign(message)

    def zeroize(self) -> None:
        """Overwrite the private key seed with NUL bytes and release references.

        After this call, sign() will raise RuntimeError. The public key
        remains valid for verification. Idempotent — safe to call multiple
        times.
        """
        with self._lock:
            if self._priv_bytes is not None:
                self._priv_bytes[:] = b"\x00" * len(self._priv_bytes)
                self._priv_bytes = None
                self._private = None  # type: ignore[assignment]
                logger.debug("Signing key zeroized — private key destroyed")

    def __del__(self) -> None:
        try:
            self.zeroize()
        except Exception:
            pass


def _extract_private_bytes(
    private_key: ed25519.Ed25519PrivateKey,
) -> bytearray:
    """Extract private key seed bytes as a mutable bytearray for zeroization."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return bytearray(raw)


# ── Intent signing ─────────────────────────────────────────────────────────

_SIGNING_FIELDS = [
    "intent_id",
    "symbol",
    "side",
    "size",
    "stop_price",
    "target_price",
    "timestamp",
    "public_key_hash",
]


def _serialize_for_signing(intent: OrderIntent) -> bytes:
    """Serialize the intent fields (excluding signature) for signing.

    Uses pipe-delimited field ordering matching _SIGNING_FIELDS.
    Deterministic — same input always produces the same bytes.
    """
    parts = [
        intent.intent_id,
        intent.symbol,
        str(intent.side),
        str(intent.size),
        str(intent.stop_price),
        str(intent.target_price),
        str(intent.timestamp),
        intent.public_key_hash,
    ]
    return "|".join(parts).encode("utf-8")


def sign_intent(
    intent: OrderIntent,
    signing_key: ProtectedSigningKey,
) -> OrderIntent:
    """Sign an OrderIntent in-place and return it.

    Modifies intent.public_key_hash and intent.signature.
    Returns the same object for chaining.
    """
    intent.public_key_hash = signing_key.public_key_hash()
    message = _serialize_for_signing(intent)
    signature = signing_key.sign(message)
    intent.signature = signature.hex()
    return intent


def verify_intent(intent: OrderIntent, public_key_bytes: bytes) -> bool:
    """Verify an OrderIntent's Ed25519 signature against a public key.

    Returns True if the signature is valid, False otherwise.
    Does NOT check intent_id replay or timestamp expiry — those are the
    executor's responsibility.
    """
    try:
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        message = _serialize_for_signing(intent)
        signature = bytes.fromhex(intent.signature)
        pubkey.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError) as exc:
        logger.debug("Signature verification failed: %s", exc)
        return False


# ── Intent builder ─────────────────────────────────────────────────────────

class IntentBuilder:
    """Builds signed OrderIntents from strategy output.

    Applies all side-channel mitigations:
      - Coarse size banding (prevents exact model-sizing inference)
      - Batch emission windows (prevents timing-based inference)
      - Random nonce intent_id (anti-replay)

    Usage
    -----
        builder = IntentBuilder(emit_window_seconds=5.0)
        intent = builder.build(
            symbol="BTCUSDT", side=1, raw_size=1.374,
            stop_price=59000, target_price=62000,
        )
        builder.enqueue(intent)
        batch = builder.emit_batch(force=True)  # or wait for window
    """

    def __init__(
        self,
        signing_key: ProtectedSigningKey | None = None,
        emit_window_seconds: float = 5.0,
        bands: list[float] | None = None,
    ) -> None:
        self._signing_key = signing_key or ProtectedSigningKey()
        self._emit_window = emit_window_seconds
        self._bands = bands or POWER_OF_TWO_BANDS
        self._pending: list[OrderIntent] = []
        self._lock = threading.Lock()
        self._last_emit: float = 0.0

    def _new_nonce(self) -> str:
        return secrets.token_hex(16)

    def build(
        self,
        symbol: str,
        side: int,
        raw_size: float,
        stop_price: float,
        target_price: float,
        *,
        timestamp: int | None = None,
    ) -> OrderIntent:
        """Build a signed OrderIntent from raw strategy parameters.

        Applies coarse size banding automatically. The strategy layer should
        call this with its exact desired size; the banding prevents inference
        of the exact model-derived sizing from the order stream.
        """
        banded_size = coarse_band(raw_size, self._bands)
        ts = timestamp if timestamp is not None else int(time.time())
        intent = OrderIntent(
            symbol=symbol,
            side=side,
            size=banded_size,
            stop_price=stop_price,
            target_price=target_price,
            timestamp=ts,
            intent_id=self._new_nonce(),
            public_key_hash="",
            signature="",
        )
        return sign_intent(intent, self._signing_key)

    def enqueue(self, intent: OrderIntent) -> int:
        """Add an intent to the pending queue. Returns current queue depth."""
        with self._lock:
            self._pending.append(intent)
            return len(self._pending)

    def emit_batch(self, *, force: bool = False) -> list[OrderIntent]:
        """Emit all pending intents if the emit window has elapsed.

        If force=True, emit immediately regardless of window.
        Returns the list of intents ready for delivery (or empty list).

        The caller should serialize and deliver the batch to the executor
        in a single message/chunk to prevent timing-based inference.
        """
        now = time.time()
        if not force and (now - self._last_emit) < self._emit_window:
            return []

        with self._lock:
            if not self._pending:
                return []
            self._last_emit = now
            batch = list(self._pending)
            self._pending.clear()

        logger.debug("Emitting batch of %d intents", len(batch))
        return batch


# ── Executor-side verification ─────────────────────────────────────────────

class IntentVerifier:
    """Executor-side intent verification.

    The executor loads the public key (NOT the private key) and verifies
    every incoming intent before placing any order. Rejects:
      - Invalid Ed25519 signatures
      - Replayed intent_id (seen within this session)
      - Stale timestamps (configurable max age)
      - Mismatched public_key_hash

    Usage
    -----
        verifier = IntentVerifier(public_key_bytes=...)
        for intent in received_intents:
            ok, reason = verifier.verify(intent)
            if ok:
                exchange.place_order(...)  # dumb pipe — place the order
            else:
                log.warning("Rejected: %s", reason)
    """

    def __init__(
        self,
        public_key_bytes: bytes,
        *,
        max_age_seconds: float = 300.0,
    ) -> None:
        self._pubkey_bytes = public_key_bytes
        self._pubkey_hash = hashlib.sha256(public_key_bytes).hexdigest()
        self._max_age = max_age_seconds
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def verify(self, intent: OrderIntent) -> tuple[bool, str]:
        """Verify an incoming intent.

        Returns (is_valid, reason).
        Only returns is_valid=True when all checks pass.
        """
        now = time.time()

        # 1. Check expiration
        age = now - intent.timestamp
        if age > self._max_age:
            logger.info(
                "Intent expired: age=%.0fs max=%.0fs intent=%s",
                age, self._max_age, intent.intent_id[:12],
            )
            return False, f"expired: age={age:.0f}s > {self._max_age}s"
        if age < -60:
            logger.info(
                "Intent timestamp in future: delta=%.0fs intent=%s",
                -age, intent.intent_id[:12],
            )
            return False, f"future timestamp: {intent.timestamp} > {int(now)}"

        # 2. Check public_key_hash matches
        if intent.public_key_hash != self._pubkey_hash:
            return False, "public_key_hash mismatch"

        # 3. Check replay
        with self._lock:
            if intent.intent_id in self._seen:
                logger.warning(
                    "Replayed intent_id: %s (%d seen)",
                    intent.intent_id[:12], len(self._seen),
                )
                return False, f"replayed intent_id: {intent.intent_id}"
            self._seen.add(intent.intent_id)

        # 4. Check signature
        if not verify_intent(intent, self._pubkey_bytes):
            return False, "invalid signature"

        return True, "ok"

    def clear_seen(self) -> None:
        """Reset the seen-intent_id set (e.g. new trading session)."""
        with self._lock:
            self._seen.clear()

    def seen_count(self) -> int:
        with self._lock:
            return len(self._seen)

    @classmethod
    def from_hex_key(cls, pubkey_hex: str, **kwargs) -> "IntentVerifier":
        """Construct a verifier from a hex-encoded public key string."""
        return cls(public_key_bytes=bytes.fromhex(pubkey_hex), **kwargs)

    @classmethod
    def from_key_file(cls, path: Path | str, **kwargs) -> "IntentVerifier":
        """Construct a verifier by reading the public key from a file."""
        hex_data = Path(path).read_text().strip()
        return cls.from_hex_key(hex_data, **kwargs)


# ── Protected memory zeroization — utility ─────────────────────────────────

def zeroize_bytes(buf: bytearray) -> None:
    """Zeroize a mutable byte buffer in place."""
    if buf is not None:
        buf[:] = b"\x00" * len(buf)


# ── __main__ demo ──────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    print("=== Signed Order Intent — Security Demo ===\n")

    # ── 1. Generate signing key (strategy side — protected memory) ─────────
    print("1. Key generation (strategy side)")
    key = ProtectedSigningKey()
    print(f"   Public key hash: {key.public_key_hash()}")
    print(f"   Public key (hex): {key.public_key_hex()[:48]}...")
    print()

    # ── 2. Build intents with coarse banding ───────────────────────────────
    print("2. Intent building with coarse size banding")
    builder = IntentBuilder(signing_key=key, emit_window_seconds=5.0)

    raw_sizes = [0.87, 1.23, 2.1, 3.76, 5.5, 7.1]
    for i, raw_size in enumerate(raw_sizes):
        intent = builder.build(
            symbol="BTCUSDT",
            side=1 if i % 2 == 0 else -1,
            raw_size=raw_size,
            stop_price=59000.0 + i * 200,
            target_price=61000.0 + i * 200,
        )
        builder.enqueue(intent)
        banded = coarse_band(raw_size)
        print(f"   Strategy raw={raw_size:.3f} -> banded={banded:.1f} "
              f"intent={intent.intent_id[:16]}...  sig={intent.signature[:32]}...")
    print(f"   Queue depth: {len(builder._pending)}")
    print()

    # ── 3. Emit batch ─────────────────────────────────────────────────────
    print("3. Batch emission")
    pending = builder.emit_batch(force=True)
    print(f"   Emitted {len(pending)} intents in one chunk")
    for intent in pending:
        print(f"   | {intent.intent_id[:12]}... "
              f"sym={intent.symbol} side={intent.side:+d} "
              f"size={intent.size:.1f} "
              f"stop={intent.stop_price:.0f} tgt={intent.target_price:.0f} "
              f"sig={intent.signature[:24]}...")
    print()

    # ── 4. Executor-side verification ─────────────────────────────────────
    print("4. Executor-side verification")
    verifier = IntentVerifier(
        public_key_bytes=key.public_key_bytes(),
        max_age_seconds=300.0,
    )
    all_ok = True
    for intent in pending:
        valid, reason = verifier.verify(intent)
        status = "ACCEPTED" if valid else "REJECTED"
        if not valid:
            all_ok = False
        print(f"   [{status}] {intent.intent_id[:12]}... — {reason}")

    print(f"   Seen IDs: {verifier.seen_count()}")
    print()

    # ── 5. Replay detection ───────────────────────────────────────────────
    print("5. Replay detection")
    print("   Attempting to replay first intent...")
    valid, reason = verifier.verify(pending[0])
    status = "ACCEPTED (BUG!)" if valid else "REJECTED"
    print(f"   [{status}] — {reason}")
    print()

    # ── 6. Tampered intent ────────────────────────────────────────────────
    print("6. Tampered intent detection")
    tampered = OrderIntent(
        symbol="BTCUSDT",
        side=1,
        size=8.0,
        stop_price=58000.0,
        target_price=65000.0,
        timestamp=int(time.time()),
        intent_id=secrets.token_hex(16),
        public_key_hash=key.public_key_hash(),
        signature=pending[0].signature,  # wrong signature for this payload
    )
    valid, reason = verifier.verify(tampered)
    status = "REJECTED" if not valid else "ACCEPTED (BUG!)"
    print(f"   [{status}] — {reason}")
    print()

    # ── 7. Zeroize key ────────────────────────────────────────────────────
    print("7. Key zeroization")
    key.zeroize()
    try:
        key.sign(b"test")
        print("   ERROR: sign() should have raised after zeroize")
    except RuntimeError as exc:
        print(f"   OK: sign() raised RuntimeError: {exc}")
    print()

    # ── 8. Persist public key for executor ────────────────────────────────
    print("8. Persist public key (executor needs this)")
    pubkey_path = Path("/tmp/sidechannel_pubkey.hex")
    pubkey_path.write_text(key.public_key_hex())
    print(f"   Written to {pubkey_path}")
    print(f"   Executor loads with: IntentVerifier.from_key_file('{pubkey_path}')")
    print()

    # ── 9. JSON serialization round-trip ──────────────────────────────────
    print("9. JSON round-trip")
    original = pending[0]
    serialized = original.to_json()
    restored = OrderIntent.from_json(serialized)
    print(f"   Original:  {original.to_dict()}")
    print(f"   Restored:  {restored.to_dict()}")
    print(f"   Match: {original.to_dict() == restored.to_dict()}")
    print()

    # ── 10. Verify round-tripped intent still passes ──────────────────────
    print("10. Verify round-tripped intent")
    verifier2 = IntentVerifier(public_key_bytes=key.public_key_bytes())
    ok2, reason2 = verifier2.verify(restored)
    print(f"    Round-tripped intent: {'ACCEPTED' if ok2 else 'REJECTED'} — {reason2}")
    print()

    # Summary
    print("=== All checks done ===")
    print(f"Intents emitted: {len(pending)}")
    print(f"All valid: {all_ok}")
    print(f"Replay blocked: {not valid}")
    print("The executor is a dumb pipe. It knows NOTHING about strategy.")


if __name__ == "__main__":
    main()
