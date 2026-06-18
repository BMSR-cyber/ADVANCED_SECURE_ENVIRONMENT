# Side-Channel Hardening: Trade-Output Minimization

Trade output is the richest side channel in any automated trading system.
Every order that hits the wire leaks information: timing, sizing,
direction, frequency. An observer who can see the exchange order stream
can potentially reverse-engineer the strategy's alpha.

This document describes the hardening measures implemented in
`signed_order_intent.py` to eliminate that side channel.

---

## 1. Why Minimal Order Intents Matter

A typical strategy emits orders carrying substantial metadata:

```
{ strategy: "TurtleBreakout_LTC_C+", confidence: 0.87, regime: "trend_high_mom",
  entry_reason: "20d_high_breakout_vol_confirmed", model_version: "v3.2.1",
  symbol: "BTCUSDT", side: "buy", size: 1.374926, stop: 59234.12, target: 61456.78 }
```

This leaks:

| Field             | What an observer learns                                      |
|-------------------|--------------------------------------------------------------|
| `strategy`        | Which alpha is active, enabling targeted adversarial trading |
| `confidence`      | Signal quality — can be used to front-run or fade           |
| `regime`          | Regime detection model output — reveals model sensitivity    |
| `entry_reason`    | The exact rule that triggered — exposes the edge             |
| `model_version`   | Software version — reveals update cadence                    |
| Exact `size`      | Model-derived position sizing — can be precisely reversed    |
| Exact `stop`/`tgt`| Strategy-specific RR parameters                              |

The **minimal OrderIntent** strips all of this:

```python
@dataclass
class OrderIntent:
    symbol: str          # "BTCUSDT"
    side: int            # +1 buy, -1 sell
    size: float          # base quantity (coarse-banded)
    stop_price: float    # protective stop
    target_price: float  # take-profit target
    timestamp: int       # unix epoch seconds
    intent_id: str       # random nonce (anti-replay)
    public_key_hash: str # SHA-256 of signing key
    signature: str       # Ed25519 over all fields
```

No strategy name. No confidence. No regime. No entry reason. No model
version. An observer sees only: *someone* wants to buy N units of X
with a stop at Y and a target at Z, signed by a known key.

---

## 2. Coarse Size Banding

**Problem:** Even if strategy name is removed, exact order sizes
(e.g. 1.374926, 3.8912) reveal the model's position-sizing function.
From a stream of such sizes, an observer can fit the Kelly-criterion
parameters and volatility estimates that produced them.

**Solution:** Round all sizes to coarse power-of-2 bands:

```python
POWER_OF_TWO_BANDS = [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, ...]

def coarse_band(size: float) -> float:
    return min(POWER_OF_TWO_BANDS, key=lambda b: abs(b - size))
```

A strategy request for 1.374926 BTC becomes 1.0 BTC on the wire.
A strategy request for 3.8912 BTC becomes 4.0 BTC.
A strategy request for 6.2 BTC becomes 8.0 BTC.

**Why power-of-2?** Because it's the coarsest plausible scheme that
still respects position-sizing semantics. An observer cannot distinguish
between a model that wanted 1.1 and one that wanted 1.4 — they both
round to 1.0. The information content per order drops dramatically.

The band list is customizable via `IntentBuilder(..., bands=[...])`
for strategies with atypical sizing ranges.

---

## 3. Batch Emission Windows

**Problem:** Individual order timing leaks signal-generation timing.
If orders arrive at 09:31:17, 11:02:44, and 14:58:03, an observer
knows the strategy fires on specific bar closes.

**Solution:** Intents accumulate in a pending queue and are emitted
together at the end of a configurable time window:

```python
builder = IntentBuilder(emit_window_seconds=5.0)
builder.enqueue(intent_1)   # emitted at t=5
builder.enqueue(intent_2)   # emitted at t=5
batch = builder.emit_batch(force=False)
# yields [] until window expires, then [intent_1, intent_2] together
```

Key properties:
- Intents within the same window are batched into a single transmission
- An observer cannot tell whether the intents were generated at t=0.1,
  t=2.3, or t=4.9 — only that they appeared at the boundary
- `force=True` allows immediate flush for critical events (circuit
  breaker trip, session close)

Recommended settings:
| Use case        | Window    |
|-----------------|-----------|
| HFT/short-term  | 1-5 sec   |
| Medium-term     | 15-60 sec |
| Daily rotation  | 60-300 sec|

---

## 4. Intent Signing (Ed25519)

**Problem:** Without signing, a man-in-the-middle between the strategy
process and the executor can modify or inject orders.

**Solution:** Every intent is signed with Ed25519:

```python
key = ProtectedSigningKey()
intent = builder.build(symbol="BTCUSDT", side=1, ...)
# intent now contains both public_key_hash and signature
```

The signature covers:
```
intent_id | symbol | side | size | stop_price | target_price | timestamp | public_key_hash
```

The signing key is ephemeral (generated fresh per session) and zeroized
after use. The executor only ever receives the public key, never the
private key.

---

## 5. Executor Verification

**The executor is a dumb pipe.** It knows nothing about strategy.

Its entire logic:

1. Load the public key (from file or environment)
2. For each incoming signed intent:
   a. Verify the Ed25519 signature
   b. Check public_key_hash matches
   c. Check intent_id has not been seen before (replay protection)
   d. Check timestamp is not too old (staleness protection)
   e. If all checks pass: place the order via the exchange API

```python
verifier = IntentVerifier.from_key_file("/etc/trading/signing_pubkey.hex")
for intent in received_batch:
    ok, reason = verifier.verify(intent)
    if ok:
        exchange.create_order(
            symbol=intent.symbol,
            side="buy" if intent.side > 0 else "sell",
            amount=intent.size,
            ...
        )
    else:
        log.error(f"Rejected intent: {reason}")
```

The executor has **zero fields** for strategy metadata. It doesn't
know which strategy generated the intent. It doesn't know the model
version. It doesn't know the confidence or the entry reason or the
regime. It verifies a signature, places an order, reports fills.
That's it.

---

## 6. Priority Hardening Items — Implementation Status

Based on the security review of the combined portfolio system, these
7 items were identified and their status is tracked below:

| # | Item                                      | Status      | Notes                                           |
|---|--------------------------------------------|-------------|-------------------------------------------------|
| 1 | Minimal OrderIntent schema                 | IMPLEMENTED | `signed_order_intent.py` — only execution-essential fields |
| 2 | Coarse size banding to power-of-2          | IMPLEMENTED | `coarse_band()` — prevents exact sizing inference |
| 3 | Batch emission windows                     | IMPLEMENTED | `IntentBuilder.emit_batch()` — prevents timing inference |
| 4 | Ed25519 intent signing with zeroized keys  | IMPLEMENTED | `ProtectedSigningKey` — keys in mutable bytearray, NUL-filled on cleanup |
| 5 | Executor-side verification with replay prot.| IMPLEMENTED | `IntentVerifier` — checks sig, pubkey, nonce, expiry |
| 6 | Remove all strategy metadata from executor | IMPLEMENTED | `OrderIntent` has no strategy/confidence/regime/model fields |
| 7 | Secure key distribution (public key only)  | IMPLEMENTED | Private key never leaves strategy process; executor receives pubkey hex |

### Defense-in-Depth Notes

These 7 items form a coherent defense:

- **Items 1-3** prevent passive observation of the order stream from
  revealing strategy internals (what, how much, when)
- **Items 4-5** prevent active tampering or injection of orders
  (integrity and authenticity)
- **Items 6-7** enforce the trust boundary: the executor receives
  authenticated but information-free orders; the strategy's alpha
  never crosses the trust boundary

### Threat Model

| Threat                                       | Mitigation                                  |
|----------------------------------------------|---------------------------------------------|
| Exchange operator observes order patterns    | Minimal schema, coarse bands, batch windows |
| Network attacker injects orders              | Ed25519 signatures, replay protection       |
| Compromised executor machine                 | Executor has only public key, no strategy data |
| Side-channel via exact order sizing          | Power-of-2 coarse banding                   |
| Side-channel via order timing                | Batch emission at window boundaries         |
| Replay of captured valid intents             | Random intent_id, per-session seen-ID set   |
| Memory dump of strategy process              | Keys in mutable bytearray, zeroized after use |

---

## Operational Notes

### Key Rotation

Signing keys are ephemeral (per-session). On restart, generate a new
keypair and deliver the public key to the executor. This limits the
blast radius of any hypothetical key compromise.

### Transport

Signed intents should travel over an authenticated, encrypted channel
(e.g. TLS, WireGuard). The Ed25519 signature provides integrity and
authentication *within* that channel, ensuring that if the transport
is compromised, the executor still rejects forged or modified intents.

### Monitoring

Alert on:
- `IntentVerifier.verify()` returning `replayed intent_id` (possible
  replay attack or proxy misconfiguration)
- `IntentVerifier.verify()` returning `invalid signature` (possible
  tampering or key mismatch)
- `IntentBuilder.emit_batch()` returning empty batches for extended
  periods (possible strategy process stall)
- `IntentBuilder.enqueue()` growing without bounds (possible
  configuration error — window too large or force flag not used)
