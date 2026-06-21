# Review — ADVANCED_SECURE_ENVIRONMENT (BMSR-cyber)

Reviewed commit `7ed9730` (2026-06-18), against the threat model: untrusted
prop-firm host AND untrusted cloud host, **no** secure hardware available
(user's stated constraint).

## Verdict in one line

The **architecture is correct and refreshingly honest**; the **implementation is
a staging prototype whose trust-critical core is stubbed**; and it **fundamentally
requires the SEV-SNP hardware it is designed for** — without that hardware it
cannot deliver its guarantee, only its executor/hygiene parts are reusable.

## Does it work WITHOUT the secure hardware? No — by design, and that's correct.

The entire guarantee is the CPU encrypting VM memory so the hypervisor/operator
cannot read it. There is **no software substitute** for memory encryption against
a root host. The code enforces this honestly: `TEEAttestation.detect()` raises
without `/dev/sev-guest`; there is no fallback. On a standard VM it refuses to
proceed. That is the right behaviour, not a bug.

So "make it work without hardware" is not achievable for the *guarantee*. Two
real paths:

### Path A (recommended) — the hardware is commodity and cheap
SEV-SNP is not exotic. This repo already targets `n2d-standard-2` / C3D / AWS
m6a — pennies/hour. The guarantee is one command away:
`gcloud compute instances create ... --confidential-compute-type=SEV_SNP
--min-cpu-platform="AMD Milan"`. If the IP is worth this much effort, **getting
one SEV-SNP instance is far higher leverage than pushing software obfuscation
past its theoretical ceiling.** Reconsider the "no hardware" decision.

### Path B (no TEE at all) — salvage the cost-raising parts only
Reusable WITHOUT hardware (raise cost, do NOT guarantee):
- **`signed_order_intent.py`** — dumb signed-order executor with **coarse size
  banding + batch emission windows + Ed25519**. Genuinely valuable: it is a more
  evolved version of the `split/` executor (#1), adding side-channel hardening so
  the *order stream itself* doesn't leak the strategy. Fold these ideas into
  `split/`.
- `ProtectedMemory` (mlock + MADV_DONTDUMP), `SecureZeroizer`, `EnforceLockdown`,
  `ReplayCache` — reduce swap/coredump/casual-scrape leakage. Hygiene, not a wall.
- Against a root operator with live RAM access, none of this stops extraction.

## Code review — NOT safe to rely on even WITH hardware yet

The README is honest about most gaps (good). Concrete, verified issues:

1. **CRITICAL: `verify_attestation_report` does not verify AMD's signature
   chain.** It only compares the 48 measurement bytes (`report[0xA0:0xA0+48]`),
   which are themselves unauthenticated. A forged report carrying the right
   measurement passes. Comment admits "measurement match is the minimum bar";
   VCEK→ASK→ARK verification is a TODO. → Local verification is attestation
   theatre until the chain is checked.
2. **Production gating documented but not implemented.** `main()` has no
   `--production` flag and constructs `CloudProtection(...)` without
   `production=`, so it defaults `False`. Therefore `EnforceLockdown.check()` and
   the tmpfs gate **never fire**, and the insecure local path is always allowed.
   README's "[ ] Local attestation path refuses production mode" is correctly
   unchecked — but other docs overclaim "production-grade".
3. **Attestation fetch likely won't run on real N2D.** `_fetch_sev_snp_report`
   does `f.write(req); f.read()` on `/dev/sev-guest`; the real Linux ABI is an
   `ioctl(SNP_GET_REPORT)` with structured req/resp (needs `fcntl.ioctl`, not
   file write/read). `_fetch_sev_snp_ext_report` names an ioctl constant but
   still uses write/read. (README: "[ ] real ioctl verified" — unchecked.)
4. **"Zero-copy key" claim violated in the same file.** `key.read()[:32]
   .tobytes()` (aes_gcm_seal/open) and `HKDF(...).derive(...)` create
   GC-managed `bytes` copies OUTSIDE the locked buffer. "Intentional key
   serialization is impossible" is overstated. Moot under SEV (RAM encrypted);
   matters without it. Their own fix — move unwrap to Rust/C — is correct.
5. KRS client is plain `urllib`, no mTLS/pinning yet (acknowledged).
6. `ContinuousAttestationMonitor` re-checks only the (unauthenticated)
   measurement locally and never re-validates via the KRS — weak drift detection.

## To make it genuinely real (with hardware), in priority order
a. Real `SNP_GET_REPORT` ioctl via `fcntl.ioctl`.
b. Full **VCEK→ASK→ARK signature chain** + policy/TCB/nonce/report_data
   verification — use AMD `snpguest` / `sev-snp-measure` / the virtee Rust libs,
   do NOT hand-roll.
c. KRS **mTLS + pinned identity** + the checks in `KRS_POLICY.md`.
d. Wire `--production` to refuse the local path and enforce tmpfs + lockdown.
e. Move key unwrap to a small Rust/C helper for the real zero-copy property.

Until (a)+(b) exist, the attestation verifies nothing cryptographically.

## Bottom line for our build
- This repo is your own (correct) attempt at the **CVM + attestation** answer I
  described — it confirms the right architecture and that you *can* do
  confidential computing on commodity cloud.
- As-is + no hardware: use only `signed_order_intent.py` + the memory-hygiene
  classes as best-effort, merged with the obfuscation pipeline and the `split/`
  executor. Be explicit it is cost-raising, not a guarantee.
- Strongest move by far: provision one SEV-SNP instance and finish items (a)–(e).
