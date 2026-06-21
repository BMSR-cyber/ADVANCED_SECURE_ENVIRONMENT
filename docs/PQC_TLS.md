# Post-Quantum Cryptography posture & TLS migration

## Where we stand
Hybrid PQC (classical **+** PQC, secure if either holds), tiered:

| Layer | Primitive | PQC status |
|:---|:---|:---|
| Symmetric (AES-256-GCM, HKDF-SHA512, LLVM keystream) | — | ✅ already quantum-safe (AES-256 = 128-bit vs Grover) |
| **App-layer KRS CEK wrap** | X25519 **+ ML-KEM-768** (hybrid, HKDF-combined) | ✅ implemented (`krs_client`/`krs_server`, `pqc.py`) |
| **App-layer KRS / channel auth** | Ed25519 **+ ML-DSA-65** (both must verify) | ✅ implemented |
| **Split channel KEX/auth** | X25519+ML-KEM-768 / Ed25519+ML-DSA-65 | ✅ implemented (`split/protocol.py`) |
| **TLS 1.3 transport (KRS mTLS)** | X25519 + classical certs | ⚠️ classical **for now** — see migration below |

**Why the CEK is already PQC-safe even though the TLS tunnel is classical:** the
CEK is ML-KEM-wrapped and the response is ML-DSA-signed at the application layer,
so a harvest-now-decrypt-later adversary who records the TLS session still cannot
recover the CEK without breaking ML-KEM **and** X25519. TLS PQC is therefore
defense-in-depth, not the thing the secret depends on.

**Why not PQC-TLS inline today:** the Python KRS uses `ssl` over OpenSSL 3.0.20,
which has neither native ML-KEM groups (added in OpenSSL 3.5) nor the oqs-provider
loaded, and Python's `ssl` does not expose hybrid-group selection. PQC-TLS thus
requires either an OpenSSL upgrade or an oqs-provider-fronted terminator (below).

## TLS PQC migration checklist (actionable)
1. **Hybrid KEM + PQC signatures.** Key exchange = `X25519MLKEM768`; auth =
   ML-DSA-65 (or Falcon) certs; prefer **hybrid** through the transition.
2. **TLS 1.3 hybrid key-share** — client+server send both classical and PQC
   shares; the session key needs *both* broken to compromise.
3. **PQC X.509** — issue hybrid or PQC-signed certs; confirm CA / PKI / HSM
   support PQC keys & formats.
4. **PQC-enabled stack** — OpenSSL ≥3.5 (native) or OpenSSL 3.0.x + **oqs-provider**;
   test interop (Chromium/BoringSSL PQC builds, cloud offerings).
5. **Key management** — rotate long-lived keys; store PQC private keys in
   FIPS/PKCS#11/HSM with PQC support; verify backup/restore.
6. **Performance/size** — PQC pubkeys/ciphertexts are larger; tune MTU/fragmentation
   and timeouts; monitor CPU/memory.
7. **Crypto agility** — support multiple algorithms, graceful fallback, track
   standards (FIPS 203/204/205).
8. **Phased rollout** — pilot internal services → critical systems → public.

## Concrete lab test (oqs-provider, hybrid TLS 1.3)
```bash
# 1. liboqs + oqs-provider (build once; needs cmake + openssl dev headers)
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider
cmake -S oqs-provider -B _b -DOPENSSL_ROOT_DIR=/usr -Dliboqs_DIR="$HOME/_oqs/lib/cmake/liboqs"
cmake --build _b && cmake --install _b           # installs oqsprovider.so

# 2. enable the provider (openssl.cnf): add under [provider_sect]
#    oqsprovider = oqs_sect   /   [oqs_sect] activate = 1

# 3. hybrid/PQC server cert (ML-DSA-65)
openssl req -x509 -new -newkey mldsa65 -keyout krs.key -out krs.crt \
  -nodes -subj "/CN=krs.internal" -days 365 -provider oqsprovider -provider default

# 4. hybrid TLS 1.3 handshake, PQC group
openssl s_server -accept 8443 -cert krs.crt -key krs.key -tls1_3 \
  -groups X25519MLKEM768 -provider oqsprovider -provider default &
openssl s_client -connect localhost:8443 -tls1_3 \
  -groups X25519MLKEM768 -provider oqsprovider -provider default </dev/null \
  | grep -i "Negotiated TLS1.3 group"      # expect: X25519MLKEM768
```
(OpenSSL 3.5+ supports `X25519MLKEM768` natively without oqs-provider; group name
under oqs-provider builds may be `x25519_mlkem768`.)

## Recommended path for this project
- **Short term (now):** app-layer hybrid PQC (done) — CEK + auth are PQC-safe.
- **Medium term:** terminate KRS mTLS on **OpenSSL ≥3.5** (native hybrid groups)
  or front it with an **nginx/stunnel** built against oqs-provider; keep the
  app-layer hybrid as belt-and-suspenders. Issue ML-DSA (hybrid) certs from a
  PQC-capable CA/HSM.
- **Crypto agility:** algorithm names are centralized in `pqc.py`
  (`KEM_ALG`/`SIG_ALG`) for a one-line swap as standards evolve.
