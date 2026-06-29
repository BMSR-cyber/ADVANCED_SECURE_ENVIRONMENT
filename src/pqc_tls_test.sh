#!/usr/bin/env bash
# PQC-TLS transport test (off-hardware). Works in two modes:
#   * OpenSSL >= 3.5 (native ML-KEM/ML-DSA): asserts a FULL live hybrid TLS 1.3 handshake over
#     X25519MLKEM768 — no provider needed.
#   * OpenSSL 3.0.x + oqs-provider: verifies the PQC building blocks (ML-DSA-65/ML-KEM-768 algs + certs);
#     the live hybrid handshake is informational (known provider/version interop gap, alert 40).
#
# Point at a locally-built 3.5:  OPENSSL_BIN=$HOME/openssl-3.5/bin/openssl bash pqc_tls_test.sh
# (the secret-bearing layers are already PQC-safe at the app layer; this is transport defense-in-depth.)
set -euo pipefail
OSSL="${OPENSSL_BIN:-openssl}"
LIBDIR="$(dirname "$(dirname "$OSSL")")/lib64"; [ -d "$LIBDIR" ] || LIBDIR="$(dirname "$(dirname "$OSSL")")/lib"
export LD_LIBRARY_PATH="$LIBDIR:${LD_LIBRARY_PATH:-}"
VER="$("$OSSL" version 2>/dev/null | awk '{print $2}')"
case "$VER" in 3.5*|3.6*|3.7*|3.8*|3.9*|4.*) NATIVE=1;; *) NATIVE=0;; esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true' EXIT
ok=1
echo "== PQC-TLS ($OSSL -> OpenSSL $VER, native_pqc=$NATIVE) =="

if [ "$NATIVE" = 0 ]; then
  export OPENSSL_CONF="${OPENSSL_CONF:-$HOME/_oqs/openssl-pqc.cnf}" OPENSSL_MODULES="${OPENSSL_MODULES:-$HOME/_oqs/lib}"
  [ -f "$OPENSSL_MODULES/oqsprovider.so" ] || { echo "  oqs-provider missing at $OPENSSL_MODULES"; exit 1; }
else
  # native build may not ship a default openssl.cnf; req/s_server need one — fall back to a system cnf
  _d="$(dirname "$(dirname "$OSSL")")/ssl/openssl.cnf"
  [ -f "$_d" ] || for c in /etc/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf; do [ -f "$c" ] && _d="$c" && break; done
  export OPENSSL_CONF="$_d"
fi

# PQC algorithms available (native in 3.5, via oqs-provider in 3.0.x)
"$OSSL" list -signature-algorithms 2>/dev/null | grep -qiE 'mldsa.?65|ML-DSA-65' && echo "  PASS ML-DSA-65 (FIPS 204) signature" || { echo "  FAIL ML-DSA-65"; ok=0; }
"$OSSL" list -kem-algorithms 2>/dev/null | grep -qiE 'mlkem.?768|ML-KEM-768' && echo "  PASS ML-KEM-768 (FIPS 203) KEM" || { echo "  FAIL ML-KEM-768"; ok=0; }

echo "== live hybrid TLS 1.3 handshake (X25519MLKEM768) =="
"$OSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$TMP/ek" -out "$TMP/ec" -nodes -subj "/CN=krs" -days 1 >/dev/null 2>&1
P=$(( (RANDOM%20000)+24000 ))
"$OSSL" s_server -accept "$P" -cert "$TMP/ec" -key "$TMP/ek" -tls1_3 -groups X25519MLKEM768 -www >/dev/null 2>&1 &
SRV=$!
for _ in $(seq 1 40); do (exec 3<>"/dev/tcp/localhost/$P") 2>/dev/null && { exec 3>&- 3<&-; break; }; sleep 0.2; done
HS="$(echo Q | "$OSSL" s_client -connect "localhost:$P" -tls1_3 -groups X25519MLKEM768 2>&1 || true)"
kill "$SRV" 2>/dev/null || true; SRV=""
if echo "$HS" | grep -qiE 'Cipher is TLS|Negotiated.*MLKEM|group: *X25519MLKEM768'; then
  echo "  PASS live hybrid handshake completed over X25519MLKEM768 + ECDSA"
  echo "$HS" | grep -iE 'Negotiated|group|Protocol|Cipher is' | head -3 | sed 's/^/    /'
elif [ "$NATIVE" = 1 ]; then
  echo "  FAIL native OpenSSL>=3.5 did not complete the hybrid handshake"; echo "$HS" | grep -iE 'error|alert' | head -3; ok=0
else
  echo "  PENDING live handshake on OpenSSL $VER (needs >=3.5) — components ready"
fi

[ "$ok" = 1 ] && echo "PQC-TLS: $([ "$NATIVE" = 1 ] && echo 'LIVE HYBRID HANDSHAKE WORKING' || echo 'COMPONENTS READY')" \
              || { echo "PQC-TLS CHECK FAILED"; exit 1; }
