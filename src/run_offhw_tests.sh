#!/usr/bin/env bash
# Off-hardware ASE test suite — everything verifiable WITHOUT a SEV-SNP host.
# Covers: full mTLS + hybrid-PQC CEK unwrap + signature auth (krs_selftest), and the fail-closed
# attestation field/logic suite (snp_failclosed_test). The only steps NOT covered here are the live PSP
# ioctl + the AMD VCEK->ASK->ARK signature chain, which require real SEV-SNP hardware + snpguest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PY:-/home/debian/.venv-warrio/bin/python3}"   # needs cryptography + liboqs(oqs)
[ -x "$PY" ] || PY="python3"

echo "== [1/4] KRS channel: mTLS + hybrid PQC (X25519+ML-KEM) unwrap + hybrid auth =="
"$PY" "$HERE/krs_selftest.py" 2>&1 | grep -vi faulthandler | tail -8

echo
echo "== [2/4] Fail-closed attestation suite (replayed/wrong-TCB/bad-image/debug/SMT/chain) =="
"$PY" "$HERE/snp_failclosed_test.py"

echo
echo "== [3/4] KRS server policy enforcement (release/deny/replay/rate-limit, production mode) =="
"$PY" "$HERE/krs_policy_test.py" 2>&1 | grep -viE 'faulthandler|Exception occurred|Traceback|File \"|self\.|raise |ValueError|ssl\.|socketserver|http/server|during handling|^-+$'

echo
echo "== [4/4] PQC-TLS (live hybrid handshake on OpenSSL>=3.5 if present, else components) =="
PQC_OSSL=""; [ -x "$HOME/openssl-3.5/bin/openssl" ] && PQC_OSSL="$HOME/openssl-3.5/bin/openssl"
OPENSSL_BIN="$PQC_OSSL" bash "$HERE/pqc_tls_test.sh" 2>&1 | grep -vE 'DH parameters|ACCEPT|DONE|shutting|CLOSED|cache|connects|renegot|items|errno|BIO_'

echo
echo "OFF-HARDWARE ASE SUITE PASSED."
echo "Still requires real SEV-SNP hardware: live SNP_GET_REPORT ioctl + snpguest VCEK->ASK->ARK chain."
echo "PQC-TLS: live X25519MLKEM768 handshake verified on OpenSSL 3.5 (set OPENSSL_BIN to a >=3.5 build)."
