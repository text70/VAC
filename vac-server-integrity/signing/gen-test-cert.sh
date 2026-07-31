#!/usr/bin/env bash
# Generate a SELF-SIGNED code-signing cert for TESTING the signing pipeline only.
#
# WARNING: A self-signed cert is NOT trusted by Windows/SmartScreen and is NOT
# a replacement for a real code-signing identity. It exists so the sign+verify
# gate in installer/build.cmd and kmod-win/build.cmd can be exercised end-to-end.
#
# Production signing should use:
#   - Microsoft Trusted Signing (Azure)  ~$10/mo, OS-trusted  <-- TODO: switch to this
#   - or a real EV cert (SSL.com/DigiCert/Sectigo)  $200-500/yr, required for
#     kernel-mode driver attestation signing via Partner Center.
#
# Usage: signing/gen-test-cert.sh [output.p12] [password]
#   default output : signing/test-cert.p12
#   default pass   : vac-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$SCRIPT_DIR/test-cert.p12}"
PASS="${2:-vac-test}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

KEY="$TMP/test-cert.key"
CRT="$TMP/test-cert.crt"

echo "[gen-test-cert] Creating self-signed code-signing key..."
openssl genrsa -out "$KEY" 2048 2>/dev/null

echo "[gen-test-cert] Creating self-signed cert (codeSigning EKU, 3650 days)..."
openssl req -new -x509 \
    -key "$KEY" \
    -out "$CRT" \
    -days 3650 \
    -subj "/CN=VAC Test Signing (DO NOT TRUST)/O=VAC Test/ST=Test/C=US" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"

echo "[gen-test-cert] Packaging into $OUT ..."
openssl pkcs12 -export \
    -inkey "$KEY" \
    -in "$CRT" \
    -out "$OUT" \
    -passout "pass:$PASS"

# Also emit the leaf cert as PEM so the signing gate can use it as -CAfile
# (self-signed certs are their own trust anchor).
CRT_OUT="${OUT%.p12}.crt"
cp "$CRT" "$CRT_OUT"

echo "[gen-test-cert] Done: $OUT (password: $PASS)"
echo "[gen-test-cert] Cert: $CRT_OUT (pass to sign.cmd as VAC_SIGN_CAFILE)"
echo "[gen-test-cert] NOTE: self-signed. NOT trusted by Windows. Test pipeline only."
