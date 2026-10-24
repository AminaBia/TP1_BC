#!/bin/bash
# Builds the consortium CA and issues certificates for alice, bob, carol, dave.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$ROOT/ca"
NODES_DIR="$ROOT/nodes"

if [ -f "$CA_DIR/ca.key" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "CA already exists. Re-run with FORCE=1 to regenerate everything." >&2
  exit 1
fi
rm -rf "$CA_DIR" "$NODES_DIR"
mkdir -p "$CA_DIR" "$NODES_DIR"

# --- Root CA (EC P-256, self-signed, 10 years) ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA_DIR/ca.key"
chmod 600 "$CA_DIR/ca.key"
openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days 3650 \
  -subj "/C=DZ/O=Consortium/CN=Consortium Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$CA_DIR/ca.crt"
echo "== CA: $(openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/ca.crt")"

# --- Node certificates (1 year) ---
for name in alice bob carol dave; do
  d="$NODES_DIR/$name"
  mkdir -p "$d"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$d/$name.key"
  chmod 600 "$d/$name.key"
  openssl req -new -key "$d/$name.key" \
    -subj "/C=DZ/O=Consortium/CN=$name" -out "$d/$name.csr"

  cat > "$d/ext.cnf" << EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$name,DNS:localhost,IP:127.0.0.1
EXT

  openssl x509 -req -in "$d/$name.csr" \
    -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
    -days 365 -sha256 -extfile "$d/ext.cnf" -out "$d/$name.crt" 2>/dev/null
  echo "== $name: $(openssl verify -CAfile "$CA_DIR/ca.crt" "$d/$name.crt")"
done
