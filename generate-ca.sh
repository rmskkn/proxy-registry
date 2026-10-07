#!/usr/bin/env bash
# Generates a self-signed root CA for registry-proxy's transparent-HTTPS
# (mitm-tls) mode and writes it to ca-dir as ca-cert.pem / ca-key.pem.
set -euo pipefail

CA_DIR="${1:-$HOME/registry-proxy/ca}"

if ! command -v openssl >/dev/null 2>&1; then
	echo "error: openssl not found in PATH" >&2
	exit 1
fi

mkdir -p "$CA_DIR"

openssl req -x509 -newkey rsa:2048 -sha256 -days 360 -nodes \
	-keyout "$CA_DIR/ca-key.pem" \
	-out "$CA_DIR/ca-cert.pem" \
	-subj "/CN=registry-proxy local CA/O=registry-proxy" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

echo "CA written: $CA_DIR/ca-cert.pem $CA_DIR/ca-key.pem"
echo ""
echo "To trust this CA, copy the certificate (not the key) into your"
echo "system's trust store and refresh its cache:"
echo ""
echo "  # Debian/Ubuntu"
echo "  sudo cp $CA_DIR/ca-cert.pem /usr/local/share/ca-certificates/registry-proxy.crt"
echo "  sudo update-ca-certificates"
echo ""
echo "  # Arch Linux"
echo "  sudo cp $CA_DIR/ca-cert.pem /etc/ca-certificates/trust-source/anchors/registry-proxy.crt"
echo "  sudo trust extract-compat"

# For url3 pythyon lib clients
cat ~/registry-proxy/ca/ca-cert.pem "$(python3 -c "import certifi; print(certifi.where())")" > ~/registry-proxy/ca/combined-ca-bundle.pem
