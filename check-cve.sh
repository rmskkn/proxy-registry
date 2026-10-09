#!/usr/bin/env bash
# Scans registry-proxy's own Go dependencies for known CVEs via govulncheck and osv-scanner.
set -euo pipefail

export PATH="$PATH:$(go env GOPATH)/bin"

if ! command -v govulncheck >/dev/null 2>&1; then
	echo "govulncheck not found, installing..." >&2
	go install golang.org/x/vuln/cmd/govulncheck@latest
fi

if ! command -v osv-scanner >/dev/null 2>&1; then
	echo "osv-scanner not found, installing..." >&2
	go install github.com/google/osv-scanner/cmd/osv-scanner@latest
fi

govulncheck ./...
osv-scanner scan -r --no-call-analysis=go .
