#!/usr/bin/env bash
# Scans registry-proxy's own Go dependencies for known CVEs via govulncheck.
set -euo pipefail

export PATH="$PATH:$(go env GOPATH)/bin"

if ! command -v govulncheck >/dev/null 2>&1; then
	echo "govulncheck not found, installing..." >&2
	go install golang.org/x/vuln/cmd/govulncheck@latest
fi

govulncheck ./...
