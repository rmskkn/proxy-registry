#!/usr/bin/env bash
# Scans registry-proxy's own Go dependencies for known CVEs via govulncheck and osv-scanner.
set -euo pipefail

export PATH="$PATH:$(go env GOPATH)/bin"

# go install hits sum.golang.org to verify modules; retry on transient
# sumdb network errors rather than failing outright.
install() {
	for attempt in 1 2 3 4 5; do
		go install "$1" && return 0
		echo "install $1 attempt $attempt failed, retrying in $((attempt * 10))s" >&2
		sleep $((attempt * 10))
	done
	return 1
}

if ! command -v govulncheck >/dev/null 2>&1; then
	echo "govulncheck not found, installing..." >&2
	install golang.org/x/vuln/cmd/govulncheck@latest
fi

if ! command -v osv-scanner >/dev/null 2>&1; then
	echo "osv-scanner not found, installing..." >&2
	install github.com/google/osv-scanner/cmd/osv-scanner@latest
fi

govulncheck ./...
osv-scanner scan -r --no-call-analysis=go .
