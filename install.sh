#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/registry-proxy"
CONFIG_FILE="$CONFIG_DIR/config"
BIN="$SCRIPT_DIR/registry-proxy"

if ! command -v go >/dev/null 2>&1; then
	echo "error: go not found in PATH" >&2
	exit 1
fi

if ! command -v aria2c >/dev/null 2>&1; then
	echo "warning: aria2c not found in PATH; install the 'aria2' package before running registry-proxy" >&2
fi

echo "building $BIN"
go build -o "$BIN" "$SCRIPT_DIR/cmd/registry-proxy"

mkdir -p "$CONFIG_DIR"

if [ -e "$CONFIG_FILE" ]; then
	echo "config already exists, leaving it untouched: $CONFIG_FILE"
else
	echo "writing default config: $CONFIG_FILE"
	cp "$SCRIPT_DIR/config.example" "$CONFIG_FILE"
fi

SERVICE_FILE="/etc/systemd/system/registry-proxy.service"
SERVICE_TEMPLATE="$SCRIPT_DIR/registry-proxy-mitm.service.in"
LISTEN_PORT="$(grep -E '^[[:space:]]*listen[[:space:]]*=' "$CONFIG_FILE" | sed -E 's/^[^=]*=[[:space:]]*//; s/.*://')"

[ -z "$LISTEN_PORT" ] && echo "Listening port is not declared" && exit 1

sed -e "s|__BIN__|$BIN|" -e "s|__WORKDIR__|$SCRIPT_DIR|" -e "s|__PORT__|$LISTEN_PORT|" -e "s|__HOME__|$HOME|" "$SERVICE_TEMPLATE" | sudo tee "$SERVICE_FILE"

