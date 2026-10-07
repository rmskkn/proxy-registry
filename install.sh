#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/registry-proxy"
CONFIG_FILE="$CONFIG_DIR/config"
BIN="$SCRIPT_DIR/registry-proxy"
DEST_BIN="/usr/bin/registry-proxy"

if ! command -v go >/dev/null 2>&1; then
	echo "error: go not found in PATH" && exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "error: docker not found in PATH; required to run aria2c" && exit 1
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

docker build -t registry-proxy-aria2:local "$SCRIPT_DIR/docker/aria2"

SERVICE_FILE="/etc/systemd/system/registry-proxy.service"
SERVICE_TEMPLATE="$SCRIPT_DIR/registry-proxy.service.in"
LISTEN_PORT="$(grep -E '^[[:space:]]*listen[[:space:]]*=' "$CONFIG_FILE" | sed -E 's/^[^=]*=[[:space:]]*//; s/.*://')"

[ -z "$LISTEN_PORT" ] && echo "Listening port is not declared" && exit 1

sudo cp "$BIN" "$DEST_BIN"
# Service runs as this user; must be in docker group for aria2c access.
if ! id -nG | tr ' ' '\n' | grep -qx docker; then
	echo "error: $(id -un) is not in the docker group; the service runs as that user and needs docker access" && exit 1
fi

sed -e "s|__BIN__|$DEST_BIN|"  -e "s|__PORT__|$LISTEN_PORT|" -e "s|__HOME__|$HOME|" -e "s|__USER__|$(id -un)|" -e "s|__GROUP__|$(id -gn)|" "$SERVICE_TEMPLATE" | sudo tee "$SERVICE_FILE"
