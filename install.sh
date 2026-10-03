#!/usr/bin/env bash
# Builds registry-proxy and populates ~/registry-proxy/config with defaults
# (without overwriting an existing config).
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

SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/registry-proxy.service"

if command -v systemctl >/dev/null 2>&1; then
	mkdir -p "$SYSTEMD_USER_DIR"
	sed -e "s|__BIN__|$BIN|" -e "s|__WORKDIR__|$SCRIPT_DIR|" \
		"$SCRIPT_DIR/registry-proxy.service" >"$SERVICE_FILE"
	systemctl --user daemon-reload
	echo "systemd user service installed: $SERVICE_FILE"
	echo "start + persist across logout: loginctl enable-linger \$USER && systemctl --user enable --now registry-proxy"
	echo "logs: journalctl --user -u registry-proxy -f"
else
	echo "systemctl not found; skipping systemd service setup"
fi

echo "done. run: $BIN"
