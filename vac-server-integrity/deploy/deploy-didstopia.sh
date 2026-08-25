#!/bin/bash
# =============================================================================
# deploy-didstopia.sh — Launch a WORKING VAC/Carbon Rust LAN server.
#
# This is the configuration that was proven to let a Linux/Proton client reach
# "finalize world" (server-side EAC fully neutralised; see
# docs/lan-linux-eac-findings.md). Uses didstopia/rust-server as the base
# (boots reliably, unlike the custom image) + Carbon + SelectiveEAC + the
# `server.encryption 0` lever.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/text70/VAC/main/\
#     vac-server-integrity/deploy/deploy-didstopia.sh | sudo bash
#
# Env overrides (before/exporting): SERVER_IP, WORLDSIZE, ADMIN_STEAMID (you),
# RCON_PASSWORD, ENABLE_CARBON (0/1, default 1)
# =============================================================================
set -euo pipefail

SERVER_IP="${SERVER_IP:-}"
ADMIN_STEAMID="${ADMIN_STEAMID:-}"
WORLDSIZE="${WORLDSIZE:-1000}"
RCON_PASSWORD="${RCON_PASSWORD:-vac-test}"
ENABLE_CARBON="${ENABLE_CARBON:-1}"

echo "=== VAC Rust LAN Server — didstopia base (working config) ==="

# --- 1. deps ---
if ! command -v podman >/dev/null; then
  echo "Installing podman..."
  apt-get update
  apt-get install -y podman podman-compose
fi
if ! command -v wget >/dev/null; then apt-get install -y wget; fi

# --- 2. auto-detect host IP if not given --------------------------------
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)
  [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
fi
echo "  Server IP: $SERVER_IP"

# --- 3. storage volume ---------------------------------------------------
mkdir -p /opt/vac-rustdata

# --- 4. Carbon (optional) ------------------------------------------------
if [ "$ENABLE_CARBON" = "1" ]; then
  CARBON_TGZ="/opt/vac-rustdata/carbon.tar.gz"
  if [ ! -d /opt/vac-rustdata/carbon/tools ]; then
    echo "Installing Carbon..."
    wget -q https://github.com/CarbonCommunity/Carbon/releases/download/production_build/Carbon.Linux.Release.tar.gz -O "$CARBON_TGZ"
    tar -xzf "$CARBON_TGZ" -C /opt/vac-rustdata
    rm -f "$CARBON_TGZ"
  fi
fi

# --- 5. extra game args: EAC fully off --------------------------------
EXTRA_ARGS="+server.anticheattoken 0 +server.strictauth_eac 0 +server.authtimeout 3600 +server.encryption 0"

# --- 6. run -------------------------------------------------------------
podman rm -f rust-server 2>/dev/null || true
podman run -d --name rust-server \
  -e RUST_SERVER_WORLDSIZE="$WORLDSIZE" \
  -e RUST_SERVER_PORT=28015 \
  -e RUST_SERVER_QUERYPORT=28016 \
  -e RUST_SERVER_STARTUP_ARGUMENTS="-batchmode -load -nographics $EXTRA_ARGS" \
  -e RUST_RCON_PASSWORD="$RCON_PASSWORD" \
  -v /opt/vac-rustdata:/steamcmd/rust \
  -p 28015:28015/udp -p 28016:28016/udp -p 28082:28082/tcp \
  didstopia/rust-server:latest

echo ""
echo "=== Done. Join at:  connect $SERVER_IP:28015 ==="
if [ -n "$ADMIN_STEAMID" ]; then
  echo "Granting admin/moderator + SelectiveEAC bypass for $ADMIN_STEAMID ..."
  # The setup operator is registered as an admin/operator so they can use
  # the Carbon admin panel (/cpanel, no leading slash). Best-effort right
  # after start; re-run post 'Server startup complete' if it didn't persist.
  # player is created/joined here too as a baseline group applied to all players.
  grant() { podman exec rust-server rcon "$1" >/dev/null 2>&1 || true; }
  grant "oxide.usergroup add $ADMIN_STEAMID admin"
  grant "oxide.usergroup add $ADMIN_STEAMID moderator"
  grant "c.grant user $ADMIN_STEAMID selectiveeac.use"
  grant "c.usergroup add $ADMIN_STEAMID selectiveeac"
  # Ensure the standard 'players' group exists (all players fall into it)
  grant "c.group create players"
  echo "Registered operator $ADMIN_STEAMID in groups: admin, moderator, selectiveeac."
  echo "Created standard group: players"
fi
echo "Wait for 'Server startup complete' in: podman logs -f rust-server"
echo "If you set ADMIN_STEAMID, after startup re-run the rcon lines above"
echo "(the container may not have been ready during first deployment)."