#!/bin/bash
# launch.sh — container entrypoint for the VAC Rust server.
# Self-contained: installs RustDedicated if missing, loads Carbon (Doorstop),
# sets up the native lib path, then starts the game.
set -euo pipefail

cd /steamcmd/rust

# Install/update RustDedicated into this volume if missing (steamcmd on PATH).
if [ ! -x ./RustDedicated ]; then
  echo "[launch] Installing RustDedicated via steamcmd (first boot ~5-15 min)..."
  steamcmd +force_install_dir /steamcmd/rust +login anonymous \
    +app_update 258550 validate +quit 2>&1 | tail -5
fi
if [ ! -x ./RustDedicated ]; then
  echo "[launch] ERROR: RustDedicated still missing after install"
  exit 1
fi

# Load Carbon (Doorstop). Note: CARBONENV_BASEDIR is derived from BASH_SOURCE
# as /steamcmd/rust/../../ => / . We want it to resolve to /steamcmd/rust, so
# run with cwd=/steamcmd/rust (done above) and source by path.
# shellcheck disable=SC1091
source ./carbon/tools/environment.sh || true

# native lib (libvac_integrity.so) must be on LD_LIBRARY_PATH for P/Invoke.
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/steamcmd/rust/carbon/native"

exec ./RustDedicated -batchmode -load -nographics \
  +server.port 28015 +server.queryport 28016 +server.identity docker \
  +server.worldsize "$WORLDSIZE" +server.seed "$VAC_SEED" \
  +server.hostname "VAC Server" +server.maxplayers 50 \
  $EXTRA_ARGS \
  +rcon.port 28016 +rcon.password "$RCON_PASSWORD" +rcon.web 1 \
  +app.port 28082 -logfile /dev/stdout
