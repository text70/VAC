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
# Map seed: random-but-persistent. If VAC_SEED is set, use it. Otherwise reuse
# the previously generated seed (kept in the volume) so redeploys/restarts
# don't reshape the world; on a fresh volume a random seed is generated.
SEED_FILE="/opt/vac-rustdata/.seed"
VAC_SEED="${VAC_SEED:-}"
if [ -z "$VAC_SEED" ] && [ -f "$SEED_FILE" ]; then
  VAC_SEED="$(cat "$SEED_FILE")"
fi
if [ -z "$VAC_SEED" ]; then
  VAC_SEED="$(( RANDOM * 32768 + RANDOM ))1467"  # arbitrary large int
  mkdir -p /opt/vac-rustdata
  printf '%s' "$VAC_SEED" > "$SEED_FILE"
  echo "  Generated random map seed: $VAC_SEED (persisted)"
else
  echo "  Map seed: $VAC_SEED"
fi

echo "=== VAC Rust LAN Server — didstopia base (working config) ==="

# --- 1. deps ---
if ! command -v podman >/dev/null; then
  echo "Installing podman..."
  apt-get update
  apt-get install -y podman podman-compose
fi
if ! command -v wget >/dev/null; then apt-get install -y wget; fi
if ! command -v git >/dev/null; then apt-get install -y git; fi
# C toolchain: Rust needs a C linker (`cc`/gcc) to build crates that link C
# (e.g. libc). Without it, `cargo build` fails on the libc build script.
if ! command -v cc >/dev/null && ! command -v gcc >/dev/null; then
  echo "Installing C toolchain (build-essential)..."
  apt-get update
  apt-get install -y build-essential
fi

# --- 2. auto-detect host IP if not given --------------------------------
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)
  [ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I | awk '{print $1}')
fi
echo "  Server IP: $SERVER_IP"

# --- 3. storage volume ---------------------------------------------------
# Ensure the volume dir exists and is writable by the current user. On a fresh
# host /opt is root-owned; if a previous root run created the dir, the current
# (possibly non-root) user must either own it or write via group.
mkdir -p /opt/vac-rustdata/carbon/native
if [ -w /opt/vac-rustdata ]; then
  : # already writable
elif [ "$(id -u)" = "0" ]; then
  chown "$(id -u):$(id -g)" /opt/vac-rustdata 2>/dev/null || true
else
  echo "  WARNING: /opt/vac-rustdata is not writable by $USER; trying group write..."
  chmod g+w /opt/vac-rustdata 2>/dev/null || true
fi
# Ensure it's actually writable before continuing.
if [ ! -w /opt/vac-rustdata ]; then
  echo "ERROR: cannot write to /opt/vac-rustdata. Re-run as root, or: sudo chown -R \$(whoami):\$(whoami) /opt/vac-rustdata"
  exit 1
fi

# --- 3b. Build + stage the VacIntegrity plugin stack ---------------------
# The plugin is a Carbon .cs plugin plus a native lib + PQC keys. For the
# server to ENFORCE (kick players with no daemon), all must be present in the
# volume. If VAC_BUILD_DIR is unset (or missing artifacts), we BUILD them
# right here from the GitHub repo (Rust toolchain + gen-keys), so no scp is
# needed. Artifacts expected in VAC_BUILD_DIR:
#   libvac_integrity.so  kyber_public.der  kyber_secret.der
#   mldsa65_public.der   mldsa65_secret.der  vac-daemon  VacIntegrity.cs
VAC_BUILD_DIR="${VAC_BUILD_DIR:-/opt/vacbuild}"

build_vacbuild() {
  local need=0
  for f in libvac_integrity.so vac-daemon kyber_public.der kyber_secret.der \
           mldsa65_public.der mldsa65_secret.der VacIntegrity.cs; do
    [ -f "${VAC_BUILD_DIR}/${f}" ] || need=1
  done
  [ "$need" = "0" ] && return 0

  echo "  Building VacIntegrity artifacts in ${VAC_BUILD_DIR} (one-time)..."
  mkdir -p "$VAC_BUILD_DIR"
  local BUILD_SRC="/opt/vacbuild-src"
  rm -rf "$BUILD_SRC"
  git clone -q --depth 1 https://github.com/text70/VAC.git "$BUILD_SRC" || { echo "ERROR: repo clone failed"; exit 1; }
  cd "$BUILD_SRC/vac-server-integrity"

  # Rust toolchain (only needed for this build)
  if ! command -v rustc >/dev/null; then
    echo "    Installing Rust (rustup)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  fi
  # Ensure cargo/rustc are on PATH. rustup installs to $CARGO_HOME (default
  # ~/.cargo); source its env if present, else fall back to common paths.
  if [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck disable=SC1090
    . "${CARGO_HOME:-$HOME/.cargo}/env"
  fi
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  command -v cargo >/dev/null || { echo "ERROR: cargo not found after rustup install"; exit 1; }

  echo "    cargo build (libvac_integrity.so, vac-daemon, gen-keys)..."
  cargo build --release -p vac-integrity -p vac-daemon -p gen-keys 2>&1 | tail -3 || { echo "ERROR: cargo build failed"; exit 1; }

  echo "    generating PQC keys..."
  ./target/release/gen-keys "$VAC_BUILD_DIR" >/dev/null 2>&1 \
    || { echo "    gen-keys via cargo run..."; cargo run --release -p gen-keys -- "$VAC_BUILD_DIR" >/dev/null 2>&1 || { echo "ERROR: gen-keys failed"; exit 1; }; }

  cp -f target/release/libvac_integrity.so "$VAC_BUILD_DIR/" || exit 1
  cp -f target/release/vac-daemon          "$VAC_BUILD_DIR/" || exit 1
  cp -f vac-plugin/VacIntegrity.cs         "$VAC_BUILD_DIR/" || exit 1

  # Free space: drop the transient build tree (4GB cloud hosts are tight)
  rm -rf "$BUILD_SRC"
  # gen-keys writes 600 on secrets already; ensure readable
  chmod -R a+r "$VAC_BUILD_DIR" 2>/dev/null || true
  echo "  Built VacIntegrity artifacts in ${VAC_BUILD_DIR}"
}

build_vacbuild

stage_native() {          # stage_native <dest_subdir> <name>
  local dest="$1" name="$2"
  if [ -f "${VAC_BUILD_DIR}/${name}" ]; then
    mkdir -p "/opt/vac-rustdata/carbon/${dest}"
    cp "${VAC_BUILD_DIR}/${name}" "/opt/vac-rustdata/carbon/${dest}/${name}"
    echo "  Staged ${name}"
  else
    echo "  WARN: missing ${VAC_BUILD_DIR}/${name}"
  fi
}
stage_native native libvac_integrity.so
stage_native native vac-daemon
stage_native native kyber_public.der
stage_native native kyber_secret.der
stage_native native mldsa65_public.der
stage_native native mldsa65_secret.der
stage_native plugins VacIntegrity.cs

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
if [ -n "${VAC_EXTRA_ARGS:-}" ]; then
  EXTRA_ARGS="$EXTRA_ARGS $VAC_EXTRA_ARGS"
  echo "  Extra args: $VAC_EXTRA_ARGS"
fi

# --- 6. run -------------------------------------------------------------
podman rm -f rust-server 2>/dev/null || true
# Pre-create + own the mount host dir. If running as root, chown to the
# podman user so a rootless conmon can traverse it (fixes
# "[conmon:e] Failed to get working directory" on fresh hosts where an earlier
# root run left a root-owned /opt/vac-rustdata).
mkdir -p /opt/vac-rustdata
if [ "$(id -u)" = "0" ] && command -v podman >/dev/null; then
  # Use the invoking user's UID if under sudo, else root.
  PM_USER="${SUDO_USER:-root}"
  if [ "$PM_USER" != "root" ]; then
    chown -R "$PM_USER" /opt/vac-rustdata 2>/dev/null || true
  fi
fi
# Pre-pull so podman run doesn't race image-pull + conmon cwd creation.
podman pull -q docker.io/didstopia/rust-server:latest >/dev/null 2>&1 || echo "  (podman pull skipped; will pull on run)"
# Pass the values the inline command uses as real container env so they expand
# inside the container (WORLDSIZE/VAC_SEED/EXTRA_ARGS/RCON_PASSWORD must be
# -e'd; export alone on the host does nothing for podman run).
podman run -d --name rust-server --workdir / \
  -e WORLDSIZE="$WORLDSIZE" \
  -e VAC_SEED="$VAC_SEED" \
  -e EXTRA_ARGS="$EXTRA_ARGS" \
  -e RCON_PASSWORD="$RCON_PASSWORD" \
  -e RUST_SERVER_PORT=28015 \
  -e RUST_SERVER_QUERYPORT=28016 \
  -e VAC_PUBLIC_IP="$SERVER_IP" \
  -v /opt/vac-rustdata:/steamcmd/rust \
  -p 28015:28015/udp -p 28016:28016/tcp -p 28016:28016/udp \
  -p 28082:28082/tcp -p 28084:28084/tcp -p 28085:28085/tcp \
  --entrypoint /bin/bash \
  docker.io/didstopia/rust-server:latest -c "
    cd /steamcmd/rust
    source ./carbon/tools/environment.sh
    export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/steamcmd/rust/carbon/native
    exec ./RustDedicated -batchmode -load -nographics \
      +server.port 28015 +server.queryport 28016 +server.identity docker \
      +server.worldsize \$WORLDSIZE +server.seed \$VAC_SEED \
      +server.hostname \"VAC Server\" +server.maxplayers 50 \
      \$EXTRA_ARGS \
      +rcon.port 28016 +rcon.password \$RCON_PASSWORD +rcon.web 1 \
      +app.port 28082 -logfile /dev/stdout"

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