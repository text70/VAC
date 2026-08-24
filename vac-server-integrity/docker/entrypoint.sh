#!/bin/bash
set -e

echo "=== VacIntegrity Test Server ==="
echo "  Server dir: ${SERVER_DIR}"
echo "  Carbon home: ${CARBON_HOME}"
echo "  Native dir: ${NATIVE_DIR}"

# Copy VAC files from mount into native dir (so Carbon native libs stay intact)
VAC_MOUNT="${VAC_MOUNT_DIR:-/server/vac-extra}"
if [ -d "${VAC_MOUNT}" ]; then
    echo "  Copying VAC files from ${VAC_MOUNT} to ${NATIVE_DIR} ..."
    cp -v "${VAC_MOUNT}"/* "${NATIVE_DIR}/" 2>/dev/null || true
fi

# Verify key material
if [ ! -f "${NATIVE_DIR}/kyber_public.der" ] || \
   [ ! -f "${NATIVE_DIR}/mldsa65_secret.der" ]; then
    echo "ERROR: PQC key material missing in ${NATIVE_DIR}"
    echo "Run: gen-keys /path/to/${NATIVE_DIR}"
    exit 1
fi

echo "  Key material: OK"

# Verify native library
if [ ! -f "${NATIVE_DIR}/libvac_integrity.so" ]; then
    echo "ERROR: libvac_integrity.so not found in ${NATIVE_DIR}"
    exit 1
fi

echo "  Native library: OK"

# Verify plugin
if [ ! -f "${PLUGINS_DIR}/VacIntegrity.dll" ]; then
    echo "WARNING: VacIntegrity.dll not found in ${PLUGINS_DIR}"
fi

echo "  Plugin: OK"

# -----------------------------------------------------------------------------
# Server configuration — all overridable via env vars for cloud deployment.
# worldsize 4500 requires ~4GB+ RAM for map generation; use 1000 on small VMs.
# -----------------------------------------------------------------------------
WORLDSIZE="${VAC_WORLDSIZE:-4500}"
MAXPLAYERS="${VAC_MAXPLAYERS:-5}"
SEED="${VAC_SEED:-12345}"
HOSTNAME="${VAC_HOSTNAME:-VacIntegrity Test Server}"
DESCRIPTION="${VAC_DESCRIPTION:-VAC Integrity Testing Environment}"
IDENTITY="${VAC_IDENTITY:-server}"
SERVER_PORT="${VAC_SERVER_PORT:-28015}"
APP_PORT="${VAC_APP_PORT:-28082}"
SAVEINTERVAL="${VAC_SAVEINTERVAL:-300}"
TICKRATE="${VAC_TICKRATE:-30}"
RCON_PASSWORD="${VAC_RCON_PASSWORD:-}"

echo ""
echo "  worldsize=${WORLDSIZE} maxplayers=${MAXPLAYERS} seed=${SEED} tickrate=${TICKRATE}"
echo "  identity=${IDENTITY} port=${SERVER_PORT} app.port=${APP_PORT}"

# -----------------------------------------------------------------------------
# First-run self-check: catch the most common launch problems early.
# -----------------------------------------------------------------------------
FAILURES=0

check_port_free() {
    local port="$1" proto="$2"
    if command -v ss >/dev/null 2>&1; then
        if [ "$proto" = "udp" ]; then
            ss -lun 2>/dev/null | grep -q ":${port} " && return 1
        else
            ss -ltn 2>/dev/null | grep -q ":${port} " && return 1
        fi
    fi
    return 0
}

for p in "${SERVER_PORT}" "${APP_PORT}"; do
    if ! check_port_free "$p" udp; then
        echo "  WARNING: port ${p}/udp already in use on host network"
        FAILURES=$((FAILURES+1))
    fi
done
for p in 28084 28085; do
    if ! check_port_free "$p" tcp; then
        echo "  WARNING: port ${p}/tcp already in use (VAC listener/download)"
        FAILURES=$((FAILURES+1))
    fi
done

MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "${WORLDSIZE}" -ge 4000 ] && [ "${MEM_KB}" -gt 0 ] && [ "${MEM_KB}" -lt 3500000 ]; then
    echo "  WARNING: ~4GB+ RAM recommended for worldsize ${WORLDSIZE};"
    echo "           this machine reports ${MEM_KB} kB. Consider VAC_WORLDSIZE=1000."
fi

JOIN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "${JOIN_IP}" ]; then
    echo "  Players join via: ${JOIN_IP}:${SERVER_PORT}"
    echo "  VAC status page:  http://${JOIN_IP}:28085/vac/status.html"
fi
if [ "${FAILURES}" -gt 0 ]; then
    echo "  ${FAILURES} warning(s) detected - see above."
else
    echo "  Self-check: OK"
fi

cd "${SERVER_DIR}"

# Generate a minimal server config if not present
# RustDedicated reads config from server/<identity>/cfg/server.cfg
IDENTITY_DIR="${SERVER_DIR}/server/${IDENTITY}"
if [ ! -f "${IDENTITY_DIR}/cfg/server.cfg" ]; then
    mkdir -p "${IDENTITY_DIR}/cfg"
    cat > "${IDENTITY_DIR}/cfg/server.cfg" << CFG
server.hostname "${HOSTNAME}"
server.description "${DESCRIPTION}"
server.maxplayers ${MAXPLAYERS}
server.worldsize ${WORLDSIZE}
server.seed ${SEED}
server.saveinterval ${SAVEINTERVAL}
server.tickrate ${TICKRATE}
CFG
    echo "  Generated server.cfg"
fi

# Source Carbon environment (sets DOORSTOP_ENABLED, DOORSTOP_TARGET_ASSEMBLY, LD_PRELOAD)
source ./carbon/tools/environment.sh

# Also add the native module directory so .NET P/Invoke can find libvac_integrity.so
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${NATIVE_DIR}"

echo ""
echo "=== Starting RustDedicated with Carbon ==="

SERVER_ARGS=( \
    -batchmode \
    +server.port "${SERVER_PORT}" \
    +server.level "Procedural Map" \
    +server.seed "${SEED}" \
    +server.worldsize "${WORLDSIZE}" \
    +server.maxplayers "${MAXPLAYERS}" \
    +server.hostname "${HOSTNAME}" \
    +server.identity "${IDENTITY}" \
    +server.saveinterval "${SAVEINTERVAL}" \
    +app.port "${APP_PORT}" \
    -logfile stdout \
)

if [ -n "${RCON_PASSWORD}" ]; then
    SERVER_ARGS+=( +rcon.password "${RCON_PASSWORD}" )
fi

# Optional operator-supplied extra game args, e.g. VAC_EXTRA_ARGS='+server.eac 0'
# to disable Easy Anti-Cheat on LAN/test servers.
if [ -n "${VAC_EXTRA_ARGS:-}" ]; then
    echo "  Extra args: ${VAC_EXTRA_ARGS}"
    # intentional unquoted expansion: word-splits "+cvar value" pairs
    SERVER_ARGS+=( ${VAC_EXTRA_ARGS} )
fi

exec ./RustDedicated "${SERVER_ARGS[@]}"
