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

cd "${SERVER_DIR}"

# Generate a minimal server config if not present
# RustDedicated reads config from server/<identity>/cfg/server.cfg
IDENTITY_DIR="${SERVER_DIR}/server/server"
if [ ! -f "${IDENTITY_DIR}/cfg/server.cfg" ]; then
    mkdir -p "${IDENTITY_DIR}/cfg"
    cat > "${IDENTITY_DIR}/cfg/server.cfg" << 'CFG'
server.hostname "VacIntegrity Test Server"
server.description "VAC Integrity Testing Environment"
server.maxplayers 5
server.worldsize 4500
server.seed 12345
server.saveinterval 300
server.tickrate 30
CFG
    echo "  Generated server.cfg"
fi

# Source Carbon environment (sets DOORSTOP_ENABLED, DOORSTOP_TARGET_ASSEMBLY, LD_PRELOAD)
source ./carbon/tools/environment.sh

# Also add the native module directory so .NET P/Invoke can find libvac_integrity.so
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${NATIVE_DIR}"

echo ""
echo "=== Starting RustDedicated with Carbon ==="

exec ./RustDedicated \
    -batchmode \
    +server.port 28015 \
    +server.level "Procedural Map" \
    +server.seed 12345 \
    +server.worldsize 4500 \
    +server.maxplayers 5 \
    +server.hostname "VacIntegrity Test Server" \
    +server.identity "server" \
    +server.saveinterval 300 \
    +app.port 28082 \
    -logfile stdout
