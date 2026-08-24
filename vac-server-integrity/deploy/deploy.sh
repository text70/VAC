#!/bin/bash
set -ex

# VAC Integrity Deployment Script (cloud/server)
# Usage (as root):    curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash
# Usage (with sudo):  curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash
#
# The container builds all VAC Rust binaries from source inside the image, so
# no host Rust toolchain is required for the server itself.  Only gen-keys is
# built on the host (needed to create the PQC key pair under /etc/vac/keys).

REPO_URL="https://github.com/text70/VAC.git"
INSTALL_DIR="/opt/vac-integrity"

export DEBIAN_FRONTEND=noninteractive

# Handle sudo gracefully — skip if already root
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "=== VAC Integrity Deployment ==="

# 1. Install dependencies
$SUDO apt-get update
$SUDO apt-get install -y git podman python3-pip linux-headers-$(uname -r) build-essential curl
pip3 install --break-system-packages podman-compose 2>/dev/null || pip3 install podman-compose

# Install/Update Rust (only needed for gen-keys).
# rustup is the canonical toolchain manager (https://rustup.rs).
#
# NOTE: a `rustup`/`cargo` binary on PATH is NOT proof of a working install.
# A partial install (e.g. deleted/empty RUSTUP_HOME) leaves broken shims in
# "$HOME/.cargo/bin" that fail with:
#   info: no updatable toolchains installed
#   error: rustup is not installed at '/root/.cargo'
# So we only run the "update" branch when `rustup` actually executes
# successfully. Otherwise we install/repair via the official installer, which
# is idempotent and restores exactly that broken state.
if command -v rustup &> /dev/null && rustup --version &> /dev/null; then
    echo "--- Updating Rust (rustup OK: $(rustup --version)) ---"
    rustup update || {
        echo "--- rustup update failed; repairing via official installer ---"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    }
else
    echo "--- Installing/repairing Rust via rustup (standard method: https://rustup.rs) ---"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

export PATH="$HOME/.cargo/bin:$PATH"
echo "--- Rust version: $(rustc --version) ---"
echo "--- Cargo version: $(cargo --version) ---"

# 2. Clone repo
$SUDO rm -rf $INSTALL_DIR
$SUDO mkdir -p $INSTALL_DIR
$SUDO chown $USER:$USER $INSTALL_DIR
git clone -b main $REPO_URL $INSTALL_DIR

# 3. Setup paths
cd $INSTALL_DIR
PROJECT_ROOT=$(find . -maxdepth 2 -name kmod -type d | head -n 1 | awk -F/ '{print $2}')
if [ -z "$PROJECT_ROOT" ]; then PROJECT_ROOT="."; fi
ROOT_DIR="$(pwd)/$PROJECT_ROOT"
echo "--- Detected project root: $ROOT_DIR ---"

# 4. Kernel module (OPTIONAL — cloud hosts may not permit module loading).
#    The daemon falls back to user-mode /proc scans when /dev/vac is absent.
KMOD_OK=0
if [ -d /lib/modules/$(uname -r) ]; then
    echo "--- Compiling kernel module ---"
    cd "$ROOT_DIR/kmod"
    make clean || true
    make || true
    cd "$ROOT_DIR"
    if [ -f kmod/vac.ko ]; then
        echo "--- Loading kernel module ---"
        if lsmod | grep -q vac; then
            $SUDO rmmod vac || true
        fi
        if $SUDO insmod kmod/vac.ko && [ -e /dev/vac ]; then
            $SUDO chmod 666 /dev/vac
            KMOD_OK=1
            echo "--- Kernel module loaded: /dev/vac available ---"
        else
            echo "--- WARNING: could not load vac.ko (/dev/vac missing)."
            echo "    Continuing WITHOUT ring-0 scans; daemon will use user-mode /proc. ---"
        fi
    else
        echo "--- WARNING: kmod build failed; continuing without ring-0 scans. ---"
    fi
else
    echo "--- WARNING: kernel headers for $(uname -r) unavailable; skipping kmod. ---"
fi

# 5. Build key generator (host-side) and generate PQC keys
echo "--- Building key generator ---"
cd "$ROOT_DIR"
cargo build --release -p gen-keys

echo "--- Generating PQC keys ---"
GEN_KEYS_PATH="$ROOT_DIR/target/release/gen-keys"
$SUDO mkdir -p /etc/vac/keys

cd /etc/vac/keys/
"$GEN_KEYS_PATH" /etc/vac/keys/
cd "$ROOT_DIR"

echo "--- Verifying keys created ---"
ls -la /etc/vac/keys/
$SUDO chmod 600 /etc/vac/keys/*.der

# 6. Default worldsize by RAM (4500 needs ~4GB+; small VMs use 1000)
TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ -n "$TOTAL_MB" ] && [ "$TOTAL_MB" -lt 4000 ] && [ -z "$VAC_WORLDSIZE" ]; then
    echo "--- Low-RAM VM detected (${TOTAL_MB}MB): defaulting VAC_WORLDSIZE=1000 ---"
    export VAC_WORLDSIZE=1000
fi
if [ -z "$VAC_WORLDSIZE" ]; then
    export VAC_WORLDSIZE=4500
fi

# 7. Deploy with podman-compose (add kmod override only if the module loaded)
#    BUILDAH_FORMAT=docker silences the harmless "SHELL is not supported for
#    OCI image format" warning during the build (see AGENTS.md).
export BUILDAH_FORMAT=docker
echo "--- Deploying containers ---"
cd "$ROOT_DIR/docker"
if [ "$KMOD_OK" -eq 1 ]; then
    echo "--- Including kmod device override (docker-compose.kmod.yml) ---"
    podman-compose -f docker-compose.yml -f docker-compose.kmod.yml up -d --build
else
    podman-compose up -d --build
fi

echo "=== Deployment Complete ==="
echo "VAC Integrity is running."
echo ""
echo "Check: podman logs docker_rust-server_1"
echo "Tune server via env vars (VAC_WORLDSIZE, VAC_MAXPLAYERS, VAC_HOSTNAME, VAC_RCON_PASSWORD, ...)."
