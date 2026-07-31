#!/bin/bash
set -ex

# VAC Integrity Deployment Script
# Usage (as root):    curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash
# Usage (with sudo):  curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash

REPO_URL="https://github.com/text70/VAC.git"
INSTALL_DIR="/opt/vac-integrity"

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
pip3 install podman-compose

# Install/Update Rust
if command -v cargo &> /dev/null; then
    echo "--- Updating Rust ---"
    rustup update
else
    echo "--- Installing Rust ---"
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

# 4. Compile and load kernel module
echo "--- Ensuring kernel headers are installed for $(uname -r) ---"
$SUDO apt-get install -y linux-headers-$(uname -r)

echo "--- Compiling kernel module ---"
cd "$ROOT_DIR/kmod"
make clean
make
cd "$ROOT_DIR"

if lsmod | grep -q vac; then
    $SUDO rmmod vac
fi
$SUDO insmod kmod/vac.ko
$SUDO chmod 666 /dev/vac

# 5. Build VAC binaries and stage them for container build
echo "--- Building VAC binaries ---"
cd "$ROOT_DIR"
cargo build --release -p vac-integrity -p vac-daemon

echo "--- Staging binaries for container build ---"
mkdir -p "$ROOT_DIR/docker/build-staging"
cp target/release/libvac_integrity.so "$ROOT_DIR/docker/build-staging/"
cp target/release/vac-daemon "$ROOT_DIR/docker/build-staging/"

# 6. Build generator and setup keys
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

# 7. Setup mount directory with keys + VAC binaries
echo "--- Setting up mount directory /etc/vac/keys ---"
$SUDO mkdir -p /etc/vac/keys
cp target/release/libvac_integrity.so target/release/vac-daemon /etc/vac/keys/
$SUDO chmod 644 /etc/vac/keys/libvac_integrity.so
$SUDO chmod 755 /etc/vac/keys/vac-daemon

# 8. Deploy with podman-compose
echo "--- Deploying containers ---"
cd "$ROOT_DIR/docker"
podman-compose up -d --build

rm -rf "$ROOT_DIR/docker/build-staging"

echo "=== Deployment Complete ==="
echo "VAC Integrity is running."
echo ""
echo "Check: podman logs docker_rust-server_1"