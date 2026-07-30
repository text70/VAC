#!/bin/bash
set -ex # Enable command tracing and exit on failure

# VAC Integrity Deployment Script
# Usage: curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash

REPO_URL="https://github.com/text70/VAC.git"
INSTALL_DIR="/opt/vac-integrity"

echo "=== VAC Integrity Deployment ==="

# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y git docker.io linux-headers-$(uname -r) build-essential curl

# Install Rust
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# 2. Clone repo
sudo rm -rf $INSTALL_DIR
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR
git clone -b main $REPO_URL $INSTALL_DIR

# 3. Setup paths
cd $INSTALL_DIR
# Find the actual project root (e.g., ./vac-server-integrity)
PROJECT_ROOT=$(find . -maxdepth 2 -name kmod -type d | head -n 1 | awk -F/ '{print $2}')
if [ -z "$PROJECT_ROOT" ]; then PROJECT_ROOT="."; fi
ROOT_DIR="$(pwd)/$PROJECT_ROOT"
echo "--- Detected project root: $ROOT_DIR ---"

# 4. Compile and load kernel module
echo "--- Ensuring kernel headers are installed for $(uname -r) ---"
sudo apt-get install -y linux-headers-$(uname -r)

echo "--- Compiling kernel module ---"
cd "$ROOT_DIR/kmod"
make clean
make
cd "$ROOT_DIR"

if lsmod | grep -q vac; then
    sudo rmmod vac
fi
sudo insmod kmod/vac.ko
sudo chmod 666 /dev/vac

# 5. Build generator and setup keys
echo "--- Building key generator ---"
cd "$ROOT_DIR"
cargo build --release -p gen-keys

echo "--- Generating PQC keys ---"
GEN_KEYS_PATH="$ROOT_DIR/target/release/gen-keys"
if [ ! -f "$GEN_KEYS_PATH" ]; then
    echo "ERROR: Key generator not found at $GEN_KEYS_PATH"
    exit 1
fi

sudo mkdir -p /etc/vac/keys
"$GEN_KEYS_PATH" /etc/vac/keys/

echo "--- Verifying keys ---"
ls -l /etc/vac/keys/
sudo chmod 600 /etc/vac/keys/*.der

# 6. Deploy with docker-compose
echo "--- Deploying containers ---"
cd "$ROOT_DIR/docker"
docker compose up -d --build

echo "=== Deployment Complete ==="
echo "VAC Integrity is running."
