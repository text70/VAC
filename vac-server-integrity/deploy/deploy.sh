#!/bin/bash
set -e

# VAC Integrity Deployment Script
# Usage: curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash

REPO_URL="https://github.com/text70/VAC.git"
INSTALL_DIR="/opt/vac-integrity"

echo "=== VAC Integrity Deployment ==="

# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y git docker.io linux-headers-$(uname -r) build-essential

# 2. Clone repo
sudo rm -rf $INSTALL_DIR
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR
git clone -b main $REPO_URL $INSTALL_DIR

cd $INSTALL_DIR

# Find project root
PROJECT_ROOT=$(find . -maxdepth 2 -name kmod -type d | head -n 1 | awk -F/ '{print $2}')
if [ -n "$PROJECT_ROOT" ] && [ "$PROJECT_ROOT" != "." ]; then
    cd "$PROJECT_ROOT"
fi

# 3. Compile and load kernel module
echo "--- Ensuring kernel headers are installed for $(uname -r) ---"
sudo apt-get install -y linux-headers-$(uname -r)

echo "--- Compiling kernel module ---"
cd kmod
make clean
make
cd ..

if lsmod | grep -q vac; then
    sudo rmmod vac
fi
sudo insmod kmod/vac.ko
sudo chmod 666 /dev/vac

# 4. Setup keys
echo "--- Setting up keys ---"
sudo mkdir -p /etc/vac/keys
echo "Please place your PQC keys (kyber_public.der, mldsa65_secret.der, kyber_secret.der, mldsa65_public.der) in /etc/vac/keys/"
read -p "Press enter when keys are placed..."

# 5. Deploy with docker-compose
echo "--- Deploying containers ---"
cd docker
docker compose up -d --build

echo "=== Deployment Complete ==="
echo "VAC Integrity is running."
