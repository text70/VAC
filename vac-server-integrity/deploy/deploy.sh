#!/bin/bash
set -e

# VAC Integrity Deployment Script
# Usage: curl -sL https://your-host.com/deploy.sh | bash

REPO_URL="https://github.com/text70/VAC.git"
INSTALL_DIR="/opt/vac-integrity"

echo "=== VAC Integrity Deployment ==="

# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y git docker.io docker-compose linux-headers-$(uname -r) build-essential

# 2. Clone repo
if [ ! -d "$INSTALL_DIR" ]; then
    sudo mkdir -p $INSTALL_DIR
    sudo chown $USER:$USER $INSTALL_DIR
    git clone $REPO_URL $INSTALL_DIR
fi
cd $INSTALL_DIR

# 3. Compile and load kernel module
echo "--- Compiling kernel module ---"
make -C kmod
if lsmod | grep -q vac; then
    sudo rmmod vac
fi
sudo insmod kmod/vac.ko
# Ensure /dev/vac has correct permissions
sudo chmod 666 /dev/vac

# 4. Setup keys
echo "--- Setting up keys ---"
sudo mkdir -p /etc/vac/keys
echo "Please place your PQC keys (kyber_public.der, mldsa65_secret.der, kyber_secret.der, mldsa65_public.der) in /etc/vac/keys/"
read -p "Press enter when keys are placed..."

# 5. Deploy with docker-compose
echo "--- Deploying containers ---"
cd docker
docker-compose up -d --build

echo "=== Deployment Complete ==="
echo "VAC Integrity is running."
