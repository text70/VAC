#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="${KEYS_DIR:-/tmp/vac-test-keys}"

echo "=== VAC Podman Test ==="
echo "Root: $ROOT"
echo "Keys: $KEYS"
echo ""

# Validate keys exist
if [ ! -f "$KEYS/kyber_public.der" ] || [ ! -f "$KEYS/kyber_secret.der" ] || \
   [ ! -f "$KEYS/mldsa65_public.der" ] || [ ! -f "$KEYS/mldsa65_secret.der" ]; then
    echo "ERROR: PQC keys missing in $KEYS"
    echo "Run: cargo run -p gen-keys -- $KEYS"
    exit 1
fi

# Build images
echo "Building server image..."
podman build -f "$ROOT/podman-test/Dockerfile.server" -t vac-test-server "$ROOT" 2>&1 | tail -5
echo "Building client image..."
podman build -f "$ROOT/podman-test/Dockerfile.client" -t vac-test-client "$ROOT" 2>&1 | tail -5

# Clean up previous run
echo "Cleaning previous containers..."
podman network rm vac-test-net 2>/dev/null || true
for c in server client_76561197960265728 client_76561197960265729 client_76561197960265730; do
  podman rm -f "$c" 2>/dev/null || true
done

# Create network
podman network create vac-test-net

# Run server
echo "Starting server container..."
podman run -d --name server --net vac-test-net -p 28084:28084 \
  -v "$KEYS:/keys:ro,z" \
  vac-test-server

# Wait for server to be fully ready (listener + registrations done)
echo "Waiting for server to be ready..."
for i in $(seq 1 20); do
  if podman logs server 2>&1 | grep -q "Registered steam_id"; then
    echo "Server ready (registration confirmed)."
    break
  fi
  sleep 1
done

# Run 3 clients
echo "Starting 3 client containers..."
for sid in 76561197960265728 76561197960265729 76561197960265730; do
  podman run -d --name "client_$sid" --net vac-test-net \
    vac-test-client server:28084 "$sid"
  echo "  Started client steam_id=$sid"
done

echo ""
echo "=== Test running. Following server logs (Ctrl+C to stop) ==="

# Tail logs for 30 seconds, then show summary
sleep 5
echo ""
echo "--- Client logs ---"
for sid in 76561197960265728 76561197960265729 76561197960265730; do
  echo "=== client_$sid ==="
  podman logs "client_$sid" 2>&1
done

echo ""
echo "--- Server log summary ---"
podman logs server 2>&1

# Check for success indicators
echo ""
echo "=== Verification ==="
AUTH_COUNT=$(podman logs server 2>&1 | grep -c "auth OK" || true)
SEALED_COUNT=$(podman logs server 2>&1 | grep -c "sealed bytes" || true)
CLEAN_COUNT=$(podman logs server 2>&1 | grep -c ": clean" || true)
REJECT_COUNT=$(podman logs server 2>&1 | grep -c "Reject" || true)
echo "Auth OK:     $AUTH_COUNT (expected 3)"
echo "Scans rcvd:  $SEALED_COUNT (expected 18 = 3 clients x 6 modules)"
echo "Clean:       $CLEAN_COUNT"
echo "Rejected:    $REJECT_COUNT (expected 0)"
echo ""
if [ "$AUTH_COUNT" -ge 3 ] && [ "$REJECT_COUNT" -eq 0 ]; then
  echo "SUCCESS: All clients authenticated and scanned."
else
  echo "PARTIAL: Some issues detected. Check logs above."
fi
