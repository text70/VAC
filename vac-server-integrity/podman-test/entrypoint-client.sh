#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] Starting vac-daemon..."
exec vac-daemon "$@"
