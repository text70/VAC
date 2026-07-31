# Deployment

To deploy the VAC Integrity test server, run one of these commands on your host:

```bash
# As root (recommended):
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash

# Or with sudo:
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash
```

### Requirements
- **OS**: Ubuntu 22.04+, Debian 12+, or any Debian-based distro
- **Root access** required (the script auto-detects root vs sudo)
- **Kernel headers**: auto-installed by the script
- **Disk space**: at least 20GB free (for RustDedicated download)

### Security
PQC keys are auto-generated on the host at `/etc/vac/keys/` and mounted read-only into the container via `docker-compose.yml`. Keys are never stored in the container image.