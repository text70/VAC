# Deployment

To deploy the VAC Integrity test server, run the following command on your cloud host:

```bash
curl -sL https://raw.githubusercontent.com/VAC/vac-server-integrity/main/deploy/deploy.sh | bash
```

### Requirements
- Ubuntu 22.04 or compatible Linux distribution.
- Root access (the script uses `sudo`).
- Kernel headers installed (handled by script).

### Security
The deployment script requires you to manually place your PQC keys in `/etc/vac/keys/` after the directory is created, ensuring they are not bundled in the Docker image.
