# Deployment

> **Current:** [`deploy-didstopia.sh`](deploy-didstopia.sh) is the blessed
> deployment path — boots the `didstopia/rust-server` image with Carbon +
> VacIntegrity in one shot (rootful or rootless). See the repo-root README
> for the one-liner, env vars, cloud (AWS) firewall setup and client guide.
>
> The `deploy.sh` flow below is the **legacy** custom-image build.

To deploy the VAC Integrity server, run one of these commands on your host:

```bash
# As root (recommended):
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | bash

# Or with sudo:
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash
```

### Requirements

- **OS**: Ubuntu 22.04+, Debian 12+, or any Debian-based distro
- **Root access** required (the script auto-detects root vs sudo)
- **Kernel headers**: auto-installed by the script (only needed for the optional kmod)
- **RAM**: 4GB minimum for map generation at `worldsize 4500`. For 2GB VMs the
  script auto-defaults to `worldsize 1000` — or pre-generate a map save on a
  capable machine and copy `server/proceduralmap.*.sav` / `server/sv.files.*.db`
  into the `rust-server-data` volume (`podman volume inspect docker_rust-server-data`).
- **Disk space**: at least 20GB free (RustDedicated + steamcmd temp + image)

### Build model

The container **builds all VAC Rust binaries from source inside the image**
(glibc-2.31 builder → glibc-2.35 runtime, so binaries are compatible). No host
Rust toolchain is needed for the server; `gen-keys` is the only host-side build
(needed to create the PQC key pair under `/etc/vac/keys`).

### Kernel module (optional)

`deploy.sh` tries to compile and load `kmod/vac.ko`. If the host does not permit
module loading (some cloud VPS / restricted kernels), the script **continues
without it** — the daemon falls back to user-mode `/proc` scans. When the module
IS loaded, `/dev/vac` is passed into the container via the
`docker-compose.kmod.yml` override.

To run with the kmod manually:

```bash
cd docker
podman-compose -f docker-compose.yml -f docker-compose.kmod.yml up -d
```

### Configuration (env vars)

All server settings are overridable at deploy time:

| Var | Default | Purpose |
|-----|---------|---------|
| `VAC_WORLDSIZE` | `4500` (auto-`1000` on <4GB RAM) | Map world size |
| `VAC_MAXPLAYERS` | `5` | Max players |
| `VAC_SEED` | `12345` | Map seed |
| `VAC_HOSTNAME` | `VacIntegrity Test Server` | Server name |
| `VAC_IDENTITY` | `server` | Server identity (config dir) |
| `VAC_SERVER_PORT` | `28015` | Game port (UDP) |
| `VAC_APP_PORT` | `28082` | RCON/App port (TCP) |
| `VAC_RCON_PASSWORD` | *(empty)* | RCON password (empty = disabled) |

```bash
VAC_WORLDSIZE=1000 VAC_MAXPLAYERS=10 VAC_HOSTNAME="My Server" \
  ./deploy/deploy.sh
```

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 28015 | UDP | Game |
| 28082 | TCP | RCON/App |
| 28084 | TCP | VAC daemon listener (client scan results) |
| 28085 | TCP | VAC installer download server (`vac-setup.exe`) |

### Post-deploy

Check the server status:

```bash
podman logs docker_rust-server_1
```

If the server exits with code 137 (OOM), the VM doesn't have enough RAM. Reduce
`VAC_WORLDSIZE` (e.g. to 1000) or add swap:

```bash
fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
```

### Security

PQC keys are auto-generated on the host at `/etc/vac/keys/` and mounted read-only
into the container via `docker-compose.yml`. Keys are never stored in the
container image or committed to the repository.
