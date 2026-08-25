# VAC — Launch a Working Linux Rust Server (Docker/Podman)

Deploy a **working** RustDedicated + Carbon LAN server whose server-side EAC
handling is neutralised, so a **Linux/Proton client can actually join**
(reaches world spawn). This is the configuration verified on a live LAN host —
see [`docs/lan-linux-eac-findings.md`](../docs/lan-linux-eac-findings.md).

> Why not the regular `deploy.sh`? That builds the *custom* VAC image, which
> currently wedges before world-gen. This page launches the battle-tested
> `didstopia/rust-server` base image, which boots reliably.

## One-command launch (curl from GitHub)

On any Debian/Ubuntu host:

```bash
# As root (recommended):
curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | sudo bash

# With an admin player + fixed IP:
sudo curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | \
  ADMIN_STEAMID=<your-steamid64> SERVER_IP=<your-server-ip> WORLDSIZE=1000 bash
```

The script:
1. Installs `podman` (+ `podman-compose`) and `wget` if missing
2. Auto-detects the host IP (`SERVER_IP=...` overrides)
3. Creates `/opt/vac-rustdata` as persistent storage (game + world survive restarts)
4. Installs Carbon (enable with `ENABLE_CARBON=1`, default on)
5. Runs `didstopia/rust-server:latest`, publishing:
   - `28015/udp` — game
   - `28016/udp+tcp` — query / RCON
   - `28082/tcp` — Rust+ companion app
6. Bakes in the **EAC-off launch args** (the verified combo):
   ```
   +server.anticheattoken 0
   +server.strictauth_eac 0
   +server.authtimeout 3600
   +server.encryption 0        # ← decisive: disables EAC network encryption
   ```
7. Grants your `ADMIN_STEAMID` the Carbon `selectiveeac.use` bypass (when set)

## Connect from the client

Launch the game with `-noeac` in Steam launch options (Linux/Proton), then in the
F1 console:

```
connect <SERVER_IP>:28015
```

> **Client tip — RAM:** Rust uses ~8–9.5GB RAM during world startup. Close
> browsers / protonvpn before joining or you'll be OOM-killed right at spawn
> (this was the verified final blocker, not EAC).

## Admin panel

Open the Carbon admin panel in-game by typing **`cpanel`** in chat (note:
it works *without* the leading `/`). Requires the player to be registered as an
admin (`ownerid <steamid>` / the deploy script's auto-admin), otherwise the
panel won't open.

## Verify healthy

```bash
podman logs -f rust-server        # wait for "Server startup complete"
ss -lunp | grep 28016             # query port should LISTEN
```

## Variables

| Env | Default | Meaning |
|-----|---------|---------|
| `SERVER_IP` | auto | advertised IP for `connect` |
| `WORLDSIZE` | `1000` | map size (small = fast boot, low RAM) |
| `ADMIN_STEAMID` | unset | SteamID64 to grant Carbon admin + SelectiveEAC bypass |
| `RCON_PASSWORD` | `vac-test` | RCON password (change it) |
| `ENABLE_CARBON` | `1` | install Carbon (0 = vanilla) |

## Firewall (ufw)

```bash
sudo ufw allow 28015/udp
sudo ufw allow 28016/tcp && sudo ufw allow 28016/udp
sudo ufw allow 28082/tcp
```

## Persistence / restart

```bash
podman start rust-server                       # after reboot
podman rm -f rust-server && <re-run script>    # rebuild; /opt/vac-rustdata persists
```

## Notes
- Server-side EAC is off (`server.encryption 0`) — private/LAN only.
- With Carbon's **SelectiveEAC** module you can grant per-player bypass;
  VacIntegrity should be layered here as the real anti-cheat under test.
- Carbon `.cs` plugin runtime-compilation is broken in this image today (only
  built-in modules load). Tracked in `docs/lan-linux-eac-findings.md`.