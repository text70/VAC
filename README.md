# VAC Integrity — Rust Server with VacIntegrity Anti-Cheat (Docker/Podman)

A **working** RustDedicated + **Carbon** server with the **VAC Integrity**
anti-cheat stack layered in, deployable on your own machine (LAN or private
server). Server-side EAC handling is neutralised so even a **Linux/Proton
client can actually join** (reaches world spawn).

This is the configuration verified live end-to-end:

- **Host**: Debian/Ubuntu, Podman
- **Base image**: `didstopia/rust-server` (boots reliably)
- **Mod framework**: Carbon (supports runtime `.cs` plugins such as VacIntegrity)
- **Anti-cheat**: VacIntegrity plugin — `libvac_integrity.so` + PQC keys
- **Client**: Windows or Linux/Proton (launch with `-noeac`)

> If you're looking for the original Valve Anti-Cheat *reverse-engineering*
> research, see [`docs/original-vac-re.md`](docs/original-vac-re.md).

## One-command launch (curl from GitHub)

On a Debian/Ubuntu host with network access:

```bash
# As root (recommended):
curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | sudo bash

# With an admin player + fixed IP + login:
sudo curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | \
  ADMIN_STEAMID=<your-steamid64> SERVER_IP=<your-server-ip> WORLDSIZE=1000 bash
```

The script:
1. Installs `podman` (+ `podman-compose`) and `wget` if missing
2. Auto-detects the host IP (`SERVER_IP=...` overrides)
3. Creates `/opt/vac-rustdata` as persistent storage (game + world survive restarts)
4. Installs Carbon (default on)
5. Runs `didstopia/rust-server:latest`, publishing:
   - `28015/udp` — game
   - `28016/udp+tcp` — query / RCON
   - `28082/tcp` — Rust+ companion app
   - `28084/tcp` — VAC daemon listener
   - `28085/tcp` — VAC installer / status server
6. Bakes in the **EAC-off launch args** (the verified combo):
   ```
   +server.anticheattoken 0
   +server.strictauth_eac 0
   +server.authtimeout 3600
   +server.encryption 0        # ← decisive: disables EAC network encryption
   ```
7. Auto-registers your `ADMIN_STEAMID`: `ownerid`, Carbon `administrator` +
   `moderator` groups, and the `selectiveeac.use` bypass; creates the standard
   `players` group.

### Manual launch (equivalent)

```bash
podman run -d --name rust-server \
  -e RUST_SERVER_WORLDSIZE=1000 -e RUST_SERVER_PORT=28015 -e RUST_SERVER_QUERYPORT=28016 \
  -e RUST_RCON_PASSWORD=secret \
  -v /opt/vac-rustdata:/steamcmd/rust \
  -p 28015:28015/udp -p 28016:28016/tcp -p 28016:28016/udp \
  -p 28082:28082/tcp -p 28084:28084/tcp -p 28085:28085/tcp \
  --entrypoint /bin/bash didstopia/rust-server:latest -c "
    cd /steamcmd/rust
    source ./carbon/tools/environment.sh
    export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/steamcmd/rust/carbon/native
    exec ./RustDedicated -batchmode -load -nographics \
      +server.port 28015 +server.queryport 28016 +server.identity docker \
      +server.worldsize 1000 +server.seed 12345 +server.maxplayers 50 \
      +server.anticheattoken 0 +server.strictauth_eac 0 \
      +server.authtimeout 3600 +server.encryption 0 \
      +rcon.port 28016 +rcon.password host +rcon.web 1 \
      +app.port 28082 -logfile /dev/stdout"
```

VAC files placed in the volume before/after first boot:

| Path | Contents |
|------|----------|
| `carbon/plugins/VacIntegrity.cs` | plugin (compiled by Carbon at boot) |
| `carbon/native/libvac_integrity.so` | native runtime |
| `carbon/native/*.der` | PQC keys: `kyber_public/secret`, `mldsa65_public/secret` |

## Connect from the client

Launch the game (launch options `-noeac` for Linux/Proton), then in the F1
console:

```
connect <SERVER_IP>:28015
```

> **Client tip — RAM:** Rust uses ~8–9.5GB RAM during world startup. Close
> browsers / VPN apps before joining, or you'll be OOM-killed at spawn.

## Admin panel & auth

- In-game, open the Carbon admin panel by typing **`cpanel`** (without the
  leading `/`) in chat.
- The setup operator is automatically registered as admin/moderator via the
  deploy script.

## VAC daemon (the anti-cheat client)

Once in game, the plugin registers you, generates your access code and shows it
in chat. Then run the daemon on your PC:

```bash
vac-daemon <SERVER_IP>:28084 <steamid64> <code-from-chat>
```

Status page: `http://<SERVER_IP>:28085/vac/status`

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
| `ADMIN_STEAMID` | unset | SteamID64 to grant admin + SelectiveEAC bypass |
| `RCON_PASSWORD` | `vac-test` | RCON password (change it) |
| `ENABLE_CARBON` | `1` | install Carbon (0 = vanilla) |

## Firewall (ufw)

```bash
sudo ufw allow 28015/udp
sudo ufw allow 28016/tcp && sudo ufw allow 28016/udp
sudo ufw allow 28082/tcp
sudo ufw allow 28084/tcp && sudo ufw allow 28085/tcp
```

## Persistence / restart

```bash
podman start rust-server                       # after reboot
podman rm -f rust-server && <re-run script>    # rebuild; /opt/vac-rustdata persists
```

## Notes
- Server-side EAC is off (`server.encryption 0`) — private/LAN only.
- **Carbon `.cs` plugins compile at runtime on this base** (verified:
  VacIntegrity loads as a `.cs` plugin). Earlier notes to the contrary were a
  false positive from an unbooted/uncompiled container state.
- See [`vac-server-integrity/docs/lan-linux-eac-findings.md`](vac-server-integrity/docs/lan-linux-eac-findings.md) for
  the full technical history of the EAC/LAN work.
</content>