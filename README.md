# VAC Integrity — Rust Server with VacIntegrity Anti-Cheat 

The Rust server that everyone wanted all along. 

RustDedicated + **Carbon** server with the **VAC Integrity**
anti-cheat stack layered in, deployable on your own machine (LAN or private
server). 

**Requirements**
- **Host**: Debian/Ubuntu, Podman

**What it provides**
- **Base image**: `didstopia/rust-server` (this is bundled in the podman/docker image)
- **Mod framework**: Carbon (supports runtime `.cs` plugins such as VacIntegrity) (also in the image)
- **Anti-cheat**: VacIntegrity plugin — `libvac_integrity.so` + PQC keys 
- **Client Daemon**: Windows or Linux/Proton auto-detected on join 

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

What it does: installs podman + wget if missing, auto-detects the host IP,
creates persistent storage in `/opt/vac-rustdata`, installs Carbon, then runs
the server published on **28015/udp** (game), **28016/udp+tcp** (query/RCON),
**28082/tcp** (companion app), **28084/tcp** (VAC daemon) and **28085/tcp**
(installer/status). It bakes in the **EAC-off args**, and if `ADMIN_STEAMID`
is set it registers you as owner/admin and creates the `players` group.

The **EAC-off launch args** baked in (the verified combo):

```
+server.anticheattoken 0
+server.strictauth_eac 0
+server.authtimeout 3600
+server.encryption 0        # ← decisive: disables EAC network encryption
```

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
| `carbon/native/vac-daemon` | Linux daemon binary (served to clients at `/vac-daemon`) |

## Verify healthy

```bash
podman logs -f rust-server        # wait for "Server startup complete"
ss -lunp | grep 28016             # query port should LISTEN
```

## Cloud deployment

The same deploy script runs on any Debian/Ubuntu cloud VM (Hetzner, DigitalOcean,
AWS, etc.). Two things differ from a home-LAN setup:

1. **Advertise the public IP** — the plugin builds in-game links / client
   packages from `VAC_PUBLIC_IP`. Inside a container that would otherwise
   fall back to the podman bridge IP (unreachable to players), so set it
   explicitly to the VM's public IP.
2. **Open the ports in the cloud firewall / security group** (see Firewall).

A typical cloud launch:

```bash
# Auto-IP only works for the host's own address; for cloud, always pass
# SERVER_IP (your VM's public IP) so everything downstream advertises it.
sudo curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | \
  SERVER_IP=<your-cloud-public-ip> \
  ADMIN_STEAMID=<your-steamid64> \
  RCON_PASSWORD='<strong-password>' \
  bash
```

> The deploy script passes `SERVER_IP` through as `VAC_PUBLIC_IP` into the
> container, so the in-game message, `/setup` link and `/vac/status` all use
> the reachable public address instead of the podman bridge IP.

### Setting environment variables

All runtime settings are environment variables on the deploy command line (or
exported before running the script). The server-side ones used by the plugin
and game:

| Env | Default | Purpose |
|-----|---------|---------|
| `SERVER_IP` | auto | public/cloud IP advertised to players (`VAC_PUBLIC_IP`) |
| `VAC_PUBLIC_IP` | set from `SERVER_IP` | IP the plugin bakes into chat links, client packages, status |
| `WORLDSIZE` | `1000` | map size; small = fast boot, low RAM |
| `VAC_MAXPLAYERS` | via image | max players |
| `ADMIN_STEAMID` | unset | operator SteamID64 → owner/admin + SelectiveEAC bypass |
| `RCON_PASSWORD` | `vac-test` | **change for cloud** (exposed on 28016) |
| `ENABLE_CARBON` | `1` | install Carbon (0 = vanilla) |
| `VAC_BUILD_DIR` | unset | host dir with prebuilt `libvac_integrity.so` + `vac-daemon` to stage |
| `VAC_EXTRA_ARGS` | unset | extra `+cvar value ...` game args appended at launch |

Those reach the server process as-is via `podman run -e ...`; the deploy script
maps `SERVER_IP`→`VAC_PUBLIC_IP`, and `VAC_EXTRA_ARGS` is appended to the
server argv. For example, to advertise a public IP and set a strong RCON
password and a larger world:

```bash
export SERVER_IP=203.0.113.10
export ADMIN_STEAMID=76561198080464013
export RCON_PASSWORD="s3cret-Rcon!"
export WORLDSIZE=3000
curl -sL https://raw.githubusercontent.com/text70/VAC/main/vac-server-integrity/deploy/deploy-didstopia.sh | sudo bash
```

> Note: `VAC_PUBLIC_IP` is the only one the plugin reads directly; the rest
> (`WORLDSIZE`, `RCON`, etc.) configure the game via the image entrypoint /
> startup args. If you skip `SERVER_IP` on a cloud VM, the auto-detected IP
> will be the interface's private address — always set it to the **public**
> IP on cloud hosts.

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

## Clients

All clients should first install the RustClient.exe to Steam as a non-steam game. 

Games -> Add a Non-Steam Game to My Library -> Browse -> <path-to-your>SteamLibrary/steamapps/common/Rust/RustClient.exe

### Windows

1. In Steam, right-click **Rust → Properties → General → Launch Options**
2. Add the option exactly:
   ```
   -noeac
   ```
3. Close Properties; launch Rust from Steam via the **Play** button
   (launch options are only applied when launched through Steam, not by
   double-clicking `RustClient.exe`).

### Linux / Proton

1. Same as Windows: Steam → Rust → Properties → General → Launch Options →
   `-noeac`, then launch through the **Play** button (Proton passes the flag
   to `RustClient.exe`).

### Connecting in-game


1. Start the game and reach the main menu.
2. Press **F1** to open the in-game console.
3. Type, substituting your server IP, and press Enter:
   ```
   connect <SERVER_IP>:28015
   ```
4. You should load into the world. In the private chat you'll receive a
   **VAC access code** (and a download link for the Windows client).

> The same server works for vanilla / EAC-enabled Windows clients too, but on
> this EAC-off server the `-noeac` client is the intended pairing.

If you can't get the daemon in next part running in 60 seconds the sever will kick you. 
Go back to step 2. and rejoin the server. 

### Installing & running the VAC daemon (Linux client)

The vac-daemon binary is downloaded with the encrypted server signature from the Rust server.  
  
The magic launch link auto-detects your OS: a Windows browser gets the
`vac-setup.zip` installer, a Linux/Proton User-Agent gets
`vac-linux.zip` (the `vac-daemon` binary + a preload ini with your access
code). Alternatively download the daemon directly into the directory of your choice:

```bash
wget http://<SERVER_IP>:28085/vac-daemon -O vac-daemon
chmod +x vac-daemon
./vac-daemon <SERVER_IP>:28084 <steamid64> <code-from-chat>
```

- `<SERVER_IP>` — the server's IP (`28084` = daemon listener)
- `<steamid64>` — your SteamID64
- `<code-from-chat>` — the access code the plugin gave you in game

On launch if the game is not connected, you will get a reject message, once connected this
message should go change.  

Keep the daemon running in a terminal during gameplay (it auto-reconnects).   

You can check your live status at:
`http://<SERVER_IP>:28085/vac/status`

> The command above downloads to your current directory (`vac-daemon`) and runs
> it with `./vac-daemon`. If you save it elsewhere (e.g. `~/vac-daemon`), run it
> with that path instead. Prefer the `vac-linux.zip` from your chat link, which
> bakes in your server address and access code so you don't have to type them.

### Installing & running the VAC daemon (Windows client)

Windows doesn't ship `wget`, so use PowerShell's `Invoke-WebRequest`. The server
auto-detects your OS and serves the Windows **installer zip** (never the raw
Linux binary). Either click the chat link, or run:

```powershell
Invoke-WebRequest "http://<SERVER_IP>:28085/setup?t=<code-from-chat>" -OutFile vac-setup.zip
```

Then:
1. Extract `vac-setup.zip` and run `vac-setup.exe`.
2. The installer pre-fills your server address and access code (from the link's
   `t=<code>`), so just click through.
3. Keep the VAC daemon running (it runs as a background service).

If you have `wget` installed (e.g. Git for Windows), this works too:
```powershell
wget "http://<SERVER_IP>:28085/setup?t=<code-from-chat>" -o vac-setup.zip
```

- `<SERVER_IP>` — the server's IP (e.g. `10.0.0.6`)
- `<code-from-chat>` — the access code the plugin gave you in game

You can check your live status at:
`http://<SERVER_IP>:28085/vac/status`



## Notes
- Server-side EAC is off (`server.encryption 0`) — private/LAN only.
- **Carbon `.cs` plugins compile at runtime on this base** (verified:
  VacIntegrity loads as a `.cs` plugin). Earlier notes to the contrary were a
  false positive from an unbooted/uncompiled container state.
- See [`vac-server-integrity/docs/lan-linux-eac-findings.md`](vac-server-integrity/docs/lan-linux-eac-findings.md) for
  the full technical history of the EAC/LAN work.

## Admin panel & auth

- In-game, open the Carbon admin panel by typing **`cpanel`** (without the
  leading `/`) in chat.
- The setup operator is automatically registered as admin/moderator via the
  deploy script.
</content>
