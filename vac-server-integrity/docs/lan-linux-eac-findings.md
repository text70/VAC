# LAN Deployment & Linux-Proton EAC: Session Findings

Date: 2026-08-25 · Server: didstopia/rust-server on <SERVER_IP>

## ✅ WORKING END-TO-END (2026-08-25)

- Linux/Proton client (`-noeac`) **loads into the game** on `<SERVER_IP>:28015`.
- **VacIntegrity plugin compiles + runs as a Carbon plugin** on this base:
  `Loaded plugin VacIntegrity v1.0.0` → `vac_init` OK → **daemon listener on
  28084 / HTTP on 28085** → `module 1..6 scan complete (12649 bytes sealed)`.
- Wiring that made it work:
  - `carbon/native` added to `LD_LIBRARY_PATH` (so P/Invoke finds
    `libvac_integrity.so`).
  - Ports published: `28015/udp, 28016/tcp+udp, 28082/tcp, 28084/tcp, 28085/tcp`.
  - Files staged in the volume: `carbon/plugins/VacIntegrity.cs`;
    `carbon/native/` = `libvac_integrity.so` + 4 PQC `.der` keys.

Client daemon once in-game:
`vac-daemon <SERVER_IP>:28084 <steamid> <code-from-chat>` → status page
`http://<SERVER_IP>:28085/vac/status` flips to CONNECTED.

EAC defeat (the core fix): `server.encryption 0` + `anticheattoken 0` +
`strictauth_eac 0` + `authtimeout 3600` on the didstopia base with Carbon
Doorstop enabled.

## ✅ STATUS: WORKING (2026-08-25)

The Linux/Proton client (`-noeac`, launch options) **loads into the game** on
`<SERVER_IP>:28015`. EAC connection gate defeated. Server runs **Carbon 2.0.257 +
SelectiveEAC + all EAC-off args** on the didstopia base:

```
-batchmode -load -nographics
+server.anticheattoken 0
+server.strictauth_eac 0
+server.authtimeout 3600
+server.encryption 0        # ← decisive
```
Verified live: anticheattoken=False, strictauth_eac=False, authtimeout=3600,
encryption=0, DOORSTOP=1, SelectiveEAC patched, startup complete.

## WORKING CONFIG — EAC gate defeated WITHOUT Carbon

The breakthrough: run didstopia's **stock entrypoint (vanilla, NO Carbon)** with
these launch args:

```
-batchmode -load -nographics
+server.anticheattoken 0
+server.strictauth_eac 0
+server.authtimeout 3600
+server.encryption 0        # ← decisive: disables EAC network encryption
```

A Linux/Proton `-noeac` client now reaches **"finalize world"** — past every
prior EAC gate. Verified on `<SERVER_IP>:28015` (world saved, A2S INSECURE).
The only remaining failure is **client RAM** (kernel OOM: RustClient.exe
~9.5GB RSS; total-vm ~32GB). Free client RAM → full spawn.

Correction: an earlier "breakthrough" was mis-attributed to Carbon. It was
actually **vanilla + server.encryption 0** all along (Carbon was never loaded
in that container). Carbon / SelectiveEAC are NOT required for connectivity.

## Verify (elect)
```
podman run -d --name rust-server \
  -e RUST_SERVER_WORLDSIZE=1000 -e RUST_SERVER_PORT=28015 \
  -e RUST_SERVER_QUERYPORT=28016 \
  -e RUST_SERVER_STARTUP_ARGUMENTS="-batchmode -load -nographics +server.anticheattoken 0 +server.strictauth_eac 0 +server.authtimeout 3600 +server.encryption 0" \
  -e RUST_RCON_PASSWORD=vactest \
  -v /opt/vac-rustdata:/steamcmd/rust \
  -p 28015:28015/udp -p 28016:28016/udp -p 28082:28082/tcp \
  didstopia/rust-server:latest
```
Client: Steam → Rust launch options `-noeac`, F1 `connect <SERVER_IP>:28015`.

## Carbon (for VacIntegrity) status
- didstopia's stock entrypoint does NOT load Carbon (this is why the working
  server is vanilla).
- Booting with Carbon (custom entrypoint sourcing `carbon/tools/environment.sh`)
  loaded Carbon 2.0.257 + SelectiveEAC module cleanly.
- Carbon runtime `.cs` plugin compilation was seen as broken ("Script processor
  has been unloaded"); this needs a clean re-test on a fresh Carbon boot when
  VacIntegrity-as-plugin is pursued (option A).

## Next step
Free client RAM and retry full spawn on the working vanilla server; then decide
VacIntegrity delivery (plugin `.cs` once Carbon compiler confirmed, or prebuilt
DLL).