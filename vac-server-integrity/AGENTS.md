# vac-server-integrity — Linux Rust port of VAC for RustDedicated + Carbon

## Build & Run

```bash
# Build all Rust crates
cargo build --release

# Run the full test harness
cargo run -p test-harness

# Generate PQC keys
cargo run -p gen-keys -- /path/to/output/

# Build release .so for deployment
cargo build --release -p vac-integrity
# -> target/release/libvac_integrity.so

# Build kernel module (requires kernel headers)
make -C kmod
# -> kmod/vac.ko — load with: insmod vac.ko
```

## Non-Container Deployment (Direct on Host)

If you don't want to use Docker/Podman containers, run the components directly:

```bash
# 1. Load kernel module
sudo insmod kmod/vac.ko
sudo chmod 666 /dev/vac

# 2. Generate PQC keys
cargo run -p gen-keys -- /etc/vac/keys/

# 3. Start the test listener (acts as server-side scan coordinator)
cargo run -p test-listener -- 28084

# 4. In another terminal, run the daemon (client-side scanner)
./target/release/vac-daemon <server_ip>:28084 <steam_id>
```

## Docker/Podman Deployment

Supported on **Ubuntu 22.04+** and **Debian 12+**.

**Current (blessed) deploy path: [`deploy/deploy-didstopia.sh`](deploy/deploy-didstopia.sh)**
— boots the `didstopia/rust-server` image with Carbon + VacIntegrity in one
shot, rootful (`sudo`) or rootless (plain user). See the repo-root README for
the one-liner, env vars and cloud/firewall docs.

`deploy.sh` (below) is the **legacy** flow: builds the custom
`vac-test-server` image and runs it via `podman-compose`.

```bash
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash
```

The script auto-detects root vs sudo and installs all dependencies.

### deploy-didstopia.sh — troubleshooting (hard-won)

Lessons from fresh-host deploys (LAN + AWS); keep these when touching the
script:

- **conmon "Failed to get working directory"** — real root cause:
  `build_vacbuild()` `cd`s into the build tree and then `rm -rf`s it, leaving
  the shell with a deleted cwd; podman/conmon's `getcwd()` then fails at run
  time. Fixed by `cd /` before `rm -rf`. (Earlier fixes — pre-pull, chown,
  `--workdir /`, file entrypoint — treated symptoms only; a fresh-host full
  build always reproduced the error without the `cd /`.)
- **steamcmd "Missing file permissions" (2025+ client)** — steamcmd refuses to
  install as *real* root. Under rootful podman (sudo/cloud) `launch.sh`
  detects rootful via `/proc/self/uid_map` (no userns mapping ⇒ real root) and
  drops to the image's uid-1000 `docker` user with `setpriv` +
  `HOME=/steamcmd` (HOME must be writable, or the client fails identically).
  Rootless podman is unaffected: container root maps to the host user and
  steamcmd accepts it (verified).
- **didstopia image facts** — the game is NOT bundled (`/steamcmd/rust` is
  empty in the image; first boot downloads ~5.9 GB via steamcmd, 5–15 min),
  and its `/usr/local/bin/steamcmd` wrapper is broken (missing `linux32/`) —
  use `/steamcmd/steamcmd.sh`.
- **curl one-liner** pulls the script AND clones the repo from GitHub `main` —
  local fixes only reach deploys after commit + push.
- The bind source must exist before `podman run` (crun `statfs` failure
  otherwise). Volume dir is `$VAC_DATA` (`/root/vac-rustdata` rootful,
  `~/vac-rustdata` rootless); build cache in `$VAC_BUILD_DIR`
  (`/root/vacbuild` / `~/vacbuild`).

### OPEN: vac_decrypt timer failure on fresh cloud deploys

Carbon logs `Timer of 60s has failed … (vac_decrypt)` for every server-local
module scan (`AnalyzeScanResult`, VacIntegrity.cs:1063) on the AWS deploy,
while the same stack works on the LAN box. Eliminated by process of
experimentation: key format (sizes identical), key material (regenerated via
`gen-keys`, restaged, still fails), native binary (pinned to the LAN-known-good
`libvac_integrity.so`, still fails), plugin source (identical md5 both hosts).
Remaining suspects: Carbon 2.0.257 timer/marshaling of `ref outDwords`, or
`vac_scan` producing bogus constant-size payloads (12649 bytes for every
module) inside the container. Impact: server-side scan verdicts only —
connection, daemon auth (28084), enforcement flags and the 28085 HTTP surface
are unaffected. Next step: run `test-harness` against the exact staged
`.so` + keys locally to isolate native vs container environment.

### Test hosts & deployment state

| Host | Access | Notes |
|------|--------|-------|
| LAN box (owner-Macmini5-2) | `ssh owner@10.0.0.6` | Test box; podman 4.9.3, 8 GB RAM, 573 G free. sudo **requires a password** (no non-interactive root from ssh — owner must run privileged commands themselves). Working legacy stack at `/opt/vac-rustdata` (full game + Carbon + `vac-tokens.db`); reusable prebuilt artifacts in `/opt/vacbuild` (`libvac_integrity.so`, `vac-daemon`, PQC keys, `VacIntegrity.cs` — point `VAC_BUILD_DIR` there to skip the build), old repo clone at `/opt/vac-integrity`. No containers running by default. **Pending:** deploy-didstopia.sh one-liner re-validation on this box (cloud-validated script should be re-run here with `VAC_BUILD_DIR=/opt/vacbuild`). |
| AWS "Rust" (`i-0b093c0f1a8908942`, us-east-1) | `ssh -i ~/networking/rust.pem ubuntu@18.212.143.27` | t3.medium (4 GB → `WORLDSIZE=1000` only), Ubuntu 26.04, podman 5.7.0. Keypair `rust` (matches `~/networking/rust.pem`; SSH user is `ubuntu`, **not** `ec2-user`). SG `sg-0d938c41d74c9c113`: 28015/udp, 28016 tcp+udp, 28082/28084/28085 tcp, 22. Volume `/root/vac-rustdata`, artifacts `/root/vacbuild`, deploy log `~/deploy.log`. awscli is configured on the dev machine (verified via `aws sts get-caller-identity`). |

Operator SteamID64 (owner/admin granted on deploys): `76561198080464011`.
RCON passwords are set per-deploy via `RCON_PASSWORD` — never commit them.

### Deploy flow

1. Installs Rust, kernel headers, podman, podman-compose
2. Clones repo to `/opt/vac-integrity`
3. Builds + loads kernel module (`kmod/vac.ko`)
4. Builds VAC Rust binaries
5. Generates PQC keys to `/etc/vac/keys/` (also stages `.so` + `vac-daemon` there)
6. Builds and starts the container via `podman-compose up -d --build`
7. Mounts `/etc/vac/keys:/server/vac-extra:ro` — the entrypoint copies them into `/server/carbon/native/` to preserve Carbon's native libs

### Requirements

- **RAM**: Minimum 4 GB for map generation. For 2 GB VMs, pre-generate a map save on a capable machine and copy `server/proceduralmap.*.sav` / `server/sv.files.*.db` into the volume (`podman volume inspect docker_rust-server-data` to locate it).
- **Disk**: 20 GB free (6 GB image + 6 GB steamcmd temp + 2 GB Rust build + overhead)
- **World size**: Default 4500. For lower-RAM VMs, set worldsize to 1000 by editing `docker/entrypoint.sh` (both `+server.worldsize` and the generated `server.cfg`), then rebuild.

### Transferring image to another host

```bash
# On build machine:
podman save vac-test-server | gzip > vac-test-server.tar.gz
scp vac-test-server.tar.gz root@<target>:/root/

# On target:
podman load < /root/vac-test-server.tar.gz
# Then run with the same docker-compose.yml (or podman run directly)

## SHELL Warning (Podman)

When building with `podman`, you may see:
```
SHELL is not supported for OCI image format, [/bin/bash -o pipefail -c] will be ignored.
```
This is **harmless**. Podman's OCI format doesn't persist the SHELL directive, so the default shell (`/bin/sh`) is used for RUN commands. To suppress it, build with `--format docker`:
```bash
podman build --format docker -t vac-test-server -f docker/Dockerfile .
```

## Workspace Layout

| Crate | Path | Purpose |
|-------|------|---------|
| `vac-core` | `vac-core/` | DataBuffer, ICE cipher, CRC32, MD5, vac_hash, XorString, Module trait, ScanReport |
| `vac-sys` | `vac-sys/` | SystemOps trait + Linux/Win32 impls, `/dev/vac` IOCTL client |
| `vac-crypto` | `vac-crypto/` | PQC seal/open: Kyber-768 + AES-256-GCM + ML-DSA-65 |
| `vac-module-systeminfo` | `vac-module-systeminfo/` | Module #1: OS/CPU/kernel/memory/mounts/processes/libs |
| `vac-module-processhandle` | `vac-module-processhandle/` | Module #2: process enumeration, cheat process detection |
| `vac-module-processmonitor` | `vac-module-processmonitor/` | Module #3: self-integrity, loaded lib path checking |
| `vac-module-deviceinfo` | `vac-module-deviceinfo/` | Module #4: block + PCI device hashing |
| `vac-module-driverinfo` | `vac-module-driverinfo/` | Module #5: kernel module listing |
| `vac-module-readmodules` | `vac-module-readmodules/` | Module #6: loaded .so manifest + partial hash |
| `vac-integrity` | `vac-host/` | cdylib with C FFI exports (vac_init, vac_scan, vac_decrypt, vac_shutdown) |
| `gen-keys` | `tools/gen-keys/` | PQC key pair generator |
| `test-harness` | `test-harness/` | End-to-end test runner |
| `test-listener` | `tools/test-listener/` | Standalone TCP listener for podman test harness |
| `vac-daemon` | `vac-daemon/` | Client-side daemon: connects to listener, runs scans, returns PQC-sealed results (Linux) |
| `vac-daemon-win` | `vac-daemon-win/` | Client-side daemon for Windows (cross-compiled via mingw) |
| `vac-client-core` | `vac-client-core/` | Platform-agnostic client scan modules (runs 6 scan types via SystemOps) |
| `vac-client-linux` | `vac-client-linux/` | Linux cdylib exporting vac_client_scan() |
| `vac-client-win` | `vac-client-win/` | Windows cdylib exporting vac_client_scan() (cross-compilable) |
| `vac-plugin` | `vac-plugin/` | Carbon C# plugin (VacIntegrity.dll) — HTTP download server + hard enforcement |
| `installer/` | `installer/` | Inno Setup script for Windows client installer (vac-setup.exe) |
| `docker/` | `docker/` | Dockerfile + docker-compose for RustDedicated test server |
| `kmod-win/` | `kmod-win/` | Windows kernel driver (`vac.sys`) — mirrors `kmod/` for Win10+ clients |

## Kernel Module

The `kmod/` directory contains a Linux kernel module (`vac.ko`) that provides ring-0
process enumeration and memory reading, replacing the user-mode `/proc/` scans when loaded.

### IOCTL interface (`kmod/vac-ioctl.h`)

| IOCTL | Description |
|-------|-------------|
| `VAC_IOCTL_FILL` | Returns capability flags (proc_list, read_mem, proc_name, protect) |
| `VAC_IOCTL_PROC_LIST` | Walks `task_struct` list at ring 0 — cannot be hooked from user-mode |
| `VAC_IOCTL_READ_MEM` | Reads process memory via `access_process_vm()` — bypasses user-mode hooks |
| `VAC_IOCTL_PROC_NAME` | Reads `task->comm` directly — cannot be faked |

Rust-side definitions in `vac-sys/src/kmod/mod.rs`; the `VacKmod` struct opens `/dev/vac`
and wraps each IOCTL as a safe Rust method.

### Kernel-thread filtering (important)

Both the kmod `VAC_IOCTL_PROC_LIST` and the user-mode `/proc/` fallback exclude kernel
threads so the two process views stay consistent:

- kmod: skips tasks with `task->flags & PF_KTHREAD` (authoritative; `mm == NULL` is NOT
  reliable — io_uring/other kernel helpers can attach an mm)
- user-mode: skips `pid == 2` (kthreadd) and `ppid == 2` (every kernel thread is forked by
  kthreadd) in both `vac-sys/src/process.rs` and the daemon's own `user_mode_proc_list()`

Without this, ring-0 walks surfaced kernel threads (e.g. `idle_inject/0`) that user-mode
`/proc/` also lists — but they matched the server's cheat-name keyword `"inject"`,
producing false bans. Filtering both sides fixes the false positive and keeps the
hidden/missing-process check meaningful (verified: 113 user-space procs, 0 hidden,
0 missing).

### Fallback behavior

- Kernel module loaded → `kernel_proc_list()` returns ring-0 process list
- Kernel module not loaded → `kernel_proc_list()` falls back to `enumerate_processes()` (user-mode `/proc/`)
- This lets the daemon work with or without the driver; server receives a flag indicating which path was used

## Windows Kernel Module (`kmod-win/vac.sys`)

The `kmod-win/` directory contains a Windows WDM driver (`vac.sys`) that mirrors the
Linux `kmod/vac.ko` interface for Windows 10/11 clients. Same 4 IOCTLs, same struct
layouts, same capability flags — so the Rust scan code (`Win32SystemOps`) is
byte-identical regardless of platform.

### IOCTL interface (`kmod-win/vac-ioctl.h`)

| IOCTL | Implementation |
|-------|---------------|
| `VAC_IOCTL_FILL` | Returns capability flags (proc_list, read_mem, proc_name) |
| `VAC_IOCTL_PROC_LIST` | Calls `ZwQuerySystemInformation(SystemProcessInformation)` at ring 0 |
| `VAC_IOCTL_READ_MEM` | Calls `MmCopyVirtualMemory()` — bypasses user-mode hooks |
| `VAC_IOCTL_PROC_NAME` | Calls `PsGetProcessImageFileName()` on target EPROCESS |

Rust-side client in `vac-sys/src/win32_kmod.rs` — `Win32Kmod` struct opens `\\.\Vac`
via `CreateFileW` + `DeviceIoControl`, same API as `VacKmod`.

### Build (requires WDK 10/11)

```bat
:: From an "x64 Native Tools Command Prompt for VS 2022"
cd kmod-win
build.cmd
:: Output: kmod-win\x64\Release\vac.sys

:: Package for Microsoft attestation signing (Partner Center):
package.cmd
:: -> kmod-win\dist\vac-driver-package.cab (vac.sys + vac.inf + vac.cat)
:: Sign the CAB with your EV cert, upload to Partner Center, select
:: "Attestation signing", then ship the MS-signed vac.sys/vac.cat.
```

### Authenticode signing gate (all Windows build artifacts)

`signing/sign.cmd` is a sign+verify gate applied by `installer/build.cmd` and
`kmod-win/build.cmd`. It runs via `osslsigncode` (no Windows tooling needed for the
gate itself) and behaves as follows:

- `VAC_SIGN_P12` **not set** → warn "UNSIGNED", exit 0 (dev builds allowed, no abort).
- `VAC_SIGN_P12` **set** → sign with the p12, verify, swap `.signed` in place;
  **exit 1 on any signing/verification failure** (P0 gate: unsigned/tampered artifacts
  never reach release).

```bat
:: Dev (self-signed test cert — pipeline testing only, NOT Windows-trusted):
set VAC_SIGN_P12=signing\test-cert.p12
set VAC_SIGN_PASS=vac-test
:: CAfile auto-derived from <p12>.crt (emitted by gen-test-cert.sh); or set explicitly:
set VAC_SIGN_CAFILE=signing\test-cert.crt
call installer\build.cmd          :: or: call kmod-win\build.cmd

:: Production (same gate, real identity):
set VAC_SIGN_P12=C:\path\trusted.p12
set VAC_SIGN_PASS=...
set VAC_SIGN_CAFILE=C:\path\chain.crt   :: optional for OS-trusted identities
```

`osslsigncode verify` fails on self-signed certs unless the leaf cert is passed as
`-CAfile` (self-signed certs are their own trust anchor). The gate handles this by
using `VAC_SIGN_CAFILE` or falling back to `%VAC_SIGN_P12%.crt`.

Generate a fresh test cert on Linux with:

```bash
bash signing/gen-test-cert.sh signing/test-cert.p12   # -> test-cert.p12 + test-cert.crt (pass vac-test)
```

**TODO (production):** replace the self-signed test cert with **Microsoft Trusted
Signing** (~$10/mo Azure service, OS-trusted, no EV purchase needed) for user-mode
binaries, or a real **EV cert** (required for kernel-mode driver attestation signing
via Partner Center). No gate changes needed — just point `VAC_SIGN_P12` at the real
identity.

### Production driver signing — Attestation (recommended)

1. Purchase an **EV code-signing certificate** (~$200–500/yr from DigiCert, GlobalSign, Sectigo, SSL.com).
2. Register for the [Microsoft Windows Hardware Developer Program](https://partner.microsoft.com/dashboard/hardware/).
3. Associate the EV cert with your Partner Center account.
4. Create a CAB with `vac.sys` + INF, sign the CAB with your EV cert (`signtool sign /fd sha256 /a`).
5. Submit via Partner Center → select **Attestation signing** (no HLK testing required).
6. Download the Microsoft-signed result. Works on Win10/11 with Secure Boot enabled for drivers distributed directly (shipped in the client installer, not via Windows Update).

For Windows Update distribution, escalate to **WHCP certification** (requires HLK testing) — attestation-signed drivers cannot be published to Windows Update for retail audiences.

### Installation on test machines

```bat
bcdedit /set testsigning on
sc create Vac type= kernel binPath= "C:\path\to\vac.sys"
sc start Vac
```

### Rust cross-compile

```bash
# Build the Rust Win32 Kmod client (no .sys needed)
cargo build --release --target x86_64-pc-windows-gnu -p vac-sys

# Build the Windows daemon binary
cargo build --release --target x86_64-pc-windows-gnu -p vac-daemon-win
# -> target/x86_64-pc-windows-gnu/release/vac-daemon-win.exe (1.8MB PE32+)
```

## Windows Client Daemon (`vac-daemon-win`)

The `vac-daemon-win/` crate is the Windows equivalent of `vac-daemon`. It runs as a
background process on Windows clients, connects to the Linux server's VAC listener
(port 28084), and performs the same scan + PQC-seal + submit protocol.

### Platform mapping

| Daemon feature | Linux (`vac-daemon`) | Windows (`vac-daemon-win`) |
|----------------|---------------------|---------------------------|
| Process listing (ring-0) | VacKmod (ioctl) | Win32Kmod (DeviceIoControl) |
| User-mode process list | `/proc/*/stat` | CreateToolhelp32Snapshot |
| Memory region scan | `/proc/self/maps` | VirtualQueryEx |
| Text integrity check | ELF magic (0x7fELF) | PE magic (MZ) |
| Config | CLI args | `vac-daemon.ini` |
| Steam ID | CLI arg | Auto-discover from `loginusers.vdf` or config |

### How the turnkey flow works (Carbon package)

1. Server operator deploys the **Carbon package** (VacIntegrity.dll + vac-setup.exe).
2. Plugin starts a **TCP download server on port 28085** serving `vac-setup.exe`.
3. Player connects → plugin registers them with the listener, sends a chat message
   with the download URL, and starts a 60-second grace timer.
4. Player downloads + runs `vac-setup.exe` (admin elevation required).
5. Installer: installs `vac.sys` as a kernel service → installs `vac-daemon-win.exe`
   as a service → prompts for server IP → starts both services.
6. Daemon auto-discovers Steam ID from `%USERPROFILE%\AppData\Local\Steam\config\loginusers.vdf`.
7. Daemon connects to `<server>:28084`, authenticates, and begins scanning.
8. Plugin's enforcement timer kicks any player who hasn't connected a daemon
   within the grace period (configurable via `vac_grace_seconds`).

### Installer

```bat
:: Prerequisites: Inno Setup 6+ on Windows
:: 1. Build vac.sys (kmod-win\build.cmd)
:: 2. Cross-compile vac-daemon-win.exe
:: 3. Run installer build script
installer\build.cmd
:: -> installer\Output\vac-setup.exe
:: Sign: signtool sign /fd sha256 /a /tr http://timestamp.digicert.com /td sha256 ...\vac-setup.exe
```

### Carbon package layout

```
vac-carbon-package/
  VacIntegrity.dll              -- Plugin binary
  VacIntegrity.cfg              -- Optional config (grace seconds, etc.)
  vac-setup.exe                 -- Windows client installer (hosted by plugin on port 28085)
  README.md
```

## Hardware Presence (replaces TPM Attestation)

TPM attestation has been removed. Instead, `SystemOps::hardware_presence()` returns a
simple 32-byte status:

| Byte 0 | Meaning |
|--------|---------|
| 1 | No trust anchor |
| 2 | TPM present (basic check only, no cryptographic proof) |
| 3 | VAC kernel module loaded + functional |

The server verifies the first byte is non-zero (same as before), but the semantics
have shifted from "prove the system is clean" to "report available trust anchors."

## Status

- [x] All workspace crates compile (19 crates)
- [x] All 6 module scans produce data
- [x] PQC seal/open round-trip works (Kyber-768 + AES-256-GCM + ML-DSA-65)
- [x] ICE cipher works (with OOB fix, sbox index masked to 10 bits)
- [x] vac_init/vac_shutdown Rust wrappers
- [x] gen-keys tool generates all 4 key files
- [x] test-harness: 17/17 tests pass
- [x] Docker test server (Built container, tested locally + on cloud)
- [x] C# VacIntegrity plugin (Compiles at runtime under Carbon, kick/ban callbacks work)
- [x] vac-client-linux (Implemented/Built)
- [x] vac-client-win (Implemented/Cross-compilable)
- [x] Kernel module `vac.ko` compiles for kernel 6.x (IOCTL interface: FILL, PROC_LIST, READ_MEM, PROC_NAME)
- [x] Windows kernel driver `vac.sys` source + `Win32Kmod` Rust client + attestation signing path
- [x] vac-daemon-win cross-compiled (1.8MB PE32+), Inno Setup installer script
- [x] Hard enforcement: plugin kicks if no daemon connected within grace period
- [x] Plugin-hosted HTTP download server on port 28085
- [x] Bug fixes: buffer truncation, plugin symbol mismatch, container namespace, unsync'd static mut, OOM vectors, wire-length caps, unsigned overflow, unscored modules
- [x] Kernel module loaded + ring-0 modules verified on host (361→113 procs after PF_KTHREAD filter; 0 hidden/missing; no idle_inject false positive)
- [x] deploy-didstopia.sh: cloud-verified (AWS t3.medium, Ubuntu 26.04, rootful) + rootless steamcmd verified locally; fixes: deleted-cwd `cd /`, steamcmd-as-root uid-1000 drop, cargo autodiscovery, dual-mode volume paths
- [x] curl one-liner validated end-to-end on AWS (fetch from GitHub main → rootful deploy → boots from save; artifacts/Carbon reused via `vacbuild` fast path). Note: env vars must ride through `sudo env` — plain `sudo curl | bash` runs the script unprivileged.

## Key Material

```
Server (/etc/vac/keys/ mounted at /server/vac-extra):   kyber_public.der  + mldsa65_secret.der
Decryption service:    kyber_secret.der  + mldsa65_public.der
```

The entrypoint copies keys from the mount into `/server/carbon/native/` alongside the VAC `.so` and `vac-daemon` (which are baked into the image).

## Wire Format (PQC sealed payload)

| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | MAGIC (0x56414349) |
| 4      | 4    | module_id (LE) — bit 31 set = unsigned payload |
| 8      | 8    | timestamp (nanos, LE) |
| 16     | 1088 | Kyber-768 ciphertext |
| 1104   | 12   | AES-256-GCM nonce |
| 1116   | 16   | AES-256-GCM tag |
| 1132   | N    | AES-256-GCM ciphertext (scan data) |
| 1132+N | 3293 | ML-DSA-65 detached signature (only if signed) |

**Client payloads are unsigned** (`mldsa65_secret_key: None`): clients never
receive signing key material, so a leaked/shared client SK cannot forge
server-trusted results. Integrity holds via AES-GCM under a fresh per-payload
Kyber encapsulation; replay is caught by the server's per-scan nonce.
Server-local scans (`vac_scan`) still sign with the server-held key.

**Daemon protocol (port 28084)**:
- AUTH `0x01`: `steam_id(8) [tok_len(u16) + token]`. Players are enrolled with
  a stable per-player access token generated once by
  `vac_server_ensure_client_token` and persisted across restarts
  (`VAC_TOKEN_DB_PATH`, default `./vac-tokens.db`). The plugin delivers it to
  the player privately via chat/magic-link; daemons present it on every AUTH
  (`token=` in `vac-daemon.ini` or CLI arg 3 on Linux) — prevents steam_id
  spoofing by third parties. Re-registration preserves existing tokens.
- SCAN_CMD `0x03`: `module_id(4) + kyber_pk_len(4) + kyber_pk + nonce(8)`
  (no secret keys on the wire).
- RESULT `0x04`: `module_id(4) + sealed_len(4) + sealed`
- PING/PONG `0x05`/`0x06`.

Client scan module ids: 1–6 standard scans (sealed as 101–106),
7 ring-0 procs (200), 8 hidden-proc diff (201), 9 memory scan (202),
10 game-process memory scan (203), 11 game-process introspection (204).
Module 203 layout:
`[found][pid][status][rwx][priv_exec][hdr_mismatch]` — rwx/priv_exec are
log-only telemetry (Discord/RTSS overlays map exec pages legitimately);
only missing MZ headers on image-backed regions score points (manual-map
evidence). On Windows, module 8 filters kernel artifacts (Idle/System/
Memory Compression/Secure System/Registry) from both views before diffing.

Module 11 / 204 — fallback-mode game introspection (works without kmod):
`[found][pid][status][ld_flags][memfd_exec][anon_exec][rwx][tracer]`.
Fills the gaps the fallback otherwise misses: `LD_*` injection env vars set
in the GAME process itself, executable memfd:/deleted mappings (injection
with no backing file), and ptrace tracer attached to the game. Server scores
the high-confidence signals (ld_flags→SuspiciousEnv, memfd_exec→
InjectedAssembly, tracer→TracerAttached); rwx/anon_exec stay log-only to
avoid false positives from legal overlays.

### Client UX surface

- **Magic-link install**: chat link is `http://ip:28085/setup?t=<token>` —
  serves a ZIP of `vac-setup.exe` + `vac-preload.ini` (server+token baked in).
  The installer auto-fills all pages from the sibling ini; manual entry is
  the fallback. `/vac-setup.exe` remains for manual downloads.
- **Diagnostics**: `vac-daemon-win.exe --doctor [ini]` checks config, Steam
  ID, access code, driver state, listener reachability; exit code = failures.
- **Failure classification**: auth rejections back off 30s with actionable
  text; network errors retry at 10s; normal reconnects 5s.
- **Status for dashboards**: `GET /vac/status` (JSON:
  `{players:[{steamid,name,daemon_connected,enrolled}]}`) and
  `/vac/status.html` (auto-refreshing table, embeddable as a Carbon dashboard
  custom tab). Read-only — tokens/key material are never exposed.
- **HTTP is plain http on 28085** (no TLS) — README/links must use `http://`.
  Downloads (`/vac-daemon`, `/setup`) can reset mid-transfer while the
  container is restarting; clients just retry.

- Every function in original C port has a comment with its byte signature (e.g. `// 83 C8 FF 83 E9 00`).
- Module structs are exact layout recreations from reverse engineering — do not reorder fields or change padding.
- Rust code uses `snake_case` throughout (even though the original C++ was PascalCase).
- TPM attestation has been removed; replaced by `hardware_presence()` in `SystemOps` (simple status flag, no crypto overhead).
