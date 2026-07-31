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

```bash
curl -sL https://raw.githubusercontent.com/text70/VAC/refs/heads/main/vac-server-integrity/deploy/deploy.sh | sudo bash
```

The script auto-detects root vs sudo and installs all dependencies.

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
| `vac-daemon` | `vac-daemon/` | Client-side daemon: connects to listener, runs scans, returns PQC-sealed results |
| `vac-client-core` | `vac-client-core/` | Platform-agnostic client scan modules (runs 6 scan types via SystemOps) |
| `vac-client-linux` | `vac-client-linux/` | Linux cdylib exporting vac_client_scan() |
| `vac-client-win` | `vac-client-win/` | Windows cdylib exporting vac_client_scan() (cross-compilable) |
| `vac-plugin` | `vac-plugin/` | Carbon C# plugin (VacIntegrity.dll) |
| `docker/` | `docker/` | Dockerfile + docker-compose for RustDedicated test server |

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

### Fallback behavior

- Kernel module loaded → `kernel_proc_list()` returns ring-0 process list
- Kernel module not loaded → `kernel_proc_list()` falls back to `enumerate_processes()` (user-mode `/proc/`)
- This lets the daemon work with or without the driver; server receives a flag indicating which path was used

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
- [x] Bug fixes: buffer truncation, plugin symbol mismatch, container namespace, unsync'd static mut, OOM vectors, wire-length caps, unsigned overflow, unscored modules
- [ ] Kernel module loaded + tested in podman test environment

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
| 4      | 4    | module_id (LE) |
| 8      | 8    | timestamp (nanos, LE) |
| 16     | 1088 | Kyber-768 ciphertext |
| 1104   | 12   | AES-256-GCM nonce |
| 1116   | 16   | AES-256-GCM tag |
| 1132   | N    | AES-256-GCM ciphertext (scan data) |
| 1132+N | 3293 | ML-DSA-65 detached signature |

- Every function in original C port has a comment with its byte signature (e.g. `// 83 C8 FF 83 E9 00`).
- Module structs are exact layout recreations from reverse engineering — do not reorder fields or change padding.
- Rust code uses `snake_case` throughout (even though the original C++ was PascalCase).
- TPM attestation has been removed; replaced by `hardware_presence()` in `SystemOps` (simple status flag, no crypto overhead).
