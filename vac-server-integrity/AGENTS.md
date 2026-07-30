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
- [x] Docker test server (Implemented/Built container)
- [x] C# VacIntegrity plugin (Implemented/Template ready)
- [x] vac-client-linux (Implemented/Built)
- [x] vac-client-win (Implemented/Cross-compilable)
- [x] Kernel module `vac.ko` compiles for kernel 6.x (IOCTL interface: FILL, PROC_LIST, READ_MEM, PROC_NAME)
- [ ] Kernel module loaded + tested in podman test environment

## Key Material

```
Server (native/):      kyber_public.der  + mldsa65_secret.der
Decryption service:    kyber_secret.der  + mldsa65_public.der
```

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
