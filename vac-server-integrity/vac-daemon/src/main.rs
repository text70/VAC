use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use vac_client_core::run_module;
use vac_core::buffer::DataBuffer;
use vac_crypto::seal;
use vac_sys::kmod::VacKmod;

const NONCE_LEN: usize = 8;

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => return Err("connection closed".into()),
            Ok(n) => off += n,
            Err(e) => return Err(format!("read error: {}", e)),
        }
    }
    Ok(())
}

fn send_msg(stream: &mut TcpStream, msg_type: u8, payload: &[u8]) -> Result<(), String> {
    let len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(payload);
    stream.write_all(&buf).map_err(|e| format!("write error: {}", e))
}

fn recv_msg(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
    let mut len_buf = [0u8; 4];
    read_exact(stream, &mut len_buf)?;
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    if msg_len == 0 || msg_len > 65536 {
        return Err("invalid frame length".into());
    }
    let mut msg = vec![0u8; msg_len];
    read_exact(stream, &mut msg)?;
    let msg_type = msg[0];
    let payload = msg[1..].to_vec();
    Ok((msg_type, payload))
}

/// Read user-mode process list from /proc/*/stat.
fn user_mode_proc_list() -> Vec<(u32, String)> {
    let mut procs = Vec::new();
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return procs,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat_path = entry.path().join("stat");
        let content = match std::fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Parse: pid (comm) state ...
        let comm_end = match content.rfind(')') {
            Some(i) => i,
            None => continue,
        };
        let comm_start = match content.find('(') {
            Some(i) => i + 1,
            None => continue,
        };
        if comm_start >= comm_end {
            continue;
        }
        // Kernel threads: kthreadd is always pid 2 and every kernel thread is
        // forked by it (ppid == 2).  Skip them so user-mode and ring-0 lists
        // agree — the kmod filters the same tasks via PF_KTHREAD.
        let after_comm = content[comm_end + 1..].trim();
        let parts: Vec<&str> = after_comm.split_whitespace().collect();
        let ppid: u32 = if parts.len() >= 2 { parts[1].parse().unwrap_or(0) } else { 0 };
        if pid == 2 || ppid == 2 {
            continue;
        }
        let comm = content[comm_start..comm_end].to_string();
        procs.push((pid, comm));
    }
    procs
}

/// Read /proc/self/maps for memory analysis.
#[derive(Debug)]
struct MapEntry {
    start: u64,
    #[allow(dead_code)]
    end: u64,
    perms: String,
    path: String,
}

fn read_maps() -> Vec<MapEntry> {
    let content = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let mut entries = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(range[1], 16).unwrap_or(0);
        let perms = parts[1].to_string();
        let path = if parts.len() > 5 { parts[5].to_string() } else { String::new() };
        entries.push(MapEntry { start, end, perms, path });
    }
    entries
}

fn handle_server(steam_id: u64, token: Option<&str>, server_addr: &str) -> Result<(), String> {
    let mut stream = TcpStream::connect(server_addr)
        .map_err(|e| format!("connect: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set timeout: {}", e))?;

    // Authenticate: steam_id(8) [+ tok_len(u16) + token].
    // Tag failures so the reconnect loop can tell config problems from blips.
    let auth = (|| -> Result<(), String> {
        let mut auth_msg = Vec::with_capacity(9 + token.map_or(0, |t| 2 + t.len()));
        auth_msg.extend_from_slice(&steam_id.to_le_bytes());
        if let Some(t) = token {
            auth_msg.extend_from_slice(&(t.len() as u16).to_le_bytes());
            auth_msg.extend_from_slice(t.as_bytes());
        }
        send_msg(&mut stream, 0x01, &auth_msg)?;
        let (mtype, _payload) = recv_msg(&mut stream)?;
        if mtype != 0x02 {
            return Err(format!("rejected by server (type {})", mtype));
        }
        Ok(())
    })();
    auth.map_err(|e| format!("auth: {}", e))?;
    eprintln!("[vac-daemon] Authenticated as steam_id={}", steam_id);

    let sys = vac_sys::linux::LinuxSystem::new();

    loop {
        let (mtype, payload) = recv_msg(&mut stream)?;

        match mtype {
            0x03 => {
                // SCAN_CMD: module_id(4) + kyber_pk_len(4) + kyber_pk + nonce(8)
                // (no secret key material is sent to the client)
                if payload.len() < 20 { continue; }
                let module_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let kpk_len = i32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
                if 8 + kpk_len + NONCE_LEN > payload.len() { continue; }
                let kyber_pk = &payload[8..8 + kpk_len];
                let nonce_off = 8 + kpk_len;
                let nonce = &payload[nonce_off..nonce_off + NONCE_LEN];
                let nonce_arr: [u8; NONCE_LEN] = nonce.try_into().unwrap();

                eprintln!("[vac-daemon] Scan cmd: module={}", module_id);

                let mut raw_payload = Vec::new();
                // Prepend nonce — server will verify it after decryption
                raw_payload.extend_from_slice(&nonce_arr);

                match module_id {
                    7 => {
                        // Ring-0 proc list
                        if let Some(kmod) = VacKmod::open() {
                            match kmod.proc_list() {
                                Ok(procs) => {
                                    eprintln!("[vac-daemon] Ring-0 proc_list: {} processes", procs.len());
                                    raw_payload.extend_from_slice(&(procs.len() as u32).to_le_bytes());
                                    for (pid, ppid, comm) in &procs {
                                        raw_payload.extend_from_slice(&pid.to_le_bytes());
                                        raw_payload.extend_from_slice(&ppid.to_le_bytes());
                                        let mut comm_buf = [0u8; 16];
                                        let comm_bytes = comm.as_bytes();
                                        let copy_len = comm_bytes.len().min(15);
                                        comm_buf[..copy_len].copy_from_slice(&comm_bytes[..copy_len]);
                                        raw_payload.extend_from_slice(&comm_buf);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[vac-daemon] Ring-0 proc_list failed: {}, sending empty", e);
                                    raw_payload.extend_from_slice(&0u32.to_le_bytes());
                                }
                            }
                        } else {
                            eprintln!("[vac-daemon] VacKmod not available, sending empty proc list");
                            raw_payload.extend_from_slice(&0u32.to_le_bytes());
                        }
                    }
                    8 => {
                        // Hidden process detection: compare ring-0 vs user-mode
                        match VacKmod::open() {
                        Some(kmod) => {
                        let ring0_procs = kmod.proc_list().unwrap_or_default();
                        let user_procs = user_mode_proc_list();

                        // Verify PID namespace alignment: if kmod is loaded, make sure
                        // the daemon's own PID exists in the ring-0 list. If not, we're
                        // running in a different PID namespace (e.g., container) and
                        // hidden-proc comparison would be meaningless.
                        let ns_mismatch = !ring0_procs.iter().any(|(pid, _, _)| *pid == std::process::id());

                        if ns_mismatch {
                            eprintln!("[vac-daemon] PID namespace mismatch (daemon PID {} not in ring-0 list), skipping hidden proc check", std::process::id());
                            raw_payload.extend_from_slice(&0u32.to_le_bytes()); // hidden_count = 0
                            raw_payload.extend_from_slice(&0u32.to_le_bytes()); // missing_count = 0
                        } else {
                            let ring0_pids: HashSet<u32> = ring0_procs.iter().map(|(pid, _, _)| *pid).collect();
                            let user_pids: HashSet<u32> = user_procs.iter().map(|(pid, _)| *pid).collect();

                            let hidden: Vec<_> = ring0_procs.iter()
                                .filter(|(pid, _, _)| !user_pids.contains(pid))
                                .collect();
                            let missing: Vec<_> = user_procs.iter()
                                .filter(|(pid, _)| !ring0_pids.contains(pid))
                                .collect();

                            eprintln!("[vac-daemon] Hidden proc check: {} hidden from user, {} missing from ring0",
                                hidden.len(), missing.len());

                            raw_payload.extend_from_slice(&(hidden.len() as u32).to_le_bytes());
                            raw_payload.extend_from_slice(&(missing.len() as u32).to_le_bytes());
                            for (pid, _, comm) in &hidden {
                                raw_payload.extend_from_slice(&pid.to_le_bytes());
                                let comm_bytes = comm.as_bytes();
                                raw_payload.extend_from_slice(&(comm_bytes.len() as u32).to_le_bytes());
                                raw_payload.extend_from_slice(comm_bytes);
                            }
                            for (pid, comm) in &missing {
                                raw_payload.extend_from_slice(&pid.to_le_bytes());
                                let comm_bytes = comm.as_bytes();
                                raw_payload.extend_from_slice(&(comm_bytes.len() as u32).to_le_bytes());
                                raw_payload.extend_from_slice(comm_bytes);
                            }
                        }
                        }
                        None => {
                            // No ring-0 view available — comparison is meaningless and
                            // would false-flag every user-mode process as "missing".
                            eprintln!("[vac-daemon] No kmod, skipping hidden proc check");
                            raw_payload.extend_from_slice(&0u32.to_le_bytes()); // hidden_count = 0
                            raw_payload.extend_from_slice(&0u32.to_le_bytes()); // missing_count = 0
                        }
                        }
                    }
                    9 => {
                        // Memory scan: check for suspicious memory mappings via /proc/self/maps
                        // and verify .text sections via ring-0 READ_MEM if available
                        let maps = read_maps();
                        let mut rwx_count: u32 = 0;
                        let mut anon_exec_count: u32 = 0;
                        let mut regions_checked: u32 = 0;

                        for entry in &maps {
                            regions_checked += 1;
                            if entry.perms.contains("rwx") {
                                rwx_count += 1;
                            }
                            if entry.perms.contains('x') && !entry.perms.contains('w') && entry.path.is_empty() {
                                anon_exec_count += 1;
                            }
                        }

                        // If VacKmod is available, verify that code pages are genuine
                        // by reading first bytes via ring-0 and checking for ELF headers
                        let mut text_mismatches: u32 = 0;
                        if let Some(kmod) = VacKmod::open() {
                            for entry in &maps {
                                if !entry.perms.contains('x') || entry.path.is_empty() {
                                    continue;
                                }
                                // Read first 16 bytes of this mapping via ring-0
                                let mut buf = [0u8; 16];
                                if kmod.read_mem(std::process::id(), entry.start, &mut buf).is_ok() {
                                    if entry.path.ends_with(".so") || entry.path.ends_with(".dll") {
                                        // Should start with ELF magic (\x7fELF)
                                        if buf[0] != 0x7f || buf[1] != b'E' || buf[2] != b'L' || buf[3] != b'F' {
                                            text_mismatches += 1;
                                        }
                                    }
                                }
                            }
                        }

                        eprintln!("[vac-daemon] Memory scan: {} RWX pages, {} anon-exec, {} text mismatches on {} regions",
                            rwx_count, anon_exec_count, text_mismatches, regions_checked);

                        // Layout: rwx_count(u32) + anon_exec_count(u32) + regions_checked(u32) + text_mismatches(u32)
                        raw_payload.extend_from_slice(&rwx_count.to_le_bytes());
                        raw_payload.extend_from_slice(&anon_exec_count.to_le_bytes());
                        raw_payload.extend_from_slice(&regions_checked.to_le_bytes());
                        raw_payload.extend_from_slice(&text_mismatches.to_le_bytes());
                    }
                    _ => {
                        // Standard client scan (modules 1-6)
                        let mut buf = DataBuffer::new();
                        run_module(module_id, &sys, &mut buf);
                        let data_bytes = unsafe {
                            std::slice::from_raw_parts(
                                buf.raw.as_ptr() as *const u8,
                                buf.raw.len() * 4,
                            )
                        };
                        raw_payload.extend_from_slice(data_bytes);
                    }
                }

                // Determine seal module_id
                let seal_module_id = match module_id {
                    7 => 200u32,
                    8 => 201u32,
                    9 => 202u32,
                    10 => 203u32,
                    _ => module_id + 100,
                };

                // Clients never hold signing keys — encryption-only seal.
                let seal_key = seal::SealKey {
                    kyber_public_key: kyber_pk.to_vec(),
                    mldsa65_secret_key: None,
                };
                let sealed = seal::seal(&raw_payload, seal_module_id, &seal_key)
                    .map_err(|_| "seal failed")?;

                // Send result
                let mut result = Vec::with_capacity(8 + sealed.raw.len());
                result.extend_from_slice(&module_id.to_le_bytes());
                result.extend_from_slice(&(sealed.raw.len() as i32).to_le_bytes());
                result.extend_from_slice(&sealed.raw);
                send_msg(&mut stream, 0x04, &result)?;

                eprintln!("[vac-daemon] Sent {} bytes for module {}", sealed.raw.len(), module_id);
            }
            0x05 => {
                // PING
                send_msg(&mut stream, 0x06, &[])?;
            }
            _ => {
                eprintln!("[vac-daemon] Unknown message type: {}", mtype);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: vac-daemon <server:port> <steam_id> [access_token]");
        std::process::exit(1);
    }
    let server_addr = &args[1];
    let steam_id: u64 = args[2].parse().expect("invalid steam_id");
    let token = args.get(3).map(|s| s.as_str());

    eprintln!("[vac-daemon] Starting, server={}, steam_id={}", server_addr, steam_id);

    loop {
        match handle_server(steam_id, token, server_addr) {
            Ok(()) => {
                eprintln!("[vac-daemon] Connection closed by server, reconnecting...");
                std::thread::sleep(Duration::from_secs(5));
            }
            Err(e) if e.starts_with("auth:") => {
                eprintln!("[vac-daemon] {}: {}", e,
                    "server rejected this client. Check your access token (arg 3) against the link/code from game chat.");
                std::thread::sleep(Duration::from_secs(30));
            }
            Err(e) => {
                eprintln!("[vac-daemon] Error: {}", e);
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }
}
