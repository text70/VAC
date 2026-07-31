// vac-daemon-win — Windows client-side VAC daemon.
// Mirrors vac-daemon protocol but uses Win32System + Win32Kmod.
//
// Build: cargo build --release --target x86_64-pc-windows-gnu -p vac-daemon-win

#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::net::TcpStream;
#[cfg(windows)]
use std::time::Duration;

#[cfg(not(windows))]
fn main() {
    eprintln!("vac-daemon-win is Windows-only.");
    eprintln!("Build: cargo build --release --target x86_64-pc-windows-gnu -p vac-daemon-win");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    run_daemon();
}

#[cfg(windows)]
fn run_daemon() {
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;

    use vac_client_core::run_module;
    use vac_core::buffer::DataBuffer;
    use vac_crypto::seal;
    use vac_sys::SystemOps;
    use vac_sys::win32_kmod::Win32Kmod;
    use vac_sys::win32_table;

    const NONCE_LEN: usize = 8;
    const CONFIG_PATH: &str = "vac-daemon.ini";

    // -----------------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------------
    struct Config {
        server: String,
        steam_id: Option<u64>,
    }

    fn load_config(path: &str) -> Config {
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut server = String::new();
        let mut steam_id: Option<u64> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim().to_lowercase();
                let val = line[eq + 1..].trim();
                match key.as_str() {
                    "server" => server = val.to_string(),
                    "steam_id" => steam_id = val.parse().ok(),
                    _ => {}
                }
            }
        }
        Config { server, steam_id }
    }

    // -----------------------------------------------------------------------
    // Steam ID discovery (Windows)
    // -----------------------------------------------------------------------
    fn find_steam_id() -> Option<u64> {
        let paths = [
            r"C:\Program Files (x86)\Steam\config\loginusers.vdf",
            r"C:\Program Files\Steam\config\loginusers.vdf",
        ];
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let mut p = PathBuf::from(&profile);
            p.push(r"AppData\Local\Steam\config\loginusers.vdf");
            if p.exists() {
                return parse_loginusers_vdf(&fs::read_to_string(p).unwrap_or_default());
            }
        }
        for p in &paths {
            if let Ok(content) = fs::read_to_string(p) {
                return parse_loginusers_vdf(&content);
            }
        }
        None
    }

    fn parse_loginusers_vdf(content: &str) -> Option<u64> {
        if let Some(start) = content.find("\"users\"") {
            if let Some(brace) = content[start..].find('{') {
                let rest = &content[start + brace + 1..];
                let mut depth = 1i32;
                let mut i = 0;
                while i < rest.len() && depth > 0 {
                    let c = rest.as_bytes()[i];
                    if c == b'{' {
                        depth += 1;
                    } else if c == b'}' {
                        depth -= 1;
                    } else if c == b'"' && depth == 1 {
                        let end = rest[i + 1..].find('"').map(|p| i + 1 + p)?;
                        let key = &rest[i + 1..end];
                        if let Ok(sid) = key.parse::<u64>() {
                            return Some(sid);
                        }
                        i = end;
                    }
                    i += 1;
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Win32 direct FFI for module 9 (memory region enumeration)
    // -----------------------------------------------------------------------
    #[repr(C)]
    struct MEMORY_BASIC_INFORMATION {
        base_address: *mut std::ffi::c_void,
        allocation_base: *mut std::ffi::c_void,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_GUARD: u32 = 0x100;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;
    const MEM_PRIVATE: u32 = 0x20000;

    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn VirtualQueryEx(
            h_process: *mut std::ffi::c_void,
            lp_address: *const std::ffi::c_void,
            lp_buffer: *mut MEMORY_BASIC_INFORMATION,
            dw_length: usize,
        ) -> usize;
    }

    #[link(name = "psapi")]
    extern "system" {
        fn GetMappedFileNameW(
            h_process: *mut std::ffi::c_void,
            lpv: *mut std::ffi::c_void,
            lp_filename: *mut u16,
            n_size: u32,
        ) -> u32;
    }

    struct MemRegion {
        start: u64,
        perms: String,
        path: String,
    }

    fn enumerate_regions() -> Vec<MemRegion> {
        let mut regions = Vec::new();
        unsafe {
            let hproc = GetCurrentProcess();
            let mut addr: *mut std::ffi::c_void = std::ptr::null_mut();
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let ret = VirtualQueryEx(
                    hproc,
                    addr as *const std::ffi::c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if ret == 0 {
                    break;
                }
                if mbi.state == MEM_COMMIT {
                    let prot = mbi.protect & !PAGE_GUARD;
                    let is_exec = (prot & PAGE_EXECUTE) != 0;
                    let is_write = prot == PAGE_EXECUTE_READWRITE
                        || (prot & 0x02) != 0;

                    let mut perms = String::with_capacity(3);
                    perms.push(if (prot & 0x04) != 0 || (prot & 0x02) != 0 || is_exec { 'r' } else { '-' });
                    perms.push(if is_write { 'w' } else { '-' });
                    perms.push(if is_exec { 'x' } else { '-' });

                    let path = if mbi.type_ == MEM_IMAGE {
                        let mut buf = [0u16; 1024];
                        let n = GetMappedFileNameW(hproc, mbi.base_address, buf.as_mut_ptr(), 1024);
                        if n > 0 {
                            String::from_utf16_lossy(&buf[..n as usize])
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    regions.push(MemRegion {
                        start: mbi.base_address as u64,
                        perms,
                        path,
                    });
                }
                addr = mbi.base_address.wrapping_add(mbi.region_size);
                if addr.is_null() {
                    break;
                }
            }
        }
        regions
    }

    // -----------------------------------------------------------------------
    // Protocol helpers
    // -----------------------------------------------------------------------
    fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
        let mut off = 0;
        while off < buf.len() {
            match stream.read(&mut buf[off..]) {
                Ok(0) => return Err("connection closed".into()),
                Ok(n) => off += n,
                Err(e) => return Err(format!("read: {}", e)),
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
        stream.write_all(&buf).map_err(|e| format!("write: {}", e))
    }

    fn recv_msg(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), String> {
        let mut len_buf = [0u8; 4];
        read_exact(stream, &mut len_buf)?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65536 {
            return Err("invalid frame".into());
        }
        let mut msg = vec![0u8; msg_len];
        read_exact(stream, &mut msg)?;
        Ok((msg[0], msg[1..].to_vec()))
    }

    // -----------------------------------------------------------------------
    // Module 7: ring-0 process list via Win32Kmod
    // -----------------------------------------------------------------------
    fn module7_proc_list(kmod: Option<&Win32Kmod>) -> Vec<u8> {
        let mut raw = Vec::new();
        if let Some(kmod) = kmod {
            match kmod.proc_list() {
                Ok(procs) => {
                    raw.extend_from_slice(&(procs.len() as u32).to_le_bytes());
                    for (pid, ppid, comm) in &procs {
                        raw.extend_from_slice(&pid.to_le_bytes());
                        raw.extend_from_slice(&ppid.to_le_bytes());
                        let mut buf = [0u8; 16];
                        let bytes = comm.as_bytes();
                        let clen = bytes.len().min(15);
                        buf[..clen].copy_from_slice(&bytes[..clen]);
                        raw.extend_from_slice(&buf);
                    }
                }
                Err(_) => raw.extend_from_slice(&0u32.to_le_bytes()),
            }
        } else {
            raw.extend_from_slice(&0u32.to_le_bytes());
        }
        raw
    }

    // -----------------------------------------------------------------------
    // Module 8: hidden proc detection (ring0 vs user-mode via Toolhelp32)
    // -----------------------------------------------------------------------
    fn module8_hidden_procs(kmod: Option<&Win32Kmod>) -> Vec<u8> {
        let mut raw = Vec::new();
        let ring0_procs = kmod.and_then(|k| k.proc_list().ok()).unwrap_or_default();
        let sys = vac_sys::win32::Win32System::new();
        let user_procs = sys.enumerate_processes().unwrap_or_default();

        let ring0_pids: HashSet<u32> = ring0_procs.iter().map(|(pid, _, _)| *pid).collect();
        let user_pids: HashSet<u32> = user_procs.iter().map(|(pid, _, _)| *pid).collect();

        let hidden: Vec<_> = ring0_procs.iter().filter(|(p, _, _)| !user_pids.contains(p)).collect();
        let missing: Vec<_> = user_procs.iter().filter(|(p, _, _)| !ring0_pids.contains(p)).collect();

        raw.extend_from_slice(&(hidden.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(missing.len() as u32).to_le_bytes());
        for (pid, _, comm) in &hidden {
            raw.extend_from_slice(&pid.to_le_bytes());
            let b = comm.as_bytes();
            raw.extend_from_slice(&(b.len() as u32).to_le_bytes());
            raw.extend_from_slice(b);
        }
        for (pid, _ppid, comm) in &missing {
            raw.extend_from_slice(&pid.to_le_bytes());
            let b = comm.as_bytes();
            raw.extend_from_slice(&(b.len() as u32).to_le_bytes());
            raw.extend_from_slice(b);
        }
        raw
    }

    // -----------------------------------------------------------------------
    // Module 9: memory scan via VirtualQuery + Win32Kmod text check
    // -----------------------------------------------------------------------
    fn module9_memory_scan(kmod: Option<&Win32Kmod>) -> Vec<u8> {
        let regions = enumerate_regions();
        let mut rwx = 0u32;
        let mut anon_exec = 0u32;
        let mut checked = 0u32;
        let mut mismatches = 0u32;

        for r in &regions {
            checked += 1;
            if r.perms == "rwx" {
                rwx += 1;
            }
            if r.perms.contains('x') && !r.perms.contains('w') && r.path.is_empty() {
                anon_exec += 1;
            }
        }

        // Text section verification via ring-0: check PE/MZ headers
        if let Some(kmod) = kmod {
            for r in &regions {
                if !r.perms.contains('x') || r.path.is_empty() {
                    continue;
                }
                let mut buf = [0u8; 16];
                if kmod.read_mem(std::process::id(), r.start, &mut buf).is_ok() {
                    if r.path.ends_with(".dll") || r.path.ends_with(".exe") || r.path.ends_with(".sys") {
                        // PE binaries start with MZ (0x4D, 0x5A)
                        if buf[0] != b'M' || buf[1] != b'Z' {
                            mismatches += 1;
                        }
                    }
                }
            }
        }

        let mut raw = Vec::with_capacity(16);
        raw.extend_from_slice(&rwx.to_le_bytes());
        raw.extend_from_slice(&anon_exec.to_le_bytes());
        raw.extend_from_slice(&checked.to_le_bytes());
        raw.extend_from_slice(&mismatches.to_le_bytes());
        raw
    }

    // -----------------------------------------------------------------------
    // Server handler loop
    // -----------------------------------------------------------------------
    fn handle_server(
        steam_id: u64,
        server_addr: &str,
        kmod: Option<&Win32Kmod>,
    ) -> Result<(), String> {
        let mut stream = TcpStream::connect(server_addr)
            .map_err(|e| format!("connect: {}", e))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("timeout: {}", e))?;

        send_msg(&mut stream, 0x01, &steam_id.to_le_bytes())?;
        let (mtype, _) = recv_msg(&mut stream)?;
        if mtype != 0x02 {
            return Err(format!("auth failed type={}", mtype));
        }

        loop {
            let (mtype, payload) = recv_msg(&mut stream)?;
            if mtype != 0x03 {
                if mtype == 0x05 {
                    send_msg(&mut stream, 0x06, &[])?;
                }
                continue;
            }
            if payload.len() < 16 {
                continue;
            }

            let module_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            let kpk_len = i32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
            if 8 + kpk_len + 4 > payload.len() { continue; }
            let kyber_pk = &payload[8..8 + kpk_len];

            let off = 8 + kpk_len;
            let dsk_len = i32::from_le_bytes(payload[off..off + 4].try_into().unwrap()) as usize;
            if off + 4 + dsk_len + NONCE_LEN > payload.len() { continue; }
            let dsa_sk = &payload[off + 4..off + 4 + dsk_len];
            let nonce = &payload[off + 4 + dsk_len..off + 4 + dsk_len + NONCE_LEN];

            let mut scan_data = Vec::new();
            scan_data.extend_from_slice(nonce);

            match module_id {
                7 => scan_data.extend_from_slice(&module7_proc_list(kmod)),
                8 => scan_data.extend_from_slice(&module8_hidden_procs(kmod)),
                9 => scan_data.extend_from_slice(&module9_memory_scan(kmod)),
                _ => {
                    let sys = vac_sys::win32::Win32System::new();
                    let mut buf = DataBuffer::new();
                    run_module(module_id, &sys, &mut buf);
                    let bytes = unsafe {
                        std::slice::from_raw_parts(buf.raw.as_ptr() as *const u8, buf.raw.len() * 4)
                    };
                    scan_data.extend_from_slice(bytes);
                }
            }

            let seal_mid = match module_id {
                7 => 200, 8 => 201, 9 => 202,
                m => m + 100,
            };
            let key = seal::SealKey {
                kyber_public_key: kyber_pk.to_vec(),
                mldsa65_secret_key: dsa_sk.to_vec(),
            };
            let sealed = seal::seal(&scan_data, seal_mid, &key).map_err(|_| "seal failed")?;

            let mut result = Vec::with_capacity(8 + sealed.raw.len());
            result.extend_from_slice(&module_id.to_le_bytes());
            result.extend_from_slice(&(sealed.raw.len() as i32).to_le_bytes());
            result.extend_from_slice(&sealed.raw);
            send_msg(&mut stream, 0x04, &result)?;
        }
    }

    // -----------------------------------------------------------------------
    // Entrypoint
    // -----------------------------------------------------------------------
    let config = load_config(CONFIG_PATH);
    if config.server.is_empty() {
        eprintln!("[vac-daemon-win] No server in {}. Create: server=1.2.3.4:28084", CONFIG_PATH);
        std::process::exit(1);
    }

    let steam_id = config.steam_id.or_else(find_steam_id).unwrap_or_else(|| {
        eprintln!("[vac-daemon-win] No Steam ID. Set steam_id= in {}", CONFIG_PATH);
        std::process::exit(1);
    });

    let api = win32_table::resolve_winapi();
    let kmod = Win32Kmod::open(&api);

    if kmod.is_some() {
        eprintln!("[vac-daemon-win] Ring-0 available");
    } else {
        eprintln!("[vac-daemon-win] User-mode only (no driver)");
    }

    eprintln!("[vac-daemon-win] server={}, steam_id={}", config.server, steam_id);

    loop {
        match handle_server(steam_id, &config.server, kmod.as_ref()) {
            Ok(()) => eprintln!("[vac-daemon-win] Connection closed"),
            Err(e) => eprintln!("[vac-daemon-win] Error: {}", e),
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}