use vac_core::buffer::DataBuffer;
use vac_sys::SystemOps;

pub trait ClientScanModule {
    fn name(&self) -> &'static str;
    fn module_id(&self) -> u32;
    fn scan(&mut self, sys: &dyn SystemOps, report: &mut DataBuffer);
}

pub const CLIENT_MODULE_PROCESS: u32 = 1;
pub const CLIENT_MODULE_LIBRARIES: u32 = 2;
pub const CLIENT_MODULE_DEBUGGER: u32 = 3;
pub const CLIENT_MODULE_ASSEMBLIES: u32 = 4;
pub const CLIENT_MODULE_ENVIRONMENT: u32 = 5;
pub const CLIENT_MODULE_CHEATS: u32 = 6;
/// Game-process memory scan (RustClient). Sealed mid on the wire: 203.
pub const CLIENT_MODULE_GAME_MEMORY: u32 = 10;

pub fn run_module(
    module_id: u32,
    sys: &dyn SystemOps,
    report: &mut DataBuffer,
) {
    match module_id {
        1 => process_scan(sys, report),
        2 => libraries_scan(sys, report),
        3 => debugger_scan(sys, report),
        4 => assemblies_scan(sys, report),
        5 => environment_scan(report),
        6 => cheats_scan(sys, report),
        10 => game_memory_scan(sys, report),
        _ => {}
    }
}

fn pad_to(buf: &mut DataBuffer, target: usize) {
    if buf.cursor() < target {
        buf.set_cursor(target.min(2048));
    }
}

fn process_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    let pid = sys.current_process_id();
    let tid = sys.current_thread_id();
    let exe = sys.current_exe_path().unwrap_or_default();
    let cmdline = sys.process_cmdline(pid).unwrap_or_default();

    // Hardware presence indicator (replaces old TPM attestation)
    let presence = sys.hardware_presence().unwrap_or_else(|_| vec![0u8; 32]);

    let parent_pid = sys.kernel_proc_list()
        .ok()
        .and_then(|procs| {
            for (p, pp, _) in &procs {
                if *p == pid {
                    return Some(*pp);
                }
            }
            None
        })
        .unwrap_or(0);

    buf.write_u32(pid);
    buf.write_u32(tid);
    buf.write_u32(parent_pid);
    let exe_hash = vac_core::hash::vac_hash(exe.as_bytes());
    buf.write_u32(exe_hash);
    let cmd_hash = vac_core::hash::vac_hash(cmdline.as_bytes());
    buf.write_u32(cmd_hash);

    // Write hardware presence + kernel module status (32 bytes)
    let kmod_loaded = sys.kernel_module_loaded();
    let kmod_flag = if kmod_loaded { 1u32 } else { 0u32 };
    buf.write_u32(kmod_flag);

    // Number of processes visible to the kernel module (ring-0 trusted count)
    let kproc_count = if kmod_loaded {
        sys.kernel_proc_list().ok().map(|p| p.len() as u32).unwrap_or(0)
    } else {
        0
    };
    buf.write_u32(kproc_count);

    // Write hardware presence data (remaining dwords 7-14)
    for chunk in presence.chunks(4).take(8) {
        let mut val = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            val |= (b as u32) << (i * 8);
        }
        buf.write_u32(val);
    }

    pad_to(buf, 96);
}

fn libraries_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    let libs = sys.loaded_libraries().unwrap_or_default();
    buf.write_u32(libs.len() as u32);

    for lib in libs.iter().take(256) {
        let name_hash = vac_core::hash::vac_hash(lib.name.as_bytes());
        buf.write_u32(name_hash);
        let path_hash = vac_core::hash::vac_hash(lib.path.as_bytes());
        buf.write_u32(path_hash);
        buf.write_u32(lib.base_address as u32);
        buf.write_u32((lib.base_address >> 32) as u32);
        buf.write_u32(lib.size as u32);
        buf.write_u32((lib.size >> 32) as u32);
    }
    pad_to(buf, 512);
}

// ---------------------------------------------------------------------------
// Module 3 — debugger detection (platform-aware)
// ---------------------------------------------------------------------------

/// (flags, tracer_id, suspicious_region_count)
#[cfg(unix)]
fn debugger_state() -> (u32, u32, u32) {
    let mut flags = 0u32;

    // TracerPid check
    let tracer = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            for line in s.lines() {
                if line.starts_with("TracerPid:") {
                    return line.split(':').nth(1)?.trim().parse::<u32>().ok();
                }
            }
            None
        })
        .unwrap_or(0);
    if tracer != 0 {
        flags |= 1;
    }

    // ptrace check via /proc/sys/kernel/yama/ptrace_scope and self status
    let ptrace_scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .unwrap_or_default()
        .trim()
        .parse::<u32>()
        .unwrap_or(1);
    if ptrace_scope == 0 {
        flags |= 2;
    }

    // Check for debugger in cmdline
    let pid = std::process::id();
    if let Ok(parent) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        let ppid: u32 = parent.lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().parse::<u32>().ok())
            .flatten()
            .unwrap_or(0);
        if ppid > 0 {
            if let Ok(parent_cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", ppid)) {
                let parent_name = parent_cmdline.replace('\0', " ").to_lowercase();
                if parent_name.contains("gdb") || parent_name.contains("lldb")
                    || parent_name.contains("strace") || parent_name.contains("ltrace")
                {
                    flags |= 4;
                }
            }
        }
    }

    // Check /proc/self/maps for suspicious regions
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let suspicious_maps: Vec<&str> = maps.lines()
        .filter(|l| {
            l.contains("rwx") || l.contains("(deleted)")
        })
        .collect();
    if suspicious_maps.len() > 5 {
        flags |= 8;
    }

    let has_vdso = maps.contains("[vdso]");
    if !has_vdso {
        flags |= 16;
    }

    (flags, tracer, suspicious_maps.len() as u32)
}

#[cfg(windows)]
fn debugger_state(sys: &dyn SystemOps) -> (u32, u32, u32) {
    use self::winffi;

    let mut flags = 0u32;
    let mut tracer = 0u32;

    unsafe {
        if winffi::IsDebuggerPresent() != 0 {
            flags |= 1;
            tracer = 1;
        }
        let mut remote: i32 = 0;
        if winffi::CheckRemoteDebuggerPresent(winffi::GetCurrentProcess(), &mut remote) != 0 && remote != 0 {
            flags |= 2;
            tracer = tracer.max(1);
        }
    }

    // Suspicious parent process (debuggers/tools attached by launcher)
    let my_pid = std::process::id();
    if let Ok(procs) = sys.enumerate_processes() {
        let ppid = procs.iter()
            .find(|(p, _, _)| *p == my_pid)
            .map(|(_, pp, _)| *pp)
            .unwrap_or(0);
        if ppid > 0 {
            if let Some((_, _, pname)) = procs.iter().find(|(p, _, _)| *p == ppid) {
                let n = pname.to_lowercase();
                const BAD_PARENTS: &[&str] = &[
                    "windbg", "x64dbg", "x32dbg", "ollydbg", "cheat engine",
                    "cheatengine", "process hacker", "processhacker", "dnspy",
                    "httpdebugger", "fiddler",
                ];
                if BAD_PARENTS.iter().any(|t| n.contains(t)) {
                    flags |= 4;
                }
            }
        }
    }

    // Private executable regions in our own address space
    let priv_exec = winffi::count_private_exec_regions(std::process::id());
    if priv_exec > 5 {
        flags |= 8;
    }

    (flags, tracer, priv_exec)
}

#[allow(unused_variables)]
fn debugger_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    #[cfg(unix)]
    let (flags, tracer, suspicious) = debugger_state();
    #[cfg(windows)]
    let (flags, tracer, suspicious) = debugger_state(sys);

    buf.write_u32(flags);
    buf.write_u32(tracer);
    buf.write_u32(suspicious);
    pad_to(buf, 32);
}

// ---------------------------------------------------------------------------
// Module 4 — game assembly integrity (platform-aware via loaded_libraries)
// ---------------------------------------------------------------------------

fn assemblies_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    let mut flags = 0u32;

    let target_assemblies = [
        "assembly-csharp.dll",
        "assembly-csharp-firstpass.dll",
        "facepunch.console.dll",
        "facepunch.network.dll",
        "facepunch.unity.dll",
        "unityengine.dll",
        "unityengine.coremodule.dll",
    ];

    let libs = sys.loaded_libraries().unwrap_or_default();
    let names: Vec<String> = libs.iter()
        .map(|l| l.name.to_lowercase())
        .collect();

    for target in &target_assemblies {
        let found = names.iter().any(|n| n.contains(target));
        if !found {
            flags |= 1;
        }
    }

    buf.write_u32(flags);

    let mut bad_count = 0u32;
    for f in &names {
        if f.contains("harmony") || f.contains("inject")
            || f.contains("loader") || f.contains("cheat")
        {
            bad_count += 1;
        }
    }
    buf.write_u32(bad_count);
    pad_to(buf, 32);
}

// ---------------------------------------------------------------------------
// Module 5 — environment checks
// ---------------------------------------------------------------------------

fn environment_scan(buf: &mut DataBuffer) {
    let mut flags = 0u32;

    for (key, value) in std::env::vars() {
        let k = key.to_lowercase();
        let v = value.to_lowercase();
        match k.as_str() {
            "ld_preload" => {
                if !v.is_empty() { flags |= 1; }
            }
            "ld_library_path" => {
                if v.contains(".") || v.contains("..") || v.contains("tmp") { flags |= 2; }
            }
            "ld_audit" => {
                if !v.is_empty() { flags |= 4; }
            }
            "ld_debug" => {
                if !v.is_empty() { flags |= 8; }
            }
            "mono_debug" => {
                if !v.is_empty() { flags |= 16; }
            }
            "mono_env_options" => {
                if !v.is_empty() { flags |= 32; }
            }
            // Wine DLL overrides are an injection vector under Proton/Wine
            "winedlloverages" => {
                if !v.is_empty() { flags |= 64; }
            }
            _ => {}
        }
    }

    buf.write_u32(flags);
    pad_to(buf, 16);
}

// ---------------------------------------------------------------------------
// Module 6 — known cheat processes
// ---------------------------------------------------------------------------

fn cheats_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    // Use kernel module trusted path when available; falls back to user-mode
    let procs = sys.kernel_proc_list().unwrap_or_default();
    let mut cheats_found = Vec::new();

    let known_cheats: &[&str] = &[
        "cheatengine", "cheat engine", "artmoney", "gameguardian",
        "wemod", "trainer", "injector", "reclass", "x64dbg",
        "x32dbg", "ollydbg", "dnspy", "de4dot", "confuser",
        "processhacker", "process explorer", "pchunter",
        "frida", "gdb", "lldb", "strace", "ltrace",
        "httrack", "wireshark", "tcpdump", "mitmproxy",
        "burpsuite", "fiddler", "proxifier", "sockscap",
    ];

    for (pid, _ppid, name) in &procs {
        let n = name.to_lowercase();
        for cheat in known_cheats {
            if n.contains(cheat) {
                cheats_found.push(*pid);
                break;
            }
        }
    }

    buf.write_u32(cheats_found.len() as u32);
    for pid in cheats_found.iter().take(32) {
        buf.write_u32(*pid);
    }
    pad_to(buf, 64);
}

// ---------------------------------------------------------------------------
// Module 10 — game-process memory scan
// Payload dwords: [found][pid][status][rwx][priv_exec][hdr_mismatch]
//   status: 1 = game not found, 2 = scanned, 3 = access denied
// ---------------------------------------------------------------------------

const GAME_PROCESS_NAMES: &[&str] = &["rustclient"];

fn find_game_pid(sys: &dyn SystemOps) -> Option<u32> {
    let procs = sys.enumerate_processes().ok()?;
    procs.into_iter()
        .find(|(_, _, name)| {
            let n = name.to_lowercase();
            GAME_PROCESS_NAMES.iter().any(|t| n.starts_with(t))
        })
        .map(|(pid, _, _)| pid)
}

/// Scan a Linux game process via /proc/<pid>/maps.
/// Overlay-injected anon-exec pages show up here too — this is telemetry for
/// the server to baseline; only structural tamper scores points server-side.
#[cfg(unix)]
fn game_scan_impl(pid: u32) -> [u32; 4] {
    let maps = match std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        Ok(m) => m,
        Err(_) => return [0, 0, 3, 0], // denied / gone
    };

    let mut rwx = 0u32;
    let mut priv_exec = 0u32;
    let mut hdr_mismatch = 0u32;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let perms = parts[1];
        let path = parts.get(5).copied().unwrap_or("");
        if perms.contains('x') {
            if perms.contains("rwx") {
                rwx += 1;
            }
            if path.is_empty() || path.contains("(deleted)") || path.starts_with("/memfd:") {
                priv_exec += 1;
            }
        }
    }

    // On Linux, image-header verification would require reading the target's
    // memory (needs the kmod); without it there is nothing to mismatch.
    let _ = &mut hdr_mismatch;

    [rwx, priv_exec, 2, hdr_mismatch]
}

#[cfg(windows)]
fn game_scan_impl(pid: u32) -> [u32; 4] {
    self::winffi::scan_game_process(pid)
}

fn game_memory_scan(sys: &dyn SystemOps, buf: &mut DataBuffer) {
    let (found, pid, result) = match find_game_pid(sys) {
        Some(pid) => (1u32, pid, game_scan_impl(pid)),
        None => (0u32, 0u32, [0, 0, 1, 0]),
    };

    buf.write_u32(found);
    buf.write_u32(pid);
    buf.write_u32(result[2]); // status
    buf.write_u32(result[0]); // rwx
    buf.write_u32(result[1]); // priv_exec
    buf.write_u32(result[3]); // hdr_mismatch
    pad_to(buf, 8);
}

// ---------------------------------------------------------------------------
// Win32 FFI helpers (compiled only on Windows targets)
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod winffi {
    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut std::ffi::c_void,
        allocation_base: *mut std::ffi::c_void,
        allocation_protect: u32,
        __alignment1: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    const PAGE_GUARD: u32 = 0x100;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;
    const MEM_PRIVATE: u32 = 0x20000;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_VM_READ: u32 = 0x0010;

    extern "system" {
        pub(crate) fn GetCurrentProcess() -> *mut std::ffi::c_void;
        pub(crate) fn IsDebuggerPresent() -> i32;
        pub(crate) fn CheckRemoteDebuggerPresent(h_process: *mut std::ffi::c_void, debugger_present: *mut i32) -> i32;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, pid: u32) -> *mut std::ffi::c_void;
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        fn VirtualQueryEx(
            h_process: *mut std::ffi::c_void,
            lp_address: *const std::ffi::c_void,
            lp_buffer: *mut MemoryBasicInformation,
            dw_length: usize,
        ) -> usize;
        fn ReadProcessMemory(
            h_process: *mut std::ffi::c_void,
            lp_base_address: *const std::ffi::c_void,
            lp_buffer: *mut u8,
            n_size: usize,
            lp_number_of_bytes_read: *mut usize,
        ) -> i32;
    }

    pub(super) fn is_exec_protect(prot: u32) -> bool {
        prot & 0xF0 != 0 // PAGE_EXECUTE* family
    }

    /// Count committed private executable regions in the given process.
    pub(super) fn count_private_exec_regions(pid: u32) -> u32 {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() {
                return 0;
            }
            let mut addr: usize = 0x10000;
            let mut priv_exec = 0u32;
            loop {
                let mut mbi: MemoryBasicInformation = std::mem::zeroed();
                let ret = VirtualQueryEx(
                    handle,
                    addr as *const _,
                    &mut mbi,
                    std::mem::size_of::<MemoryBasicInformation>(),
                );
                if ret == 0 {
                    break;
                }
                let size = mbi.region_size;
                if size == 0 {
                    break;
                }
                if mbi.state == MEM_COMMIT
                    && mbi.type_ == MEM_PRIVATE
                    && is_exec_protect(mbi.protect & !PAGE_GUARD)
                {
                    priv_exec += 1;
                }
                addr = addr.wrapping_add(size);
                if addr == 0 {
                    break;
                }
            }
            CloseHandle(handle);
            priv_exec
        }
    }

    /// Full game-process scan: region stats + MZ header validation on
    /// image-backed executable regions (manual mappers strip headers).
    pub(super) fn scan_game_process(pid: u32) -> [u32; 4] {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() {
                return [0, 0, 3, 0]; // denied
            }

            let mut addr: usize = 0x10000;
            let mut rwx = 0u32;
            let mut priv_exec = 0u32;
            let mut hdr_mismatch = 0u32;
            loop {
                let mut mbi: MemoryBasicInformation = std::mem::zeroed();
                let ret = VirtualQueryEx(
                    handle,
                    addr as *const _,
                    &mut mbi,
                    std::mem::size_of::<MemoryBasicInformation>(),
                );
                if ret == 0 {
                    break;
                }
                let size = mbi.region_size;
                if size == 0 {
                    break;
                }
                if mbi.state == MEM_COMMIT {
                    let prot = mbi.protect & !PAGE_GUARD;
                    let exec = is_exec_protect(prot);
                    if mbi.type_ == MEM_PRIVATE && exec {
                        priv_exec += 1;
                        if prot == 0x40 || prot == 0x80 {
                            rwx += 1;
                        }
                    } else if mbi.type_ == MEM_IMAGE && exec {
                        let mut hdr = [0u8; 2];
                        let mut read: usize = 0;
                        if ReadProcessMemory(
                            handle,
                            mbi.base_address,
                            hdr.as_mut_ptr(),
                            2,
                            &mut read,
                        ) != 0 && read == 2
                        {
                            if !(hdr[0] == b'M' && hdr[1] == b'Z') {
                                hdr_mismatch += 1;
                            }
                        }
                    }
                }
                addr = addr.wrapping_add(size);
                if addr == 0 {
                    break;
                }
            }

            CloseHandle(handle);
            [rwx, priv_exec, 2, hdr_mismatch]
        }
    }
}
