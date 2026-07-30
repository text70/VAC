use vac_core::buffer::DataBuffer;
use vac_sys::SystemOps;

pub trait ClientScanModule {
    fn name(&self) -> &'static str;
    fn module_id(&self) -> u32;
    fn scan(&mut self, sys: &dyn SystemOps, report: &mut DataBuffer);
}

pub fn run_module(
    module_id: u32,
    sys: &dyn SystemOps,
    report: &mut DataBuffer,
) {
    match module_id {
        1 => process_scan(sys, report),
        2 => libraries_scan(sys, report),
        3 => debugger_scan(report),
        4 => assemblies_scan(report),
        5 => environment_scan(report),
        6 => cheats_scan(sys, report),
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
    
    // Write hardware presence data (remaining dwords 7-12)
    for chunk in presence.chunks(4).skip(0).take(6) {
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

fn debugger_scan(buf: &mut DataBuffer) {
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

    buf.write_u32(flags);
    buf.write_u32(tracer);
    buf.write_u32(suspicious_maps.len() as u32);
    pad_to(buf, 32);
}

fn assemblies_scan(buf: &mut DataBuffer) {
    let mut flags = 0u32;

    let target_assemblies = [
        "Assembly-CSharp.dll",
        "Assembly-CSharp-firstpass.dll",
        "Facepunch.Console.dll",
        "Facepunch.Network.dll",
        "Facepunch.Unity.dll",
        "UnityEngine.dll",
        "UnityEngine.CoreModule.dll",
    ];

    let libs = std::fs::read_dir("/proc/self/map_files").ok();
    let found_files: Vec<String> = if let Some(entries) = libs {
        entries.filter_map(|e| e.ok()).filter_map(|e| {
            let path = e.path();
            if let Ok(target) = std::fs::read_link(&path) {
                let name = target.file_name()?.to_str()?.to_string();
                Some(name)
            } else {
                None
            }
        }).collect()
    } else {
        Vec::new()
    };

    for target in &target_assemblies {
        let found = found_files.iter().any(|f| f.contains(target));
        if !found {
            flags |= 1;
        }
    }

    buf.write_u32(flags);

    let mut bad_count = 0u32;
    for f in &found_files {
        let f_lower = f.to_lowercase();
        if f_lower.contains("harmony") || f_lower.contains("inject")
            || f_lower.contains("loader") || f_lower.contains("cheat")
        {
            bad_count += 1;
        }
    }
    buf.write_u32(bad_count);
    pad_to(buf, 32);
}

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
            _ => {}
        }
    }

    buf.write_u32(flags);
    pad_to(buf, 16);
}

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
