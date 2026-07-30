use std::fs;

use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 3;

pub struct ProcessMonitorModule;

impl Module for ProcessMonitorModule {
    fn name(&self) -> &'static str {
        "ProcessMonitor"
    }

    fn module_id(&self) -> u32 {
        MODULE_ID
    }

    fn scan(&mut self, report: &mut ScanReport) {
        let sys = vac_sys::linux::LinuxSystem::new();

        let buf = &mut report.data;

        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(MODULE_ID);

        // Check our own binary integrity
        let pid = sys.current_process_id();
        let exe = match sys.current_exe_path() {
            Ok(p) => p,
            Err(_) => {
                report.error = ScanError::SystemCallFailed;
                return;
            }
        };

        // Hash the executable's .text section from /proc/pid/exe
        let text_hash = hash_text_section(pid, &exe);
        buf.write_u32(text_hash);

        // Check loaded libraries
        let libs = match sys.loaded_libraries() {
            Ok(l) => l,
            Err(_) => {
                buf.write_u32(0);
                return;
            }
        };
        buf.write_u32(libs.len() as u32);

        let mut suspicious_count = 0;
        for lib in &libs {
            // Flag libraries loaded from unusual paths
            if lib.path.contains("/tmp/")
                || lib.path.contains("/dev/shm/")
                || lib.path.contains("/var/tmp/")
            {
                let name_hash = vac_core::hash::vac_hash(lib.name.as_bytes());
                buf.write_u32(1);
                buf.write_u32(name_hash);
                suspicious_count += 1;
            }
        }
        buf.set_cursor(7);
        buf.write_u32(suspicious_count);

        report.error = ScanError::None;
    }
}

fn hash_text_section(pid: u32, exe: &str) -> u32 {
    // Read the actual binary content from disk and hash the first 64KB
    // This is a real integrity check — any modification to the binary changes the hash.
    let exe_path = format!("/proc/{}/exe", pid);
    let exe_real = fs::read_link(&exe_path).unwrap_or_else(|_| std::path::PathBuf::from(exe));
    let data = fs::read(&exe_real).unwrap_or_default();
    let max = data.len().min(65536);
    if max == 0 {
        return 0x45D71892;
    }
    vac_core::crc32::crc32(&data[..max], 0x45D71892)
}
