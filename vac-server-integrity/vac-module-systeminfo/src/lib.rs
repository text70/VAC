use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 1;

pub struct SystemInfoModule;

impl Module for SystemInfoModule {
    fn name(&self) -> &'static str {
        "SystemInfo"
    }

    fn module_id(&self) -> u32 {
        MODULE_ID
    }

    fn scan(&mut self, report: &mut ScanReport) {
        let sys = vac_sys::linux::LinuxSystem::new();

        let info = sys.system_info();

        let buf = &mut report.data;

        // Module header
        buf.write_u32(0); // pad
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(MODULE_ID);
        buf.write_u32(0); // error

        // Timestamps (indices 6-7)
        let boot_time = sys.boot_time().unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        buf.write_u32(boot_time as u32); // boot time low
        buf.write_u32(boot_time as u32 >> 16);
        buf.write_u32(now as u32);

        // OS version info
        buf.write_u32(0x0A000001); // Windows compat: major 10, build placeholder
        buf.write_u32(info.cpu_count);
        buf.write_u32(0); // processor type placeholder

        // Memory
        buf.write_u32((info.total_memory_kb / 1024) as u32);
        buf.write_u32(info.uptime_seconds as u32);

        // CPU info
        let cpu_hash = vac_core::hash::vac_hash(info.cpu_model.as_bytes());
        buf.write_u32(cpu_hash);

        // Architecture
        let arch_hash = vac_core::hash::vac_hash(info.architecture.as_bytes());
        buf.write_u32(arch_hash);

        // Kernel
        let kernel_hash = vac_core::hash::vac_hash(info.kernel_release.as_bytes());
        buf.write_u32(kernel_hash);

        // Hostname
        let host_hash = vac_core::hash::vac_hash(info.hostname.as_bytes());
        buf.write_u32(host_hash);

        // Number of CPUs
        buf.write_u32(info.cpu_count);

        // PID, TID
        buf.write_u32(sys.current_process_id());
        buf.write_u32(sys.current_thread_id());

        // Current exe path
        if let Ok(exe) = sys.current_exe_path() {
            let bytes = exe.as_bytes();
            let len = bytes.len().min(36);
            buf.write_bytes(&bytes[bytes.len() - len..]);
        }

        // Mount count
        let mounts = sys.mounts().unwrap_or_default();
        buf.write_u32(mounts.len() as u32);

        // Process count
        let procs = sys.enumerate_processes().unwrap_or_default();
        buf.write_u32(procs.len() as u32);

        // Loaded libraries count
        let libs = sys.loaded_libraries().unwrap_or_default();
        buf.write_u32(libs.len() as u32);

        // Has debug privilege
        buf.write_u32(if sys.has_debug_privilege() { 1 } else { 0 });

        report.error = ScanError::None;
    }
}
