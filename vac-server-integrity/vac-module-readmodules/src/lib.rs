use sha2::{Digest, Sha256};
use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 6;

pub struct ReadModulesModule;

impl Module for ReadModulesModule {
    fn name(&self) -> &'static str {
        "ReadModules"
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

        let libs = match sys.loaded_libraries() {
            Ok(l) => l,
            Err(_) => {
                report.error = ScanError::SystemCallFailed;
                return;
            }
        };

        buf.write_u32(libs.len() as u32);

        // Sort by base address for determinism
        let mut sorted = libs.clone();
        sorted.sort_by_key(|l| l.base_address);

        for (i, lib) in sorted.iter().enumerate() {
            if i >= 200 {
                break;
            }
            let name_hash = vac_core::hash::vac_hash(lib.name.as_bytes());
            let path_hash = vac_core::hash::vac_hash(lib.path.as_bytes());
            buf.write_u32(name_hash);
            buf.write_u32(path_hash);
            buf.write_u32(lib.base_address as u32);
            buf.write_u32(lib.size as u32);

            // SHA-256 of the .so file (first 8 bytes as u32 pair)
            let mut hasher = Sha256::new();
            if let Ok(content) = std::fs::read(&lib.path) {
                hasher.update(&content);
                let result = hasher.finalize();
                buf.write_bytes(&result[..8]);
            } else {
                buf.write_u32(0);
                buf.write_u32(0);
            }
        }

        report.error = ScanError::None;
    }
}
