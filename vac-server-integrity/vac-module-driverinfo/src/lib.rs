use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 5;

pub struct DriverInfoModule;

impl Module for DriverInfoModule {
    fn name(&self) -> &'static str {
        "DriverInfo"
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

        let modules = match sys.loaded_modules() {
            Ok(m) => m,
            Err(_) => {
                report.error = ScanError::SystemCallFailed;
                return;
            }
        };

        buf.write_u32(modules.len() as u32);

        for (i, km) in modules.iter().enumerate() {
            if i >= 256 {
                break;
            }
            let name_hash = vac_core::hash::vac_hash(km.name.as_bytes());
            buf.write_u32(name_hash);
            buf.write_u32(km.size as u32);
            buf.write_u32(km.refcount);
            buf.write_u32(km.dependencies.len() as u32);
        }

        report.error = ScanError::None;
    }
}
