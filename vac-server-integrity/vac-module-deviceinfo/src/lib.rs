use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 4;

pub struct DeviceInfoModule;

impl Module for DeviceInfoModule {
    fn name(&self) -> &'static str {
        "DeviceInfo"
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

        let devices = match sys.device_info() {
            Ok(d) => d,
            Err(_) => {
                report.error = ScanError::SystemCallFailed;
                return;
            }
        };

        buf.write_u32(devices.block_devices.len() as u32);
        buf.write_u32(devices.pci_devices.len() as u32);

        for dev in &devices.block_devices {
            let name_hash = vac_core::hash::vac_hash(dev.name.as_bytes());
            buf.write_u32(name_hash);
            buf.write_u32(dev.size_sectors as u32);
            buf.write_u32(if dev.removable { 1 } else { 0 });
        }

        for dev in &devices.pci_devices {
            let slot_hash = vac_core::hash::vac_hash(dev.slot.as_bytes());
            let vendor_hash = vac_core::hash::vac_hash(dev.vendor.as_bytes());
            let device_hash = vac_core::hash::vac_hash(dev.device.as_bytes());
            buf.write_u32(slot_hash);
            buf.write_u32(vendor_hash);
            buf.write_u32(device_hash);
            let driver_hash = vac_core::hash::vac_hash(dev.driver.as_bytes());
            buf.write_u32(driver_hash);
        }

        report.error = ScanError::None;
    }
}
