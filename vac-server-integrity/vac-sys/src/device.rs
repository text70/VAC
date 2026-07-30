use std::fs;
use std::io;
use crate::{BlockDeviceInfo, DeviceList, PciDeviceInfo};

pub fn enumerate_devices() -> io::Result<DeviceList> {
    let mut devices = DeviceList::default();

    // Block devices from /sys/block
    if let Ok(entries) = fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let size_path = entry.path().join("size");
            let rem_path = entry.path().join("removable");
            let size = fs::read_to_string(&size_path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let removable = fs::read_to_string(&rem_path)
                .ok()
                .map(|s| s.trim() == "1")
                .unwrap_or(false);
            devices.block_devices.push(BlockDeviceInfo {
                name,
                size_sectors: size,
                removable,
            });
        }
    }

    // PCI devices from /sys/bus/pci/devices
    if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
        for entry in entries.flatten() {
            let slot = entry.file_name().to_string_lossy().to_string();
            let vendor = read_sys_attr(&entry.path(), "vendor").unwrap_or_default();
            let device = read_sys_attr(&entry.path(), "device").unwrap_or_default();
            let driver = read_sys_link(&entry.path().join("driver")).unwrap_or_default();
            devices.pci_devices.push(PciDeviceInfo {
                slot,
                vendor,
                device,
                driver,
            });
        }
    }

    Ok(devices)
}

fn read_sys_attr(path: &std::path::Path, attr: &str) -> Option<String> {
    fs::read_to_string(path.join(attr))
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_sys_link(path: &std::path::Path) -> Option<String> {
    fs::read_link(path)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
}
