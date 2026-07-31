#[cfg(not(target_os = "windows"))]
pub mod process;
#[cfg(not(target_os = "windows"))]
pub mod filesystem;
#[cfg(not(target_os = "windows"))]
pub mod module;
#[cfg(not(target_os = "windows"))]
pub mod device;
#[cfg(not(target_os = "windows"))]
pub mod service;
#[cfg(not(target_os = "windows"))]
pub mod memory;
#[cfg(not(target_os = "windows"))]
pub mod linux;
#[cfg(not(target_os = "windows"))]
pub mod kmod;
pub mod win32_table;
#[cfg(target_os = "windows")]
pub mod win32;
#[cfg(target_os = "windows")]
pub mod win32_kmod;

pub trait SystemOps {
    fn current_process_id(&self) -> u32;
    fn current_thread_id(&self) -> u32;
    fn current_exe_path(&self) -> Result<String, std::io::Error>;
    fn enumerate_processes(&self) -> Result<Vec<(u32, u32, String)>, std::io::Error>;
    fn enumerate_process_fds(&self, pid: u32) -> Result<Vec<(u32, String)>, std::io::Error>;
    fn process_cmdline(&self, pid: u32) -> Result<String, std::io::Error>;
    fn read_process_memory(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, std::io::Error>;
    fn system_info(&self) -> SystemInfoData;
    fn boot_time(&self) -> Result<u64, std::io::Error>;
    fn kernel_range(&self) -> Result<(u64, u64), std::io::Error>;
    fn loaded_modules(&self) -> Result<Vec<KernelModuleInfo>, std::io::Error>;
    fn loaded_libraries(&self) -> Result<Vec<LibraryInfo>, std::io::Error>;
    fn mounts(&self) -> Result<Vec<MountInfo>, std::io::Error>;
    fn device_info(&self) -> Result<DeviceList, std::io::Error>;
    fn services(&self) -> Result<Vec<ServiceInfo>, std::io::Error>;
    fn has_debug_privilege(&self) -> bool;
    fn mmap_anon(&self, size: usize) -> Result<*mut u8, std::io::Error>;
    fn munmap(&self, addr: *mut u8, size: usize) -> Result<(), std::io::Error>;
    fn hostname(&self) -> Result<String, std::io::Error>;

    /// Returns true if the VAC kernel module is loaded.
    /// Default: false (no kernel driver).
    fn kernel_module_loaded(&self) -> bool {
        false
    }

    /// Enumerate processes via the kernel module (ring-0 trusted path).
    /// Default: falls back to user-mode enumerate_processes().
    fn kernel_proc_list(&self) -> Result<Vec<(u32, u32, String)>, std::io::Error> {
        self.enumerate_processes()
    }

    /// Read process memory via the kernel module (ring-0 trusted path).
    /// Default: falls back to user-mode read_process_memory().
    fn kernel_read_mem(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read_process_memory(pid, addr, buf)
    }

    /// Returns a 32-byte hardware presence indicator (replaces old TPM attestation).
    /// First byte = 1 if a hardware trust anchor (TPM, kernel module) is present, 0 otherwise.
    fn hardware_presence(&self) -> Result<Vec<u8>, std::io::Error>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfoData {
    pub kernel_release: String,
    pub kernel_version: String,
    pub hostname: String,
    pub os_name: String,
    pub cpu_model: String,
    pub cpu_count: u32,
    pub total_memory_kb: u64,
    pub uptime_seconds: u64,
    pub architecture: String,
}

#[derive(Debug, Clone)]
pub struct KernelModuleInfo {
    pub name: String,
    pub size: u64,
    pub refcount: u32,
    pub dependencies: Vec<String>,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct LibraryInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
    pub options: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceList {
    pub block_devices: Vec<BlockDeviceInfo>,
    pub pci_devices: Vec<PciDeviceInfo>,
}

#[derive(Debug, Clone)]
pub struct BlockDeviceInfo {
    pub name: String,
    pub size_sectors: u64,
    pub removable: bool,
}

#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    pub slot: String,
    pub vendor: String,
    pub device: String,
    pub driver: String,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub state: String,
    pub enabled: bool,
}
