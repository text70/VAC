use std::fs;
use std::io::{self, BufRead};
use crate::{
    SystemOps, SystemInfoData, KernelModuleInfo, LibraryInfo,
    MountInfo, DeviceList, ServiceInfo,
};

pub struct LinuxSystem;

impl LinuxSystem {
    pub fn new() -> Self {
        Self
    }

    fn read_first_line(path: &str) -> io::Result<String> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        reader.lines().next().unwrap_or_else(|| Ok(String::new()))
    }
}

impl SystemOps for LinuxSystem {
    fn current_process_id(&self) -> u32 {
        crate::process::current_process_id()
    }

    fn current_thread_id(&self) -> u32 {
        crate::process::current_thread_id()
    }

    fn current_exe_path(&self) -> Result<String, io::Error> {
        crate::process::current_exe_path()
    }

    fn enumerate_processes(&self) -> Result<Vec<(u32, u32, String)>, io::Error> {
        crate::process::enumerate_processes()
    }

    fn enumerate_process_fds(&self, pid: u32) -> Result<Vec<(u32, String)>, io::Error> {
        crate::process::enumerate_process_fds(pid)
    }

    fn process_cmdline(&self, pid: u32) -> Result<String, io::Error> {
        crate::process::process_cmdline(pid)
    }

    fn read_process_memory(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, io::Error> {
        crate::process::read_process_memory(pid, addr, buf)
    }

    fn system_info(&self) -> SystemInfoData {
        let mut info = SystemInfoData::default();

        if let Ok(content) = fs::read_to_string("/proc/version") {
            info.kernel_release = content.trim().to_string();
        }

        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("model name\t: ") {
                    info.cpu_model = val.trim().to_string();
                    break;
                }
            }
        }

        info.cpu_count = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);

        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("MemTotal:") {
                    if let Ok(kb) = val.trim().trim_end_matches(" kB").trim().parse::<u64>() {
                        info.total_memory_kb = kb;
                    }
                    break;
                }
            }
        }

        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(uptime_str) = content.split_whitespace().next() {
                if let Ok(secs) = uptime_str.parse::<f64>() {
                    info.uptime_seconds = secs as u64;
                }
            }
        }

        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/hostname") {
            info.hostname = content.trim().to_string();
        }

        info.architecture = std::env::consts::ARCH.to_string();
        info.os_name = std::env::consts::OS.to_string();

        info
    }

    fn boot_time(&self) -> Result<u64, io::Error> {
        let content = fs::read_to_string("/proc/stat")?;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("btime ") {
                return val.trim().parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "btime not found in /proc/stat"))
    }

    fn kernel_range(&self) -> Result<(u64, u64), io::Error> {
        let content = fs::read_to_string("/proc/kallsyms")?;
        let mut start = u64::MAX;
        let mut end = 0;
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                    if addr > 0 && addr < 0xffffffffffffffff {
                        start = start.min(addr);
                        end = end.max(addr);
                    }
                }
            }
        }
        if start == u64::MAX {
            Err(io::Error::new(io::ErrorKind::NotFound, "no kernel symbols"))
        } else {
            Ok((start, end))
        }
    }

    fn loaded_modules(&self) -> Result<Vec<KernelModuleInfo>, io::Error> {
        crate::module::loaded_kernel_modules()
    }

    fn loaded_libraries(&self) -> Result<Vec<LibraryInfo>, io::Error> {
        crate::memory::loaded_libraries()
    }

    fn mounts(&self) -> Result<Vec<MountInfo>, io::Error> {
        crate::filesystem::mounts()
    }

    fn device_info(&self) -> Result<DeviceList, io::Error> {
        crate::device::enumerate_devices()
    }

    fn services(&self) -> Result<Vec<ServiceInfo>, io::Error> {
        // Try systemd first, fall back to sysv
        crate::service::list_systemd_services()
            .or_else(|_| crate::service::list_sysv_services())
    }

    fn has_debug_privilege(&self) -> bool {
        // Check if we have CAP_SYS_PTRACE
        let content = match fs::read_to_string("/proc/self/status") {
            Ok(c) => c,
            Err(_) => return false,
        };
        for line in content.lines() {
            if line.starts_with("CapPrm:") || line.starts_with("CapEff:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(mask) = u64::from_str_radix(val.trim(), 16) {
                        // CAP_SYS_PTRACE = bit 19
                        return (mask & (1 << 19)) != 0;
                    }
                }
            }
        }
        false
    }

    fn mmap_anon(&self, size: usize) -> Result<*mut u8, io::Error> {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(addr as *mut u8)
        }
    }

    fn munmap(&self, addr: *mut u8, size: usize) -> Result<(), io::Error> {
        let ret = unsafe { libc::munmap(addr as *mut libc::c_void, size) };
        if ret != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn hostname(&self) -> Result<String, io::Error> {
        Self::read_first_line("/proc/sys/kernel/hostname").map(|s| s.trim().to_string())
    }

    fn kernel_module_loaded(&self) -> bool {
        crate::kmod::VacKmod::is_loaded()
    }

    fn kernel_proc_list(&self) -> Result<Vec<(u32, u32, String)>, io::Error> {
        if let Some(kmod) = crate::kmod::VacKmod::open() {
            kmod.proc_list()
        } else {
            self.enumerate_processes()
        }
    }

    fn kernel_read_mem(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, io::Error> {
        if let Some(kmod) = crate::kmod::VacKmod::open() {
            kmod.read_mem(pid, addr, buf)
        } else {
            self.read_process_memory(pid, addr, buf)
        }
    }

    fn hardware_presence(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = [0u8; 32];
        if crate::kmod::VacKmod::is_loaded() {
            buf[0] = 3; // kernel module present
        } else if std::path::Path::new("/dev/tpm0").exists() {
            buf[0] = 2; // TPM present, no kernel module
        } else {
            buf[0] = 1; // no hardware trust anchor
        }
        Ok(buf.to_vec())
    }
}
