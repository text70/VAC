#[cfg(target_os = "windows")]

use std::io;
use crate::{SystemOps, SystemInfoData, KernelModuleInfo, LibraryInfo, MountInfo, DeviceList, ServiceInfo};
use crate::win32_table::*;

pub struct Win32System {
    api: WinApiTable,
}

impl Win32System {
    pub fn new() -> Self {
        Win32System {
            api: resolve_winapi(),
        }
    }

    pub fn from_table(api: WinApiTable) -> Self {
        Win32System { api }
    }

    unsafe fn wide_to_string(&self, wstr: &[u16]) -> String {
        let len = wstr.iter().position(|&c| c == 0).unwrap_or(wstr.len());
        let mut buf = vec![0u8; len * 4];
        let written = (self.api.WideCharToMultiByte.unwrap())(
            65001, 0, wstr.as_ptr(), len as i32,
            buf.as_mut_ptr(), buf.len() as i32,
            std::ptr::null(), std::ptr::null_mut(),
        );
        if written > 0 {
            buf.truncate(written as usize);
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        }
    }

    unsafe fn ansi_to_string(&self, s: &[u8]) -> String {
        let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..len]).to_string()
    }
}

impl SystemOps for Win32System {
    fn current_process_id(&self) -> u32 {
        unsafe { (self.api.GetCurrentProcessId.unwrap())() }
    }

    fn current_thread_id(&self) -> u32 {
        unsafe { (self.api.GetCurrentThreadId.unwrap())() }
    }

    fn current_exe_path(&self) -> Result<String, io::Error> {
        unsafe {
            let mut buf = [0u16; 4096];
            let mut len = buf.len() as u32;
            // Use QueryFullProcessImageNameW (entry 87) with GetCurrentProcess (entry 101)
            let hproc = (self.api.GetCurrentProcess.unwrap())();
            if (self.api.QueryFullProcessImageNameW.unwrap())(hproc, 0, buf.as_mut_ptr(), &mut len) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(self.wide_to_string(&buf))
        }
    }

    fn enumerate_processes(&self) -> Result<Vec<(u32, u32, String)>, io::Error> {
        unsafe {
            let snapshot = (self.api.CreateToolhelp32Snapshot.unwrap())(2, 0); // TH32CS_SNAPPROCESS
            if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }

            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut procs = Vec::new();
            if (self.api.Process32FirstW.unwrap())(snapshot, &mut pe as *mut _ as LPPROCESSENTRY32W) != 0 {
                loop {
                    let name = self.wide_to_string(&pe.szExeFile);
                    procs.push((pe.th32ProcessID, pe.th32ParentProcessID, name));

                    if (self.api.Process32NextW.unwrap())(snapshot, &mut pe as *mut _ as LPPROCESSENTRY32W) == 0 {
                        break;
                    }
                }
            }

            (self.api.CloseHandle.unwrap())(snapshot);
            Ok(procs)
        }
    }

    fn enumerate_process_fds(&self, pid: u32) -> Result<Vec<(u32, String)>, io::Error> {
        // Enumerate handles via NtQuerySystemInformation (SystemHandleInformation = 16)
        let mut buf = vec![0u8; 1024 * 1024];
        let mut ret_len: u32 = 0;
        let mut status = unsafe { (self.api.NtQuerySystemInformation.unwrap())(16, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret_len) };
        if status == 0xC0000004u32 as i32 { // STATUS_INFO_LENGTH_MISMATCH
            buf.resize(ret_len as usize, 0);
            status = unsafe { (self.api.NtQuerySystemInformation.unwrap())(16, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret_len) };
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let handle_count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let mut fds = Vec::new();
        let handle_info_ptr = unsafe { buf.as_ptr().add(8) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO };
        for i in 0..handle_count {
            let handle_info = unsafe { *handle_info_ptr.add(i) };

            if handle_info.UniqueProcessId == pid as u16 {
                fds.push((handle_info.HandleValue as u32, format!("Handle: 0x{:X}", handle_info.HandleValue)));
            }
        }
        Ok(fds)
    }

    fn process_cmdline(&self, pid: u32) -> Result<String, io::Error> {
        unsafe {
            let handle = (self.api.OpenProcess.unwrap())(0x0010, 0, pid);
            if handle.is_null() { return Err(io::Error::last_os_error()); }
            
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let mut ret_len: u32 = 0;
            let status = (self.api.NtQueryInformationProcess.unwrap())(handle, 0, &mut pbi as *mut _ as *mut _, std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut ret_len);
            
            if status != 0 {
                (self.api.CloseHandle.unwrap())(handle);
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            
            // This requires reading PEB + parameters which is architecture-dependent.
            // Simplified for now, just indicating it's not implemented yet.
            (self.api.CloseHandle.unwrap())(handle);
            Ok("Command line not fully implemented".to_string())
        }
    }

    fn read_process_memory(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize, io::Error> {
        unsafe {
            let handle = (self.api.OpenProcess.unwrap())(0x0010 | 0x0020, 0, pid); // PROCESS_VM_READ | PROCESS_VM_WRITE
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut read: usize = 0;
            let ret = (self.api.ReadProcessMemory.unwrap())(
                handle, addr as LPCVOID, buf.as_mut_ptr() as LPVOID, buf.len(), &mut read
            );
            (self.api.CloseHandle.unwrap())(handle);
            if ret == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(read)
            }
        }
    }

    fn system_info(&self) -> SystemInfoData {
        let mut info = SystemInfoData::default();

        unsafe {
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            (self.api.GetSystemInfo.unwrap())(&mut si as *mut _ as LPSYSTEM_INFO);
            info.cpu_count = si.dwNumberOfProcessors;
            info.architecture = match si.wProcessorArchitecture {
                0 => "x86",
                5 => "ARM",
                6 => "IA64",
                9 => "x64",
                12 => "ARM64",
                _ => "unknown",
            }.to_string();

            let mut buf = [0u16; 260];
            let len = (self.api.GetComputerNameExW.unwrap())(
                5, // ComputerNamePhysicalDnsHostname
                buf.as_mut_ptr(), &mut (buf.len() as u32)
            );
            if len != 0 {
                info.hostname = self.wide_to_string(&buf);
            }
        }

        info.os_name = "Windows".to_string();
        info
    }

    fn boot_time(&self) -> Result<u64, io::Error> {
        // Use GetTickCount to approximate boot time
        let ms = unsafe { (self.api.GetTickCount.unwrap())() };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(now - (ms as u64 / 1000))
    }

    fn kernel_range(&self) -> Result<(u64, u64), io::Error> {
        Ok((0xfffff80000000000, 0xffffffffff000000)) // Default Windows kernel range
    }

    fn loaded_modules(&self) -> Result<Vec<KernelModuleInfo>, io::Error> {
        let mut buf = vec![0u8; 1024 * 1024];
        let mut ret_len: u32 = 0;
        let mut status = unsafe { (self.api.NtQuerySystemInformation.unwrap())(11, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret_len) };
        if status == 0xC0000004u32 as i32 { // STATUS_INFO_LENGTH_MISMATCH
            buf.resize(ret_len as usize, 0);
            status = unsafe { (self.api.NtQuerySystemInformation.unwrap())(11, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret_len) };
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let module_count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let mut modules = Vec::new();
        let module_info_ptr = unsafe { buf.as_ptr().add(8) as *const SYSTEM_MODULE_ENTRY };
        for i in 0..module_count {
            let mod_info = unsafe { *module_info_ptr.add(i) };
            let name_ptr = mod_info.ImageName.as_ptr();
            let name = unsafe { std::ffi::CStr::from_ptr(name_ptr as *const i8).to_string_lossy().to_string() };
            modules.push(KernelModuleInfo {
                name,
                size: mod_info.ImageSize as u64,
                refcount: mod_info.LoadCount as u32,
                dependencies: Vec::new(),
                address: mod_info.ImageBase as u64,
            });
        }
        Ok(modules)
    }

    fn loaded_libraries(&self) -> Result<Vec<LibraryInfo>, io::Error> {
        unsafe {
            let pid = (self.api.GetCurrentProcessId.unwrap())();
            let handle = (self.api.OpenProcess.unwrap())(0x0400 | 0x0010, 0, pid); // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut needed: u32 = 0;
            if (self.api.EnumProcessModules.unwrap())(handle, std::ptr::null_mut(), 0, &mut needed) == 0 {
                (self.api.CloseHandle.unwrap())(handle);
                return Err(io::Error::last_os_error());
            }

            let count = (needed as usize) / std::mem::size_of::<HMODULE>();
            let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); count];
            if (self.api.EnumProcessModules.unwrap())(
                handle, modules.as_mut_ptr(), needed, &mut needed
            ) == 0 {
                (self.api.CloseHandle.unwrap())(handle);
                return Err(io::Error::last_os_error());
            }

            let mut libs = Vec::new();
            for &hmod in &modules {
                if hmod.is_null() { continue; }

                let mut name_buf = [0u16; 260];
                let name_len = (self.api.GetModuleBaseNameW.unwrap())(
                    handle, hmod, name_buf.as_mut_ptr(), name_buf.len() as u32
                );
                let name = if name_len > 0 {
                    self.wide_to_string(&name_buf)
                } else {
                    String::new()
                };

                let mut path_buf = [0u16; 260];
                let path_len = (self.api.GetModuleFileNameExW.unwrap())(
                    handle, hmod, path_buf.as_mut_ptr(), path_buf.len() as u32
                );
                let path = if path_len > 0 {
                    self.wide_to_string(&path_buf)
                } else {
                    String::new()
                };

                libs.push(LibraryInfo {
                    name,
                    path,
                    base_address: hmod as u64,
                    size: 0,
                });
            }

            (self.api.CloseHandle.unwrap())(handle);
            Ok(libs)
        }
    }

    fn mounts(&self) -> Result<Vec<MountInfo>, io::Error> {
        unsafe {
            let mut drives = vec![0u16; 256];
            let len = (self.api.GetLogicalDriveStringsW.unwrap())(drives.len() as u32, drives.as_mut_ptr());
            if len == 0 {
                return Err(io::Error::last_os_error());
            }

            let mut mounts = Vec::new();
            let mut i = 0;
            while i < len as usize && drives[i] != 0 {
                let drive = &drives[i..];
                let name = self.wide_to_string(drive);
                let drive_type = (self.api.GetDriveTypeW.unwrap())(drive.as_ptr());
                let fstype = match drive_type {
                    2 => "REMOVABLE",
                    3 => "FIXED",
                    4 => "REMOTE",
                    5 => "CDROM",
                    6 => "RAMDISK",
                    _ => "UNKNOWN",
                }.to_string();
                mounts.push(MountInfo {
                    device: name.clone(),
                    mount_point: name,
                    fstype,
                    options: String::new(),
                });
                while i < len as usize && drives[i] != 0 { i += 1; }
                i += 1;
            }

            Ok(mounts)
        }
    }

    fn device_info(&self) -> Result<DeviceList, io::Error> {
        unsafe {
            let hdev = (self.api.SetupDiGetClassDevsA.unwrap())(
                std::ptr::null(), // All classes
                std::ptr::null(),
                std::ptr::null_mut(),
                0x00000002, // DIGCF_ALLCLASSES
            );
            if hdev.is_null() || hdev == INVALID_HANDLE_VALUE {
                return Ok(DeviceList::default());
            }

            let mut list = DeviceList::default();
            let mut index: u32 = 0;
            loop {
                let mut devinfo: SP_DEVINFO_DATA = std::mem::zeroed();
                devinfo.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

                if (self.api.SetupDiEnumDeviceInfo.unwrap())(hdev, index, &mut devinfo as *mut _ as PSP_DEVINFO_DATA) == 0 {
                    break;
                }

                let mut buf = [0u8; 256];
                let mut data_type: u32 = 0;
                let mut size: u32 = 0;
                // SPDRP_HARDWAREID = 0x00000001
                if (self.api.SetupDiGetDeviceRegistryPropertyA.unwrap())(
                    hdev, &mut devinfo as *mut _ as PSP_DEVINFO_DATA,
                    0x00000001, &mut data_type, buf.as_mut_ptr(), buf.len() as u32, &mut size
                ) != 0 {
                    let hwid = self.ansi_to_string(&buf);
                    if hwid.contains("PCI") || hwid.contains("VEN_") {
                        list.pci_devices.push(crate::PciDeviceInfo {
                            slot: index.to_string(),
                            vendor: hwid.clone(),
                            device: hwid,
                            driver: String::new(),
                        });
                    }
                }

                index += 1;
            }

            (self.api.SetupDiDestroyDeviceInfoList.unwrap())(hdev);
            Ok(list)
        }
    }

    fn services(&self) -> Result<Vec<ServiceInfo>, io::Error> {
        unsafe {
            let scm = (self.api.OpenSCManagerA.unwrap())(
                std::ptr::null(), std::ptr::null(), 0x0002 | 0x0004 // SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
            );
            if scm.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut buf = vec![0u8; 65536];
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;

            if (self.api.EnumServicesStatusA.unwrap())(
                scm, 3, 0x00000030, // SERVICE_WIN32 | SERVICE_DRIVER
                buf.as_mut_ptr() as LPENUM_SERVICE_STATUSA, buf.len() as u32,
                &mut needed, &mut returned, std::ptr::null_mut()
            ) == 0 {
                (self.api.CloseServiceHandle.unwrap())(scm);
                return Err(io::Error::last_os_error());
            }

            let entry_size = std::mem::size_of::<ENUM_SERVICE_STATUSA>();
            let mut services = Vec::new();
            for i in 0..returned as usize {
                let off = i * entry_size;
                if off + entry_size > buf.len() { break; }
                let entry = &buf[off..off + entry_size];
                // ENUM_SERVICE_STATUSA has: lpServiceName (4), lpDisplayName (4), ServiceStatus (12)
                let name_ptr = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as *const u8;
                let name = if !name_ptr.is_null() {
                    let mut name_bytes = Vec::new();
                    let mut p = name_ptr;
                    loop {
                        let c = *p;
                        if c == 0 { break; }
                        name_bytes.push(c);
                        p = p.offset(1);
                    }
                    String::from_utf8_lossy(&name_bytes).to_string()
                } else {
                    String::new()
                };

                let state_code = u32::from_le_bytes(entry[16..20].try_into().unwrap()); // dwCurrentState
                let state = match state_code {
                    1 => "STOPPED",
                    2 => "START_PENDING",
                    3 => "STOP_PENDING",
                    4 => "RUNNING",
                    5 => "CONTINUE_PENDING",
                    6 => "PAUSE_PENDING",
                    7 => "PAUSED",
                    _ => "UNKNOWN",
                }.to_string();

                services.push(ServiceInfo {
                    name,
                    state,
                    enabled: false, // Would need QueryServiceConfig to determine
                });
            }

            (self.api.CloseServiceHandle.unwrap())(scm);
            Ok(services)
        }
    }

    fn has_debug_privilege(&self) -> bool {
        unsafe {
            let token: HANDLE = std::ptr::null_mut();
            let process = (self.api.GetCurrentProcess.unwrap())();
            if (self.api.OpenProcessToken.unwrap())(process, 0x0008, &token as *const _ as PHANDLE) == 0 {
                return false;
            }
            // TOKEN_QUERY = 0x0008
            let mut buf = [0u8; 256];
            let mut len: u32 = 0;
            let ret = (self.api.GetTokenInformation.unwrap())(
                token, 20, // TokenElevation
                buf.as_mut_ptr() as LPVOID, buf.len() as u32, &mut len
            );
            (self.api.CloseHandle.unwrap())(token);
            ret != 0 && len >= 4 && u32::from_le_bytes(buf[..4].try_into().unwrap()) != 0
        }
    }

    fn mmap_anon(&self, size: usize) -> Result<*mut u8, io::Error> {
        unsafe {
            let addr = (self.api.VirtualAlloc.unwrap())(
                std::ptr::null_mut(), size, 0x1000, 0x04 // MEM_COMMIT | PAGE_READWRITE
            );
            if addr.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(addr as *mut u8)
            }
        }
    }

    fn munmap(&self, addr: *mut u8, size: usize) -> Result<(), io::Error> {
        unsafe {
            let ret = (self.api.VirtualFree.unwrap())(addr as LPVOID, size, 0x8000); // MEM_RELEASE
            if ret == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn hostname(&self) -> Result<String, io::Error> {
        unsafe {
            let mut buf = [0u16; 260];
            let mut len = buf.len() as u32;
            if (self.api.GetComputerNameExW.unwrap())(
                5, // ComputerNamePhysicalDnsHostname
                buf.as_mut_ptr(), &mut len
            ) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(self.wide_to_string(&buf))
        }
    }

    fn hardware_presence(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = [0u8; 32];
        // Simple TPM presence check (no crypto proof; kernel module not applicable on Windows yet)
        let output = std::process::Command::new("powershell")
            .args(["-Command", "if (Get-Tpm).TpmPresent { exit 0 } else { exit 1 }"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        buf[0] = if output { 2 } else { 1 };
        Ok(buf.to_vec())
    }
}

// Win32 struct definitions
const INVALID_HANDLE_VALUE: HANDLE = (-1isize) as *mut _;

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}

#[allow(unused)]
#[repr(C)]
struct MODULEENTRY32W {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: *mut u8,
    modBaseSize: u32,
    hModule: HMODULE,
    szModule: [u16; 256],
    szExePath: [u16; 260],
}

#[repr(C)]
struct SYSTEM_INFO {
    wProcessorArchitecture: u16,
    wReserved: u16,
    dwPageSize: u32,
    lpMinimumApplicationAddress: *mut std::ffi::c_void,
    lpMaximumApplicationAddress: *mut std::ffi::c_void,
    dwActiveProcessorMask: usize,
    dwNumberOfProcessors: u32,
    dwProcessorType: u32,
    dwAllocationGranularity: u32,
    wProcessorLevel: u16,
    wProcessorRevision: u16,
}

#[repr(C)]
struct SP_DEVINFO_DATA {
    cbSize: u32,
    classGuid: [u8; 16],
    devInst: u32,
    reserved: usize,
}

#[repr(C)]
struct ENUM_SERVICE_STATUSA {
    lpServiceName: *const u8,
    lpDisplayName: *const u8,
    serviceStatus: SERVICE_STATUS,
}

#[repr(C)]
struct SERVICE_STATUS {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
}

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    ExitStatus: u32,
    PebBaseAddress: *mut std::ffi::c_void,
    AffinityMask: usize,
    BasePriority: u32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    UniqueProcessId: u16,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u8,
    HandleAttributes: u8,
    HandleValue: u16,
    Object: *mut std::ffi::c_void,
    GrantedAccess: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SYSTEM_MODULE_ENTRY {
    Reserved: [usize; 2],
    ImageBase: *mut std::ffi::c_void,
    ImageSize: u32,
    Flags: u32,
    Index: u16,
    LoadCount: u16,
    ModuleNameOffset: u16,
    Reserved1: u16,
    ImageName: [u8; 256],
}


