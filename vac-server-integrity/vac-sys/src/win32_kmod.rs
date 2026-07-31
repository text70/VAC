#![allow(non_camel_case_types, dead_code, non_snake_case)]
// Rust client for \\.\Vac (Windows kernel driver).
// Mirrors vac-sys/src/kmod/mod.rs interface using Win32 API.
// This file is compiled only under #[cfg(target_os = "windows")] (see lib.rs).

use std::io;
use std::ptr;

use crate::win32_table::*;

// CTL_CODE(0x22, function, 0, 0)
const fn ctl_code(function: u32) -> u32 {
    (0x22u32 << 16) | (function << 2)
}

pub const VAC_IOCTL_FILL: u32 = ctl_code(0x800);
pub const VAC_IOCTL_PROC_LIST: u32 = ctl_code(0x801);
pub const VAC_IOCTL_READ_MEM: u32 = ctl_code(0x802);
pub const VAC_IOCTL_PROC_NAME: u32 = ctl_code(0x803);

pub const VAC_MAX_PROCS: usize = 2048;
pub const VAC_MAX_COMM: usize = 16;
pub const VAC_READ_SIZE: usize = 256;

pub const VAC_CAP_PROC_LIST: u32 = 1 << 0;
pub const VAC_CAP_READ_MEM: u32 = 1 << 1;
pub const VAC_CAP_PROC_NAME: u32 = 1 << 2;
pub const VAC_CAP_PROTECT: u32 = 1 << 3;

#[repr(C, packed)]
pub struct VacProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; VAC_MAX_COMM],
}

#[repr(C, packed)]
pub struct VacProcList {
    pub count: u32,
    pub entries: [VacProcEntry; VAC_MAX_PROCS],
}

#[repr(C, packed)]
pub struct VacReadMem {
    pub pid: u32,
    pub address: u64,
    pub size: u32,
    pub data: [u8; VAC_READ_SIZE],
    pub bytes_read: u32,
}

#[repr(C, packed)]
pub struct VacProcName {
    pub pid: u32,
    pub comm: [u8; VAC_MAX_COMM],
}

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: HANDLE = (-1isize) as *mut _;

pub struct Win32Kmod<'a> {
    api: &'a WinApiTable,
    handle: HANDLE,
}

impl<'a> Win32Kmod<'a> {
    pub fn open(api: &'a WinApiTable) -> Option<Self> {
        unsafe {
            let path: Vec<u16> = "\\\\.\\Vac\0".encode_utf16().collect();
            let handle = (api.CreateFileW.unwrap())(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,                          // dwShareMode
                ptr::null_mut(),            // lpSecurityAttributes
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),            // hTemplateFile
            );
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return None;
            }
            Some(Self { api, handle })
        }
    }

    pub fn is_loaded() -> bool {
        // Try to open; we use a trick: call open and drop immediately
        // Since we need an API table, this is a convenience — caller should
        // use Self::open().is_some() instead.
        false
    }

    pub fn capabilities(&self) -> io::Result<u32> {
        let mut caps: u32 = 0;
        let mut returned: u32 = 0;
        let ret = unsafe {
            (self.api.DeviceIoControl.unwrap())(
                self.handle,
                VAC_IOCTL_FILL,
                ptr::null_mut(),
                0,
                &mut caps as *mut u32 as LPVOID,
                std::mem::size_of::<u32>() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(caps)
        }
    }

    pub fn proc_list(&self) -> io::Result<Vec<(u32, u32, String)>> {
        let mut list: VacProcList = unsafe { std::mem::zeroed() };
        let mut returned: u32 = 0;
        let out_size = std::mem::size_of::<VacProcList>() as u32;
        let ret = unsafe {
            (self.api.DeviceIoControl.unwrap())(
                self.handle,
                VAC_IOCTL_PROC_LIST,
                ptr::null_mut(),
                0,
                &mut list as *mut VacProcList as LPVOID,
                out_size,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
        let count = list.count as usize;
        let mut result = Vec::with_capacity(count);
        for i in 0..count.min(VAC_MAX_PROCS) {
            let comm = &list.entries[i].comm;
            let name = String::from_utf8_lossy(comm)
                .trim_end_matches('\0')
                .trim_end_matches('\x00')
                .to_string();
            result.push((list.entries[i].pid, list.entries[i].ppid, name));
        }
        Ok(result)
    }

    pub fn read_mem(&self, pid: u32, address: u64, buf: &mut [u8]) -> io::Result<usize> {
        let size = buf.len().min(VAC_READ_SIZE);
        let mut rm: VacReadMem = unsafe { std::mem::zeroed() };
        rm.pid = pid;
        rm.address = address;
        rm.size = size as u32;

        let mut returned: u32 = 0;
        let io_size = std::mem::size_of::<VacReadMem>() as u32;
        let ret = unsafe {
            (self.api.DeviceIoControl.unwrap())(
                self.handle,
                VAC_IOCTL_READ_MEM,
                &mut rm as *mut VacReadMem as LPVOID,
                io_size,
                &mut rm as *mut VacReadMem as LPVOID,
                io_size,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
        let n = rm.bytes_read as usize;
        if n > 0 && n <= buf.len() {
            buf[..n].copy_from_slice(&rm.data[..n]);
        }
        Ok(n)
    }

    pub fn proc_name(&self, pid: u32) -> io::Result<String> {
        let mut pn: VacProcName = unsafe { std::mem::zeroed() };
        pn.pid = pid;

        let mut returned: u32 = 0;
        let io_size = std::mem::size_of::<VacProcName>() as u32;
        let ret = unsafe {
            (self.api.DeviceIoControl.unwrap())(
                self.handle,
                VAC_IOCTL_PROC_NAME,
                &mut pn as *mut VacProcName as LPVOID,
                io_size,
                &mut pn as *mut VacProcName as LPVOID,
                io_size,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ret == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::from_utf8_lossy(&pn.comm)
            .trim_end_matches('\0')
            .trim_end_matches('\x00')
            .to_string())
    }
}

impl<'a> Drop for Win32Kmod<'a> {
    fn drop(&mut self) {
        unsafe {
            (self.api.CloseHandle.unwrap())(self.handle);
        }
    }
}