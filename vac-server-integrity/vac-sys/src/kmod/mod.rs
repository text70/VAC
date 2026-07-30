use std::io;

pub const VAC_IOC_MAGIC: u8 = b'V';
pub const VAC_MAX_PROCS: usize = 2048;
pub const VAC_MAX_COMM: usize = 16;
pub const VAC_READ_SIZE: usize = 256;

pub const VAC_CAP_PROC_LIST: u32 = 1 << 0;
pub const VAC_CAP_READ_MEM: u32 = 1 << 1;
pub const VAC_CAP_PROC_NAME: u32 = 1 << 2;
pub const VAC_CAP_PROTECT: u32 = 1 << 3;

const fn _io(magic: u8, nr: u8) -> u64 {
    ((magic as u64) << 8) | (nr as u64)
}

const fn _ior(magic: u8, nr: u8, size: u16) -> u64 {
    (2u64 << 30) | ((size as u64) << 16) | ((magic as u64) << 8) | (nr as u64)
}

const fn _iowr(magic: u8, nr: u8, size: u16) -> u64 {
    (3u64 << 30) | ((size as u64) << 16) | ((magic as u64) << 8) | (nr as u64)
}

pub const VAC_IOCTL_FILL: u64 = _ior(VAC_IOC_MAGIC, 0, 4);

/*
 * vac_proc_list (49156 bytes) exceeds the 14-bit size field in _IOR,
 * so the kernel C header uses _IO (no size encoding) and the handler
 * manages copy_to_user manually.  Rust side follows the same IOCTL number.
 */
pub const VAC_IOCTL_PROC_LIST: u64 = _io(VAC_IOC_MAGIC, 1);

pub const VAC_IOCTL_READ_MEM: u64 = _iowr(
    VAC_IOC_MAGIC,
    2,
    std::mem::size_of::<VacReadMem>() as u16,
);

pub const VAC_IOCTL_PROC_NAME: u64 = _iowr(
    VAC_IOC_MAGIC,
    3,
    std::mem::size_of::<VacProcName>() as u16,
);

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

pub struct VacKmod {
    fd: std::os::unix::io::RawFd,
}

impl VacKmod {
    pub fn open() -> Option<Self> {
        let fd = unsafe {
            libc::open(
                "/dev/vac\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR,
            )
        };
        if fd < 0 {
            return None;
        }
        Some(Self { fd })
    }

    pub fn is_loaded() -> bool {
        Self::open().is_some()
    }

    pub fn capabilities(&self) -> io::Result<u32> {
        let mut caps: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, VAC_IOCTL_FILL, &mut caps as *mut u32) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(caps)
        }
    }

    pub fn proc_list(&self) -> io::Result<Vec<(u32, u32, String)>> {
        let mut list: VacProcList = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                VAC_IOCTL_PROC_LIST as _,
                &mut list as *mut VacProcList,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = list.count as usize;
        let mut result = Vec::with_capacity(count);
        for i in 0..count.min(VAC_MAX_PROCS) {
            let name = String::from_utf8_lossy(&list.entries[i].comm)
                .trim_end_matches('\0')
                .to_string();
            result.push((list.entries[i].pid, list.entries[i].ppid, name));
        }
        Ok(result)
    }

    pub fn read_mem(&self, pid: u32, address: u64, buf: &mut [u8]) -> io::Result<usize> {
        let size = buf.len().min(VAC_READ_SIZE);
        let mut r: VacReadMem = unsafe { std::mem::zeroed() };
        r.pid = pid;
        r.address = address;
        r.size = size as u32;

        let ret = unsafe {
            libc::ioctl(
                self.fd,
                VAC_IOCTL_READ_MEM as _,
                &mut r as *mut VacReadMem,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = r.bytes_read as usize;
        buf[..n].copy_from_slice(&r.data[..n]);
        Ok(n)
    }

    pub fn proc_name(&self, pid: u32) -> io::Result<String> {
        let mut n: VacProcName = unsafe { std::mem::zeroed() };
        n.pid = pid;
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                VAC_IOCTL_PROC_NAME as _,
                &mut n as *mut VacProcName,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(String::from_utf8_lossy(&n.comm)
            .trim_end_matches('\0')
            .to_string())
    }
}

impl Drop for VacKmod {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
