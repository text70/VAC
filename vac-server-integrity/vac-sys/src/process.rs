use std::fs;
use std::io::{self};

pub fn current_process_id() -> u32 {
    unsafe { libc::getpid() as u32 }
}

pub fn current_thread_id() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

pub fn current_exe_path() -> io::Result<String> {
    fs::read_link("/proc/self/exe")?
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 exe path"))
}

pub fn enumerate_processes() -> io::Result<Vec<(u32, u32, String)>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat_path = entry.path().join("stat");
        let stat_content = match fs::read_to_string(&stat_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ppid = parse_ppid(&stat_content).unwrap_or(0);
        let comm = parse_comm(&stat_content).unwrap_or_default();
        processes.push((pid, ppid, comm));
    }
    processes.sort_by_key(|p| p.0);
    Ok(processes)
}

pub fn process_cmdline(pid: u32) -> io::Result<String> {
    let cmdline = fs::read(format!("/proc/{}/cmdline", pid))?;
    Ok(cmdline
        .split(|&b| b == 0)
        .filter_map(|s| {
            if s.is_empty() {
                None
            } else {
                std::str::from_utf8(s).ok().map(|s| s.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn enumerate_process_fds(pid: u32) -> io::Result<Vec<(u32, String)>> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut fds = Vec::new();
    for entry in fs::read_dir(&fd_dir)? {
        let entry = entry?;
        let fd_name = entry.file_name().to_string_lossy().to_string();
        let fd_num: u32 = match fd_name.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let target = fs::read_link(entry.path())?;
        let target_str = target.to_string_lossy().to_string();
        fds.push((fd_num, target_str));
    }
    fds.sort_by_key(|f| f.0);
    Ok(fds)
}

pub fn read_process_memory(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
    let remote = pid as libc::pid_t;
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let ret = unsafe {
        libc::process_vm_readv(
            remote,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn parse_ppid(stat: &str) -> Option<u32> {
    let after_comm = stat.rfind(')')?;
    let rest = stat[after_comm + 1..].trim();
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

fn parse_comm(stat: &str) -> Option<String> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    Some(stat[open + 1..close].to_string())
}
