use std::ffi::CStr;
use std::io;
use crate::LibraryInfo;

pub fn loaded_libraries() -> io::Result<Vec<LibraryInfo>> {
    let mut libs = Vec::new();
    let path = format!("/proc/{}/maps", unsafe { libc::getpid() });
    let content = std::fs::read_to_string(&path)?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() == 2 {
                let base = u64::from_str_radix(addr_range[0], 16).unwrap_or(0);
                // Check if this is a new mapping (first address for a library)
                let perms = parts[1];
                if perms.contains('r') && perms.contains('x') {
                    let name = parts[5].to_string();
                    if !name.is_empty() && !libs.iter().any(|l: &LibraryInfo| l.path == name) {
                        let (fname, size) = if let Ok(meta) = std::fs::metadata(&name) {
                            (std::path::Path::new(&name)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default(),
                             meta.len())
                        } else {
                            (String::new(), 0)
                        };
                        libs.push(LibraryInfo {
                            name: fname,
                            path: name,
                            base_address: base,
                            size,
                        });
                    }
                }
            }
        }
    }
    Ok(libs)
}

pub unsafe fn dl_iterate_phdr() -> Vec<LibraryInfo> {
    let mut libs = Vec::new();
    libc::dl_iterate_phdr(Some(callback), &mut libs as *mut Vec<LibraryInfo> as *mut libc::c_void);
    libs
}

extern "C" fn callback(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut libc::c_void,
) -> i32 {
    unsafe {
        let libs = &mut *(data as *mut Vec<LibraryInfo>);
        let name = if (*info).dlpi_name.is_null() {
            String::new()
        } else {
            CStr::from_ptr((*info).dlpi_name)
                .to_string_lossy()
                .to_string()
        };
        if !name.is_empty() {
            let path = std::path::Path::new(&name);
            let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let size = (*info).dlpi_phnum as u64;
            libs.push(LibraryInfo {
                name: fname,
                path: name,
                base_address: (*info).dlpi_addr as u64,
                size,
            });
        }
    }
    0
}
