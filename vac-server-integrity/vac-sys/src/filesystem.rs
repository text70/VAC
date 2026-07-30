use std::fs;
use std::io::{self, BufRead};
use crate::MountInfo;

pub fn mounts() -> io::Result<Vec<MountInfo>> {
    let file = fs::File::open("/proc/self/mountinfo")?;
    let reader = io::BufReader::new(file);
    let mut result = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            result.push(MountInfo {
                device: parts[9].to_string(),
                mount_point: parts[4].to_string(),
                fstype: parts[7].to_string(),
                options: parts[5].to_string(),
            });
        }
    }
    Ok(result)
}

pub fn file_info(path: &str) -> io::Result<(u64, u64)> {
    let meta = fs::metadata(path)?;
    Ok((meta.len(), meta.modified()?.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)))
}

pub fn stat_device(path: &str) -> io::Result<(u64, u64)> {
    // device ID + inode
    let meta = fs::metadata(path)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;
        Ok((meta.st_dev(), meta.st_ino()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = meta;
        Ok((0, 0))
    }
}
