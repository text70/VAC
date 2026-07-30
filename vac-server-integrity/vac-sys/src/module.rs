use std::fs;
use std::io::{self, BufRead};
use crate::KernelModuleInfo;

pub fn loaded_kernel_modules() -> io::Result<Vec<KernelModuleInfo>> {
    let file = fs::File::open("/proc/modules")?;
    let reader = io::BufReader::new(file);
    let mut modules = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let deps = if parts[3] == "-" {
                Vec::new()
            } else {
                parts[3].split(',').map(|s| s.to_string()).collect()
            };
            modules.push(KernelModuleInfo {
                name: parts[0].to_string(),
                size: parts[1].parse().unwrap_or(0),
                refcount: parts[2].parse().unwrap_or(0),
                dependencies: deps,
                address: u64::from_str_radix(parts[5].trim_end_matches("]"), 16).unwrap_or(0),
            });
        }
    }
    Ok(modules)
}

pub fn module_path(name: &str) -> Option<String> {
    let path = format!("/sys/module/{}/sections/.text", name);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}
