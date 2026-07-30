use std::fs;
use std::io;
use crate::ServiceInfo;

pub fn list_systemd_services() -> io::Result<Vec<ServiceInfo>> {
    let output = std::process::Command::new("systemctl")
        .args(["list-units", "--type=service", "--all", "--no-pager", "--no-legend"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[0].trim_end_matches(".service").to_string();
            let state = parts[2].to_string();
            let enabled = parts[3] == "enabled";
            services.push(ServiceInfo { name, state, enabled });
        }
    }
    Ok(services)
}

pub fn list_sysv_services() -> io::Result<Vec<ServiceInfo>> {
    let mut services = Vec::new();
    if let Ok(dir) = fs::read_dir("/etc/init.d") {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            services.push(ServiceInfo {
                name,
                state: "unknown".to_string(),
                enabled: false,
            });
        }
    }
    Ok(services)
}
