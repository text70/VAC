use vac_core::module::{Module, ScanError, ScanReport};
use vac_sys::SystemOps;

pub const MODULE_ID: u32 = 2;

const KNOWN_CHEAT_PROCESSES: &[&str] = &[
    "cheatengine",
    "cheatengine64",
    "injector",
    "extreme_injector",
    "process_hacker",
    "processhacker",
    "x96dbg",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "ida64",
    "ida",
    "windbg",
    "reclass",
    "reclass64",
    "httpproxy",
    "fiddler",
    "wireshark",
];

pub struct ProcessHandleListModule;

impl Module for ProcessHandleListModule {
    fn name(&self) -> &'static str {
        "ProcessHandleList"
    }

    fn module_id(&self) -> u32 {
        MODULE_ID
    }

    fn scan(&mut self, report: &mut ScanReport) {
        let sys = vac_sys::linux::LinuxSystem::new();

        let buf = &mut report.data;

        buf.write_u32(0); // pad
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(0);
        buf.write_u32(MODULE_ID);

        let processes = match sys.enumerate_processes() {
            Ok(p) => p,
            Err(_e) => {
                report.error = ScanError::SystemCallFailed;
                return;
            }
        };

        buf.write_u32(processes.len() as u32);

        let mut flagged_count = 0;

        for (i, (pid, ppid, comm)) in processes.iter().enumerate() {
            if i >= 400 {
                break;
            }

            buf.write_u32(*pid);
            buf.write_u32(*ppid);

            let comm_lower = comm.to_lowercase();
            let is_suspicious = KNOWN_CHEAT_PROCESSES
                .iter()
                .any(|cheat| comm_lower.contains(cheat));

            if is_suspicious {
                buf.write_u32(1); // flagged
                let name_hash = vac_core::hash::vac_hash(comm.as_bytes());
                buf.write_u32(name_hash);
                flagged_count += 1;
            } else {
                buf.write_u32(0); // clean
                buf.write_u32(0);
            }
        }

        // Write flagged count at a known offset
        buf.set_cursor(6);
        buf.write_u32(flagged_count);

        report.error = ScanError::None;
    }
}
