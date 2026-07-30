use std::collections::HashSet;

// -----------------------------------------------------------------------
// Cheat process name signatures
// -----------------------------------------------------------------------

/// Known cheat/tool process names (matched against task->comm from ring-0).
pub static KNOWN_CHEAT_COMMS: &[&str] = &[
    "cheatengine", "cheat", "injector", "inject", "loader", "reclass",
    "x64dbg", "x32dbg", "ollydbg", "dnspy", "de4dot", "confuser",
    "processhacker", "pchunter", "frida", "gdb", "lldb", "strace", "ltrace",
    "httrack", "wireshark", "tcpdump", "mitmproxy", "burpsuite", "fiddler",
    "proxifier", "sockscap", "gameguardian", "artmoney", "wemod", "trainer",
];

// -----------------------------------------------------------------------
// Ring-0 process data types
// -----------------------------------------------------------------------

pub struct Ring0ProcEntry {
    pub pid: u32,
    #[allow(dead_code)]
    pub ppid: u32,
    pub comm: String,
}

/// Parse a ring-0 payload byte stream into process entries.
/// Format: [count: u32 LE] + [pid(u32) + ppid(u32) + comm[16]] × count
pub fn parse_ring0_payload(data: &[u8]) -> Vec<Ring0ProcEntry> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut off = 4usize;
    for _ in 0..count {
        if off + 24 > data.len() {
            break;
        }
        let pid = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let ppid = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let comm_bytes = &data[off + 8..off + 24];
        let comm = String::from_utf8_lossy(comm_bytes)
            .trim_end_matches('\0')
            .to_string();
        entries.push(Ring0ProcEntry { pid, ppid, comm });
        off += 24;
    }
    entries
}

// -----------------------------------------------------------------------
// Violation / finding types
// -----------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum FindingKind {
    CheatProcess { pid: u32, comm: String },
    HiddenProcess { pid: u32, comm: String },
    #[allow(dead_code)]
    MissingFromRing0 { pid: u32, comm: String },
    RwxPage { address: u64, size: u64 },
    AnonymousExec { address: u64, size: u64 },
    TracerAttached { tracer_pid: u32 },
    DebuggerFlags { flags: u32 },
    SuspiciousEnv { flags: u32 },
    InjectedAssembly { name: String },
    LatencyAnomaly { duration_ms: u64 },
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: FindingKind,
    #[allow(dead_code)]
    pub points: u32,
}

// -----------------------------------------------------------------------
// Scoring thresholds
// -----------------------------------------------------------------------

pub const SCORE_WARN: u32 = 30;
pub const SCORE_KICK: u32 = 50;
pub const SCORE_BAN: u32 = 80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Warn,
    Kick,
    Ban,
}

// -----------------------------------------------------------------------
// Per-client score state
// -----------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ScoreState {
    pub total: u32,
    pub findings: Vec<Finding>,
    pub clean_scan_count: u32,
}

impl ScoreState {
    pub fn new() -> Self {
        Self {
            total: 0,
            findings: Vec::new(),
            clean_scan_count: 0,
        }
    }

    /// Add a finding with its point weight.
    pub fn add_finding(&mut self, kind: FindingKind, points: u32) {
        self.total += points;
        self.findings.push(Finding {
            kind,
            points,
        });
    }

    /// Determine what action to take based on current score.
    pub fn action(&self) -> Action {
        if self.total >= SCORE_BAN {
            Action::Ban
        } else if self.total >= SCORE_KICK {
            Action::Kick
        } else if self.total >= SCORE_WARN {
            Action::Warn
        } else {
            Action::None
        }
    }

    /// Reset after a clean scan or after an action is taken.
    pub fn reset(&mut self) {
        if self.total == 0 {
            self.clean_scan_count += 1;
        } else {
            self.clean_scan_count = 0;
        }
        self.total = 0;
        self.findings.clear();
    }
}

// -----------------------------------------------------------------------
// Scoring weights by finding type
// -----------------------------------------------------------------------

pub const POINTS_CHEAT_PROCESS: u32 = 50;
pub const POINTS_HIDDEN_PROCESS: u32 = 40;
pub const POINTS_MISSING_RING0: u32 = 30;
pub const POINTS_RWX_PAGE: u32 = 35;
pub const POINTS_ANON_EXEC: u32 = 30;
pub const POINTS_TRACER: u32 = 25;
pub const POINTS_DEBUGGER_FLAGS: u32 = 20;
pub const POINTS_SUSPICIOUS_ENV: u32 = 10;
pub const POINTS_INJECTED_ASSEMBLY: u32 = 30;
pub const POINTS_LATENCY_ANOMALY: u32 = 15;

// -----------------------------------------------------------------------
// Ring-0 process analysis
// -----------------------------------------------------------------------

/// Analyze ring-0 process entries against known cheat names.
#[allow(dead_code)]
pub fn analyze_ring0_procs(entries: &[Ring0ProcEntry], state: &mut ScoreState) {
    let mut seen_comms: HashSet<&str> = HashSet::new();

    for entry in entries {
        let comm_lower = entry.comm.to_lowercase();

        if !comm_lower.is_empty() {
            for &cheat in KNOWN_CHEAT_COMMS {
                if comm_lower.contains(cheat) {
                    if seen_comms.insert(cheat) {
                        state.add_finding(
                            FindingKind::CheatProcess {
                                pid: entry.pid,
                                comm: entry.comm.clone(),
                            },
                            POINTS_CHEAT_PROCESS,
                        );
                    }
                    break;
                }
            }
        }
    }
}

// -----------------------------------------------------------------------
// Hidden process analysis
// -----------------------------------------------------------------------

/// Compare user-mode /proc/ process list vs ring-0 process list.
/// Returns findings for processes visible only on one side.
#[allow(dead_code)]
pub fn analyze_hidden_procs(
    user_procs: &[(u32, String)],
    ring0_procs: &[(u32, String)],
    state: &mut ScoreState,
) {
    let ring0_pids: HashSet<u32> = ring0_procs.iter().map(|(pid, _)| *pid).collect();
    let user_pids: HashSet<u32> = user_procs.iter().map(|(pid, _)| *pid).collect();

    // Processes visible in user-mode but NOT in ring-0
    // This suggests a user-mode rootkit hiding from /proc/
    for (pid, comm) in user_procs {
        if !ring0_pids.contains(pid) {
            state.add_finding(
                FindingKind::MissingFromRing0 {
                    pid: *pid,
                    comm: comm.clone(),
                },
                POINTS_MISSING_RING0,
            );
        }
    }

    // Processes visible in ring-0 but NOT in user-mode
    // This suggests a kernel-mode rootkit hiding from /proc or the process was killed between scans
    for (pid, comm) in ring0_procs {
        if !user_pids.contains(pid) {
            state.add_finding(
                FindingKind::HiddenProcess {
                    pid: *pid,
                    comm: comm.clone(),
                },
                POINTS_HIDDEN_PROCESS,
            );
        }
    }
}

// -----------------------------------------------------------------------
// Memory anomaly analysis
// -----------------------------------------------------------------------

/// Analyze memory map entries for suspicious patterns.
/// entries: (start_addr, end_addr, perms, pathname)
#[allow(dead_code)]
pub fn analyze_memory_map(
    entries: &[(u64, u64, String, String)],
    state: &mut ScoreState,
) {
    for (start, end, perms, path) in entries {
        // RWX pages — should not exist in normal operation
        if perms.contains("rwx") {
            state.add_finding(
                FindingKind::RwxPage {
                    address: *start,
                    size: end - start,
                },
                POINTS_RWX_PAGE,
            );
        }

        // Anonymous executable pages (no file backing)
        if perms.contains('x') && !perms.contains('w') && path.is_empty() {
            state.add_finding(
                FindingKind::AnonymousExec {
                    address: *start,
                    size: end - start,
                },
                POINTS_ANON_EXEC,
            );
        }
    }
}

/// Generate a human-readable summary of all findings.
pub fn findings_summary(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "clean".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    for f in findings {
        match &f.kind {
            FindingKind::CheatProcess { pid, comm } => {
                parts.push(format!("cheat[{}](pid={})", comm, pid));
            }
            FindingKind::HiddenProcess { pid, comm } => {
                parts.push(format!("hidden[{}](pid={})", comm, pid));
            }
            FindingKind::MissingFromRing0 { pid, comm } => {
                parts.push(format!("user-hides-ring0[{}](pid={})", comm, pid));
            }
            FindingKind::RwxPage { address, size } => {
                parts.push(format!("rwx@{:#x}+{}", address, size));
            }
            FindingKind::AnonymousExec { address, size } => {
                parts.push(format!("anon-exec@{:#x}+{}", address, size));
            }
            FindingKind::TracerAttached { tracer_pid } => {
                parts.push(format!("tracer(pid={})", tracer_pid));
            }
            FindingKind::DebuggerFlags { flags } => {
                parts.push(format!("dbg-flags({})", flags));
            }
            FindingKind::SuspiciousEnv { flags } => {
                parts.push(format!("env-flags({})", flags));
            }
            FindingKind::InjectedAssembly { name } => {
                parts.push(format!("injected({})", name));
            }
            FindingKind::LatencyAnomaly { duration_ms } => {
                parts.push(format!("latency({}ms)", duration_ms));
            }
        }
    }
    parts.join("; ")
}
