use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use vac_core::buffer::DataBuffer;
use vac_crypto::seal;

use crate::policy::{self, Action, FindingKind, ScoreState};

static LISTENER_RUNNING: AtomicBool = AtomicBool::new(false);

struct ListenerState {
    handle: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
    registered: Arc<Mutex<HashMap<u64, (String, ScoreState)>>>,
    connected: Arc<Mutex<HashSet<u64>>>,
}

static LISTENER: RwLock<Option<ListenerState>> = RwLock::new(None);

const NONCE_LEN: usize = 8;

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => return Err("closed".into()),
            Ok(n) => off += n,
            Err(e) => return Err(format!("read: {}", e)),
        }
    }
    Ok(())
}

fn send_msg(stream: &mut TcpStream, msg_type: u8, payload: &[u8]) -> Result<(), String> {
    let len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.push(msg_type);
    buf.extend_from_slice(payload);
    stream.write_all(&buf).map_err(|e| format!("write: {}", e))
}

fn decrypt_result(
    sealed: &[u8],
    player_name: &str,
    module_id: u32,
    _steam_id: u64,
    expected_nonce: &[u8; NONCE_LEN],
    state: &mut ScoreState,
) -> Duration {
    let start = Instant::now();
    let open_key = match crate::get_open_key() {
        Some(k) => k,
        None => {
            eprintln!("[vac-listener] No keys for {} module {}", player_name, module_id);
            return start.elapsed();
        }
    };

    match seal::open(sealed, &open_key) {
        Ok((plaintext, mid, _ts)) => {
            // Verify nonce (first 8 bytes)
            if plaintext.len() < NONCE_LEN {
                eprintln!("[vac-listener] {} module {}: payload too short (missing nonce)", player_name, mid);
                state.add_finding(FindingKind::LatencyAnomaly { duration_ms: 0 }, 20);
                return start.elapsed();
            }

            let actual_nonce: [u8; NONCE_LEN] = plaintext[..NONCE_LEN].try_into().unwrap();
            if actual_nonce != *expected_nonce {
                eprintln!("[vac-listener] {} module {}: NONCE MISMATCH — replay attack?", player_name, mid);
                state.add_finding(FindingKind::LatencyAnomaly { duration_ms: 0 }, 50);
            }

            let data = &plaintext[NONCE_LEN..];
            let dwords = data.len() / 4;
            let max = dwords.min(2048);
            let mut buf = DataBuffer::new();
            for i in 0..max {
                let val = u32::from_le_bytes(
                    data[i * 4..i * 4 + 4].try_into().unwrap()
                );
                buf.raw[i] = val;
            }
            let cursor = dwords.min(2048);
            buf.set_cursor(cursor);

            match mid {
                101 | 102 | 103 | 104 | 105 | 106 => {
                    // Client scan modules — feed findings into score state
                    analyze_client_module(mid, &buf, cursor, player_name, state);
                }
                200 => {
                    // Ring-0 raw process list
                    let r0_data = &plaintext[NONCE_LEN..];
                    let entries = policy::parse_ring0_payload(r0_data);
                    policy::analyze_ring0_procs(&entries, state);
                    if !state.findings.is_empty() {
                        let has_cheat = state.findings.iter().any(|f| matches!(f.kind, FindingKind::CheatProcess { .. }));
                        if has_cheat {
                            eprintln!("[vac-listener] {} RING-0 cheat processes detected", player_name);
                        }
                    }
                }
                201 => {
                    // Hidden process detection results
                    analyze_hidden_module(&buf, cursor, player_name, state);
                }
                202 => {
                    // Memory scan results
                    analyze_memory_module(&buf, cursor, player_name, state);
                }
                _ => {
                    // Server-local modules (1-6)
                    match mid {
                        1 => {
                            if cursor > 23 && (buf.raw[23] & 1) == 1 {
                                eprintln!("[vac-listener] {} MODULE 1: kernel debugger detected", player_name);
                                state.add_finding(FindingKind::DebuggerFlags { flags: buf.raw[23] }, 20);
                            }
                        }
                        2 => {
                            if cursor > 6 && buf.raw[6] > 0 {
                                let count = buf.raw[6];
                                eprintln!("[vac-listener] {} MODULE 2: {} suspicious processes", player_name, count);
                                state.add_finding(FindingKind::DebuggerFlags { flags: count }, count.saturating_mul(10));
                            }
                        }
                        3 => {
                            if cursor > 7 && buf.raw[7] > 0 {
                                let count = buf.raw[7];
                                eprintln!("[vac-listener] {} MODULE 3: {} suspicious libs", player_name, count);
                            }
                        }
                        6 => {
                            let suspicious = if cursor > 1 { buf.raw[1] } else { 0 };
                            if suspicious > 0 {
                                eprintln!("[vac-listener] {} MODULE 6: {} suspicious modules", player_name, suspicious);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Log summary
            let elapsed = start.elapsed();
            if state.total > 0 {
                eprintln!("[vac-listener] {} module {}: score={}, findings={}",
                    player_name, mid, state.total, state.findings.len());
            } else {
                eprintln!("[vac-listener] {} module {}: clean", player_name, mid);
            }

            elapsed
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("signature") {
                eprintln!("[vac-listener] {} module {}: INVALID SIGNATURE", player_name, module_id);
                state.add_finding(FindingKind::LatencyAnomaly { duration_ms: 0 }, 50);
            } else {
                eprintln!("[vac-listener] {} module {}: decrypt failed: {}", player_name, module_id, msg);
                state.add_finding(FindingKind::LatencyAnomaly { duration_ms: 0 }, 10);
            }
            start.elapsed()
        }
    }
}

fn analyze_client_module(mid: u32, buf: &DataBuffer, cursor: usize, player_name: &str, state: &mut ScoreState) {
    match mid {
        101 => {
            let kmod = if cursor > 5 { buf.raw[5] } else { 0 };
            let pcount = if cursor > 6 { buf.raw[6] } else { 0 };
            if kmod == 1 && pcount == 0 {
                eprintln!("[vac-listener] {} MODULE 101: kernel module loaded but reports 0 procs", player_name);
                state.add_finding(FindingKind::DebuggerFlags { flags: 0x101 }, 20);
            }
        }
        102 => {
            if cursor > 0 && buf.raw[0] > 400 {
                let count = buf.raw[0];
                eprintln!("[vac-listener] {} MODULE 102: excessive libraries ({})", player_name, count);
                state.add_finding(FindingKind::SuspiciousEnv { flags: count }, 15);
            }
        }
        103 => {
            if cursor > 0 && buf.raw[0] != 0 {
                let flags = buf.raw[0];
                eprintln!("[vac-listener] {} MODULE 103: debugger flags={}", player_name, flags);
                state.add_finding(FindingKind::DebuggerFlags { flags }, policy::POINTS_DEBUGGER_FLAGS);
            }
            if cursor > 1 && buf.raw[1] != 0 {
                let tracer = buf.raw[1];
                eprintln!("[vac-listener] {} MODULE 103: tracer PID={}", player_name, tracer);
                state.add_finding(FindingKind::TracerAttached { tracer_pid: tracer }, policy::POINTS_TRACER);
            }
        }
        104 => {
            if cursor > 0 && buf.raw[0] != 0 {
                let flags = buf.raw[0];
                eprintln!("[vac-listener] {} MODULE 104: missing assemblies={}", player_name, flags);
            }
            if cursor > 1 && buf.raw[1] != 0 {
                let count = buf.raw[1];
                eprintln!("[vac-listener] {} MODULE 104: {} injected assemblies", player_name, count);
                state.add_finding(FindingKind::InjectedAssembly { name: format!("count={}", count) }, policy::POINTS_INJECTED_ASSEMBLY);
            }
        }
        105 => {
            if cursor > 0 && buf.raw[0] != 0 {
                let flags = buf.raw[0];
                eprintln!("[vac-listener] {} MODULE 105: env flags={}", player_name, flags);
                state.add_finding(FindingKind::SuspiciousEnv { flags }, policy::POINTS_SUSPICIOUS_ENV);
            }
        }
        106 => {
            if cursor > 0 && buf.raw[0] != 0 {
                let count = buf.raw[0];
                eprintln!("[vac-listener] {} MODULE 106: {} cheat procs", player_name, count);
                state.add_finding(FindingKind::DebuggerFlags { flags: count }, count.saturating_mul(20));
            }
        }
        _ => {}
    }
}

fn analyze_hidden_module(buf: &DataBuffer, cursor: usize, player_name: &str, state: &mut ScoreState) {
    if cursor < 2 {
        return;
    }
    let hidden_count = buf.raw[0];
    let missing_count = buf.raw[1];
    if hidden_count > 0 {
        eprintln!("[vac-listener] {} MODULE 201: {} processes hidden from user-mode", player_name, hidden_count);
        state.add_finding(FindingKind::HiddenProcess { pid: 0, comm: format!("{} hidden", hidden_count) },
            hidden_count.saturating_mul(policy::POINTS_HIDDEN_PROCESS));
    }
    if missing_count > 0 {
        eprintln!("[vac-listener] {} MODULE 201: {} processes missing from ring-0", player_name, missing_count);
        state.add_finding(FindingKind::HiddenProcess { pid: 0, comm: format!("{} missing-from-ring0", missing_count) },
            missing_count.saturating_mul(policy::POINTS_MISSING_RING0));
    }
}

fn analyze_memory_module(buf: &DataBuffer, cursor: usize, player_name: &str, state: &mut ScoreState) {
    if cursor < 4 {
        return;
    }
    let rwx_count = buf.raw[0];
    let anon_exec_count = buf.raw[1];
    let regions_checked = buf.raw[2];
    let text_mismatches = buf.raw[3];
    if rwx_count > 0 {
        eprintln!("[vac-listener] {} MODULE 202: {} RWX pages (checked {})", player_name, rwx_count, regions_checked);
        state.add_finding(FindingKind::RwxPage { address: 0, size: rwx_count as u64 },
            rwx_count.saturating_mul(policy::POINTS_RWX_PAGE));
    }
    if anon_exec_count > 0 {
        eprintln!("[vac-listener] {} MODULE 202: {} anonymous exec mappings (checked {})",
            player_name, anon_exec_count, regions_checked);
        state.add_finding(FindingKind::AnonymousExec { address: 0, size: anon_exec_count as u64 },
            anon_exec_count.saturating_mul(policy::POINTS_ANON_EXEC));
    }
    if text_mismatches > 0 {
        eprintln!("[vac-listener] {} MODULE 202: {} text section hash mismatches (possible code modification)",
            player_name, text_mismatches);
        state.add_finding(FindingKind::InjectedAssembly { name: format!("text-mismatch({})", text_mismatches) },
            text_mismatches.saturating_mul(policy::POINTS_INJECTED_ASSEMBLY));
    }
}

fn enforce_score_state(steam_id: u64, player_name: &str, state: &ScoreState) {
    let action = state.action();
    match action {
        Action::Ban => {
            let summary = policy::findings_summary(&state.findings);
            eprintln!("[vac-listener] {} BANNING (score={}): {}", player_name, state.total, summary);
            crate::report_cheat(steam_id, &format!("SCORE_BAN: {}", summary));
        }
        Action::Kick => {
            let summary = policy::findings_summary(&state.findings);
            eprintln!("[vac-listener] {} KICKING (score={}): {}", player_name, state.total, summary);
            crate::report_cheat(steam_id, &format!("SCORE_KICK: {}", summary));
        }
        Action::Warn => {
            let summary = policy::findings_summary(&state.findings);
            eprintln!("[vac-listener] {} WARN (score={}): {}", player_name, state.total, summary);
        }
        Action::None => {}
    }
}

fn handle_client(mut stream: TcpStream, registered: Arc<Mutex<HashMap<u64, (String, ScoreState)>>>, connected: Arc<Mutex<HashSet<u64>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));

    let mut len_buf = [0u8; 4];
    if read_exact(&mut stream, &mut len_buf).is_err() { return; }
    let msg_len = u32::from_le_bytes(len_buf) as usize;
    if msg_len < 9 || msg_len > 65536 { return; }
    let mut msg = vec![0u8; msg_len];
    if read_exact(&mut stream, &mut msg).is_err() { return; }
    if msg[0] != 0x01 { return; }

    let steam_id = u64::from_le_bytes(msg[1..9].try_into().unwrap());

    let (player_name, mut score_state) = {
        let mut reg = registered.lock().unwrap();
        match reg.get_mut(&steam_id) {
            Some((name, st)) => (name.clone(), st.clone()),
            None => {
                eprintln!("[vac-listener] Reject unregistered steam_id={}", steam_id);
                return;
            }
        }
    };

    if send_msg(&mut stream, 0x02, &[]).is_err() { return; }
    {
        let mut conn = connected.lock().unwrap();
        conn.insert(steam_id);
    }
    // Drop guard: remove steam_id from connected on any exit path
    struct RemoveOnDrop<'a> {
        connected: &'a Arc<std::sync::Mutex<HashSet<u64>>>,
        steam_id: u64,
    }
    impl<'a> Drop for RemoveOnDrop<'a> {
        fn drop(&mut self) {
            if let Ok(mut conn) = self.connected.lock() {
                conn.remove(&self.steam_id);
            }
        }
    }
    let _guard = RemoveOnDrop { connected: &connected, steam_id };
    eprintln!("[vac-listener] Client auth OK: {} steam_id={}", player_name, steam_id);

    // Get sealing keys from the scheduler
    let keys = crate::get_keys();
    let (kyber_pk, dsa_sk) = match keys {
        Some(k) => k,
        None => {
            eprintln!("[vac-listener] No sealing keys");
            return;
        }
    };

    // Run all modules 1-9
    for module_id in 1u32..=9 {
        // Generate random nonce for challenge-response
        let nonce: [u8; 8] = rand::random();

        let mut cmd = Vec::new();
        cmd.extend_from_slice(&module_id.to_le_bytes());
        cmd.extend_from_slice(&(kyber_pk.len() as i32).to_le_bytes());
        cmd.extend_from_slice(&kyber_pk);
        cmd.extend_from_slice(&(dsa_sk.len() as i32).to_le_bytes());
        cmd.extend_from_slice(&dsa_sk);
        cmd.extend_from_slice(&nonce);

        if send_msg(&mut stream, 0x03, &cmd).is_err() {
            eprintln!("[vac-listener] Send SCAN_CMD failed for {} module {}", player_name, module_id);
            return;
        }

        // Read response
        let mut rlen = [0u8; 4];
        if read_exact(&mut stream, &mut rlen).is_err() {
            eprintln!("[vac-listener] Read response failed for {} module {}", player_name, module_id);
            return;
        }
        let rmsg_len = u32::from_le_bytes(rlen) as usize;
        if rmsg_len < 9 || rmsg_len > 65536 { return; }
        let mut rmsg = vec![0u8; rmsg_len];
        if read_exact(&mut stream, &mut rmsg).is_err() { return; }

        if rmsg[0] != 0x04 || rmsg.len() < 9 { return; }
        let mid = u32::from_le_bytes(rmsg[1..5].try_into().unwrap());
        let sealed_len = i32::from_le_bytes(rmsg[5..9].try_into().unwrap()) as usize;
        let sealed = &rmsg[9..9 + sealed_len.min(rmsg.len() - 9)];

        // Decrypt and analyze — feeds findings into score_state
        let duration = decrypt_result(sealed, &player_name, mid, steam_id, &nonce, &mut score_state);
        if duration > Duration::from_millis(100) {
            eprintln!("[vac-listener] {} module {}: latency {}ms", player_name, mid, duration.as_millis());
            score_state.add_finding(FindingKind::LatencyAnomaly { duration_ms: duration.as_millis() as u64 },
                policy::POINTS_LATENCY_ANOMALY);
        }
    }

    // After all modules: enforce action if score exceeds threshold
    enforce_score_state(steam_id, &player_name, &score_state);

    // Reset score for next scan round
    score_state.reset();

    // Store score state back
    {
        let mut reg = registered.lock().unwrap();
        let name_clone = player_name.clone();
        reg.insert(steam_id, (player_name, score_state));
        eprintln!("[vac-listener] Client {} scan complete", name_clone);
    }
}

fn listener_thread(port: u16, stop: Arc<AtomicBool>, registered: Arc<Mutex<HashMap<u64, (String, ScoreState)>>>, connected: Arc<Mutex<HashSet<u64>>>) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => {
            eprintln!("[vac-listener] TCP listener on {}", addr);
            l
        }
        Err(e) => {
            eprintln!("[vac-listener] Failed to bind: {}", e);
            return;
        }
    };
    listener.set_nonblocking(true).ok();

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let reg = registered.clone();
                let conn = connected.clone();
                thread::spawn(move || handle_client(stream, reg, conn));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[vac-listener] accept error: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
    eprintln!("[vac-listener] Stopped");
}

pub fn start(port: u16) -> bool {
    if LISTENER_RUNNING.swap(true, Ordering::SeqCst) {
        return false;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let registered: Arc<Mutex<HashMap<u64, (String, ScoreState)>>> = Arc::new(Mutex::new(HashMap::new()));
    let connected: Arc<Mutex<HashSet<u64>>> = Arc::new(Mutex::new(HashSet::new()));

    let stop_clone = stop.clone();
    let reg_clone = registered.clone();
    let conn_clone = connected.clone();
    let handle = thread::spawn(move || {
        listener_thread(port, stop_clone, reg_clone, conn_clone);
    });

    if let Ok(mut guard) = LISTENER.write() {
        *guard = Some(ListenerState {
            handle: Some(handle),
            stop_flag: stop,
            registered,
            connected,
        });
    }
    true
}

pub fn stop() {
    if let Ok(mut guard) = LISTENER.write() {
        if let Some(ref mut ls) = *guard {
            ls.stop_flag.store(true, Ordering::SeqCst);
            if let Some(h) = ls.handle.take() {
                h.join().ok();
            }
        }
        *guard = None;
    }
    LISTENER_RUNNING.store(false, Ordering::SeqCst);
}

pub fn register_client(steam_id: u64, player_name: &str) {
    if let Ok(guard) = LISTENER.read() {
        if let Some(ref ls) = *guard {
            let mut reg = ls.registered.lock().unwrap();
            reg.insert(steam_id, (player_name.to_string(), ScoreState::new()));
        }
    }
}

pub fn unregister_client(steam_id: u64) {
    if let Ok(guard) = LISTENER.read() {
        if let Some(ref ls) = *guard {
            let mut reg = ls.registered.lock().unwrap();
            reg.remove(&steam_id);
        }
    }
}

pub fn is_connected(steam_id: u64) -> bool {
    if let Ok(guard) = LISTENER.read() {
        if let Some(ref ls) = *guard {
            let conn = ls.connected.lock().unwrap();
            return conn.contains(&steam_id);
        }
    }
    false
}
