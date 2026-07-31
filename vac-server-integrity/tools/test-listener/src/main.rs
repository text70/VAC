use std::fs;
use std::thread;
use std::time::Duration;

fn load_key(dir: &str, name: &str) -> Vec<u8> {
    let full = format!("{}/{}", dir.trim_end_matches('/'), name);
    fs::read(&full).unwrap_or_else(|e| panic!("Failed to load {}: {}", full, e))
}

fn register_player(sid: u64, n: u64) {
    let name = format!("test_player_{}", n);
    let lo = sid as u32;
    let hi = (sid >> 32) as u32;
    let name_bytes = name.as_bytes();
    vac_integrity::vac_server_register_client(lo, hi, name_bytes.as_ptr(), name_bytes.len() as i32);
    eprintln!("[test-listener] Registered steam_id={} as '{}'", sid, name);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key_dir = if args.len() > 1 { &args[1] } else { "/keys" };
    let port: u16 = if args.len() > 2 {
        args[2].parse().expect("Usage: test-listener [key_dir] [port]")
    } else {
        28084
    };

    eprintln!("[test-listener] Loading PQC keys from {} ...", key_dir);
    let kyber_pk = load_key(key_dir, "kyber_public.der");
    let kyber_sk = load_key(key_dir, "kyber_secret.der");
    let mldsa65_pk = load_key(key_dir, "mldsa65_public.der");
    let mldsa65_sk = load_key(key_dir, "mldsa65_secret.der");

    eprintln!("[test-listener] Initializing VAC...");
    vac_integrity::vac_init_rs(&kyber_pk, &mldsa65_sk, &kyber_sk, &mldsa65_pk)
        .expect("vac_init_rs failed");

    // Start listener FIRST (so LISTENER global is populated)
    eprintln!("[test-listener] Starting TCP listener on port {} ...", port);

    // Register a logging kick callback
    extern "C" fn kick_cb(lo: u32, hi: u32, reason: *const std::ffi::c_char) {
        let steam_id = (hi as u64) << 32 | lo as u64;
        let reason_str = if reason.is_null() {
            "unknown".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(reason) }
                .to_string_lossy()
                .to_string()
        };
        eprintln!("[test-listener] KICK CALLBACK: steam_id={}: {}", steam_id, reason_str);
    }
    vac_integrity::vac_set_kick_callback_rs(kick_cb);

    let rc = vac_integrity::vac_server_listener_start(port);
    if rc != 0 {
        panic!("vac_server_listener_start failed with code {}", rc);
    }
    eprintln!("[test-listener] Listener started on port {}", port);

    // Give the listener thread a moment to initialize
    thread::sleep(Duration::from_millis(200));

    // Register 3 test players AFTER listener is running
    for n in 0u64..3 {
        register_player(76561197960265728 + n, n);
    }

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
