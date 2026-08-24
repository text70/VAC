//! Per-player enrollment token store.
//!
//! Tokens are generated once per player and persisted to disk so installed
//! daemons keep authenticating across server restarts. The path comes from
//! `VAC_TOKEN_DB_PATH` (default: `./vac-tokens.db`). Format: one record per
//! line, `<steam_id> <tab> <token>`.
//!
//! Tokens are only handed back through the host FFI (`vac_server_client_token`,
//! used by the Carbon plugin for chat/magic-link delivery). They are never
//! exposed on the scan protocol and never included in status output.

use std::collections::HashMap;
use std::fs;
use std::sync::Mutex;

static TOKEN_DB_PATH: Mutex<Option<String>> = Mutex::new(None);

fn token_db_path() -> String {
    // Precedence: explicit set_db_path > VAC_TOKEN_DB_PATH env > default
    if let Some(p) = TOKEN_DB_PATH.lock().ok().and_then(|g| g.clone()) {
        return p;
    }
    if let Ok(p) = std::env::var("VAC_TOKEN_DB_PATH") {
        if !p.is_empty() {
            return p;
        }
    }
    "vac-tokens.db".to_string()
}

/// Override the persistence path (called once at init, before any I/O).
pub fn set_db_path(path: &str) {
    if let Ok(mut g) = TOKEN_DB_PATH.lock() {
        *g = Some(path.to_string());
    }
}

/// Load persisted tokens into the given map (steam_id -> token).
pub fn load_all(map: &mut HashMap<u64, String>) {
    let path = token_db_path();
    let Ok(content) = fs::read_to_string(&path) else {
        return;
    };
    for line in content.lines() {
        let Some((id_str, tok)) = line.split_once('\t') else {
            continue;
        };
        let Ok(id) = id_str.parse::<u64>() else {
            continue;
        };
        let tok = tok.trim();
        if !tok.is_empty() && tok.len() <= 128 {
            map.insert(id, tok.to_string());
        }
    }
}

/// Persist one record (append + fsync-light; the file is small).
pub fn store_one(steam_id: u64, token: &str) {
    use std::io::Write;
    let path = token_db_path();
    let mut all = HashMap::new();
    load_all(&mut all);
    all.insert(steam_id, token.to_string());
    let Ok(mut f) = fs::File::create(&path) else {
        eprintln!("[vac-tokens] WARN: cannot write {}", path);
        return;
    };
    let mut buf = String::new();
    for (id, tok) in &all {
        buf.push_str(&id.to_string());
        buf.push('\t');
        buf.push_str(tok);
        buf.push('\n');
    }
    let _ = f.write_all(buf.as_bytes());
}

/// Generate a fresh enrollment token: 32 hex chars from OS randomness.
pub fn generate() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
