use std::sync::Mutex;

use vac_core::buffer::DATA_BUFFER_DWORDS;
use vac_core::module::{Module, ScanReport};
use vac_crypto::seal;
use vac_crypto::seal::{HEADER_LEN, AES_NONCE_LEN, AES_TAG_LEN, KYBER_CT_LEN, MLDSA_65_SIG_LEN};

mod scan_scheduler;
mod listener;
mod policy;

static SCAN_SCHEDULER: Mutex<Option<scan_scheduler::ScanScheduler>> = Mutex::new(None);

/// Registered by the host (Carbon plugin or test-listener) to handle cheat detection.
/// Signature: fn(steam_id_lo: u32, steam_id_hi: u32, reason: *const c_char)
static KICK_CALLBACK: Mutex<Option<KickFn>> = Mutex::new(None);

type KickFn = extern "C" fn(u32, u32, *const std::ffi::c_char);

/// Called by listener when a ring-0+verified cheat is detected.
pub fn report_cheat(steam_id: u64, reason: &str) {
    let lo = steam_id as u32;
    let hi = (steam_id >> 32) as u32;
    let c_reason = std::ffi::CString::new(reason).unwrap_or_default();
    if let Ok(guard) = KICK_CALLBACK.lock() {
        if let Some(cb) = guard.as_ref() {
            cb(lo, hi, c_reason.as_ptr());
        }
    }
    // Always log even without callback
    eprintln!("[vac-cheat] steam_id={} BANNED: {}", steam_id, reason);
}

pub fn get_keys() -> Option<(Vec<u8>, Vec<u8>)> {
    SCAN_SCHEDULER.lock().ok().and_then(|guard| {
        guard.as_ref().map(|s| (s.kyber_pk.clone(), s.mldsa65_sk.clone()))
    })
}

pub fn get_open_key() -> Option<seal::OpenKey> {
    SCAN_SCHEDULER.lock().ok().and_then(|guard| {
        guard.as_ref().map(|s| s.open_key())
    })
}

/// Initialize the VAC integrity system.
/// Called once by the Carbon plugin on server startup.
///
/// Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn vac_init(
    kyber_pk: *const u8,
    kyber_pk_len: i32,
    mldsa65_sk: *const u8,
    mldsa65_sk_len: i32,
    kyber_sk: *const u8,
    kyber_sk_len: i32,
    mldsa65_pk: *const u8,
    mldsa65_pk_len: i32,
) -> i32 {
    let kyber_key = if kyber_pk.is_null() || kyber_pk_len <= 0 {
        return -2;
    } else {
        unsafe { std::slice::from_raw_parts(kyber_pk, kyber_pk_len as usize) }.to_vec()
    };

    let dsa_key = if mldsa65_sk.is_null() || mldsa65_sk_len <= 0 {
        return -3;
    } else {
        unsafe { std::slice::from_raw_parts(mldsa65_sk, mldsa65_sk_len as usize) }.to_vec()
    };

    let kyber_secret = if kyber_sk.is_null() || kyber_sk_len <= 0 {
        return -4;
    } else {
        unsafe { std::slice::from_raw_parts(kyber_sk, kyber_sk_len as usize) }.to_vec()
    };

    let dsa_public = if mldsa65_pk.is_null() || mldsa65_pk_len <= 0 {
        return -5;
    } else {
        unsafe { std::slice::from_raw_parts(mldsa65_pk, mldsa65_pk_len as usize) }.to_vec()
    };

    let scheduler = scan_scheduler::ScanScheduler::new(kyber_key, dsa_key, kyber_secret, dsa_public);

    match SCAN_SCHEDULER.lock() {
        Ok(mut guard) => {
            *guard = Some(scheduler);
            0
        }
        Err(_) => -1,
    }
}

/// Run a specific module scan.
/// Called periodically by the Carbon plugin.
///
/// buffer: output buffer (must be at least 12617 bytes)
/// len: in = buffer capacity, out = bytes written
/// Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn vac_scan(module_id: u32, buffer: *mut u8, len: *mut i32) -> i32 {
    if buffer.is_null() || len.is_null() {
        return -5;
    }

    let (kyber_pk, mldsa65_sk) = match SCAN_SCHEDULER.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(s) => (s.kyber_pk.clone(), s.mldsa65_sk.clone()),
            None => return -4,
        },
        Err(_) => return -1,
    };

    let capacity = unsafe { *len as usize };
    const PRESENCE_LEN: usize = 32;
    let min_capacity = HEADER_LEN + KYBER_CT_LEN + AES_NONCE_LEN + AES_TAG_LEN
        + (DATA_BUFFER_DWORDS * 4) + PRESENCE_LEN + MLDSA_65_SIG_LEN;
    if capacity < min_capacity || capacity > 65536 {
        return -6;
    }

    let mut report = ScanReport::new(module_id);

    match module_id {
        1 => {
            let mut module = vac_module_systeminfo::SystemInfoModule;
            module.scan(&mut report);
        }
        2 => {
            let mut module = vac_module_processhandle::ProcessHandleListModule;
            module.scan(&mut report);
        }
        3 => {
            let mut module = vac_module_processmonitor::ProcessMonitorModule;
            module.scan(&mut report);
        }
        4 => {
            let mut module = vac_module_deviceinfo::DeviceInfoModule;
            module.scan(&mut report);
        }
        5 => {
            let mut module = vac_module_driverinfo::DriverInfoModule;
            module.scan(&mut report);
        }
        6 => {
            let mut module = vac_module_readmodules::ReadModulesModule;
            module.scan(&mut report);
        }
        _ => return -7, // unknown module
    }

    let data_bytes = &report.data.raw;
    let data_slice = unsafe {
        std::slice::from_raw_parts(
            data_bytes.as_ptr() as *const u8,
            data_bytes.len() * 4,
        )
    };

    // Append hardware presence data (32 bytes) so vac_decrypt_with_attestation
    // can extract it from the decrypted plaintext.
    let mut presence_payload = Vec::with_capacity(data_slice.len() + 32);
    presence_payload.extend_from_slice(data_slice);
    // First byte = presence flag (1 = no kernel module; on the host this is always 1)
    presence_payload.extend_from_slice(&[
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    // Seal with PQC
    let seal_key = seal::SealKey {
        kyber_public_key: kyber_pk,
        mldsa65_secret_key: mldsa65_sk,
    };

    match seal::seal(&presence_payload, module_id, &seal_key) {
        Ok(sealed) => {
            let write_len = sealed.raw.len().min(capacity);
            unsafe {
                std::ptr::copy_nonoverlapping(sealed.raw.as_ptr(), buffer, write_len);
                *len = write_len as i32;
            }
            0
        }
        Err(_) => -8, // seal failed
    }
}

/// Verifies the TPM attestation payload.
/// Currently a sanity check; in production, this should compare the quote/signature
/// against a known-good baseline (PCR values, etc.).
fn verify_attestation(attestation: &[u8]) -> bool {
    // Basic check: attestation should not be all zeros
    !attestation.iter().all(|&b| b == 0)
}

/// Decrypt and verify a scan result from a client.
/// Adds attestation output support.
///
/// output: decrypted scan data (2048 DWORD = 8192 bytes)
/// output_dwords: out = DWORDs written
/// attestation: out = 32-byte TPM attestation
#[no_mangle]
pub extern "C" fn vac_decrypt_with_attestation(
    encrypted: *const u8,
    encrypted_len: i32,
    kyber_sk: *const u8,
    kyber_sk_len: i32,
    mldsa65_pk: *const u8,
    mldsa65_pk_len: i32,
    output: *mut u32,
    output_dwords: *mut i32,
    attestation: *mut u8,
) -> i32 {
    if encrypted.is_null() || encrypted_len <= 0 || output.is_null() || attestation.is_null() {
        return -1;
    }

    let enc = unsafe { std::slice::from_raw_parts(encrypted, encrypted_len as usize) };
    let ksk = if !kyber_sk.is_null() && kyber_sk_len > 0 {
        Some(unsafe { std::slice::from_raw_parts(kyber_sk, kyber_sk_len as usize) }.to_vec())
    } else {
        None
    };
    let mpk = if !mldsa65_pk.is_null() && mldsa65_pk_len > 0 {
        Some(
            unsafe { std::slice::from_raw_parts(mldsa65_pk, mldsa65_pk_len as usize) }.to_vec(),
        )
    } else {
        None
    };

    let (ksk, mpk) = match (ksk, mpk) {
        (Some(k), Some(m)) => (k, m),
        _ => return -2,
    };

    let open_key = seal::OpenKey {
        kyber_secret_key: ksk,
        mldsa65_public_key: mpk,
    };

    match seal::open(enc, &open_key) {
        Ok((plaintext, _module_id, _timestamp)) => {
            // Assume plaintext = original_data (8192) + attestation (32)
            let data_len = plaintext.len().min(8192);
            let dwords = data_len / 4;
            
            // Extract attestation
            let mut att_data = [0u8; 32];
            if plaintext.len() >= data_len + 32 {
                att_data.copy_from_slice(&plaintext[data_len..data_len+32]);
            }
            
            // Verify attestation
            if !verify_attestation(&att_data) {
                return 3; // Attestation verification failed
            }
            
            unsafe {
                std::ptr::copy_nonoverlapping(
                    plaintext.as_ptr() as *const u32,
                    output,
                    dwords,
                );
                if !output_dwords.is_null() {
                    *output_dwords = dwords as i32;
                }
                
                std::ptr::copy_nonoverlapping(
                    att_data.as_ptr(),
                    attestation,
                    32,
                );
            }
            0 // Clean
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("signature") { 1 } else { 2 }
        }
    }
}

/// Legacy wrapper: 8-arg vac_decrypt (no attestation output).
/// Calls vac_decrypt_with_attestation internally with a dummy attestation buffer.
/// Used by the C# plugin and older callers.
#[no_mangle]
pub extern "C" fn vac_decrypt(
    encrypted: *const u8,
    encrypted_len: i32,
    kyber_sk: *const u8,
    kyber_sk_len: i32,
    mldsa65_pk: *const u8,
    mldsa65_pk_len: i32,
    output: *mut u32,
    output_dwords: *mut i32,
) -> i32 {
    let mut dummy_attestation = [0u8; 32];
    vac_decrypt_with_attestation(
        encrypted, encrypted_len,
        kyber_sk, kyber_sk_len,
        mldsa65_pk, mldsa65_pk_len,
        output, output_dwords,
        dummy_attestation.as_mut_ptr(),
    )
}

/// Start the daemon TCP listener on a port.
/// Scheduler needs to be initialized first (call vac_init).
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn vac_server_listener_start(port: u16) -> i32 {
    if SCAN_SCHEDULER.lock().ok().and_then(|g| g.as_ref().map(|_| ())).is_none() {
        return -1;
    }
    if listener::start(port) {
        0
    } else {
        -2
    }
}

/// Stop the daemon TCP listener.
#[no_mangle]
pub extern "C" fn vac_server_listener_stop() -> i32 {
    listener::stop();
    0
}

/// Register a connected player for daemon authentication.
#[no_mangle]
pub extern "C" fn vac_server_register_client(
    steam_id_lo: u32,
    steam_id_hi: u32,
    player_name: *const u8,
    player_name_len: i32,
) -> i32 {
    if player_name.is_null() || player_name_len <= 0 {
        return -1;
    }
    let steam_id = (steam_id_hi as u64) << 32 | steam_id_lo as u64;
    let name = unsafe {
        std::slice::from_raw_parts(player_name, player_name_len as usize)
    };
    let name_str = String::from_utf8_lossy(name).to_string();
    listener::register_client(steam_id, &name_str);
    0
}

/// Unregister a disconnected player.
#[no_mangle]
pub extern "C" fn vac_server_unregister_client(
    steam_id_lo: u32,
    steam_id_hi: u32,
) -> i32 {
    let steam_id = (steam_id_hi as u64) << 32 | steam_id_lo as u64;
    listener::unregister_client(steam_id);
    0
}

/// Rust-friendly wrapper for testing without C FFI.
pub fn vac_init_rs(
    kyber_pk: &[u8], mldsa65_sk: &[u8],
    kyber_sk: &[u8], mldsa65_pk: &[u8],
) -> Result<(), i32> {
    let scheduler = scan_scheduler::ScanScheduler::new(
        kyber_pk.to_vec(), mldsa65_sk.to_vec(),
        kyber_sk.to_vec(), mldsa65_pk.to_vec(),
    );
    match SCAN_SCHEDULER.lock() {
        Ok(mut guard) => {
            *guard = Some(scheduler);
            Ok(())
        }
        Err(_) => Err(-1),
    }
}

/// Rust-friendly wrapper for testing without C FFI.
pub fn vac_shutdown_rs() {
    if let Ok(mut guard) = SCAN_SCHEDULER.lock() {
        *guard = None;
    }
}

/// Register the kick/ban callback invoked when ring-0 analysis detects a cheat.
/// callback: fn(steam_id_lo: u32, steam_id_hi: u32, reason: *const c_char)
/// Must be valid for the lifetime of the listener.
#[no_mangle]
pub extern "C" fn vac_server_set_kick_callback(callback: Option<extern "C" fn(u32, u32, *const std::ffi::c_char)>) -> i32 {
    match KICK_CALLBACK.lock() {
        Ok(mut guard) => {
            *guard = callback;
            0
        }
        Err(_) => -1,
    }
}

/// Rust-friendly wrapper to register a kick callback (no C FFI needed).
pub fn vac_set_kick_callback_rs(cb: extern "C" fn(u32, u32, *const std::ffi::c_char)) {
    if let Ok(mut guard) = KICK_CALLBACK.lock() {
        *guard = Some(cb);
    }
}

/// Report a cheat that was detected outside the listener (e.g., local scan).
/// This calls the registered kick callback if any.
#[no_mangle]
pub extern "C" fn vac_server_report_cheat(steam_id_lo: u32, steam_id_hi: u32, reason: *const std::ffi::c_char) -> i32 {
    let steam_id = (steam_id_hi as u64) << 32 | steam_id_lo as u64;
    let reason_str = if reason.is_null() {
        "unknown".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(reason) }
            .to_string_lossy()
            .to_string()
    };
    report_cheat(steam_id, &reason_str);
    0
}

/// Check if a daemon is currently connected for a player.
/// Returns 1 if connected, 0 otherwise.
#[no_mangle]
pub extern "C" fn vac_server_daemon_connected(
    steam_id_lo: u32,
    steam_id_hi: u32,
) -> i32 {
    let steam_id = (steam_id_hi as u64) << 32 | steam_id_lo as u64;
    if listener::is_connected(steam_id) { 1 } else { 0 }
}

/// Shutdown the VAC integrity system.
#[no_mangle]
pub extern "C" fn vac_shutdown() -> i32 {
    match SCAN_SCHEDULER.lock() {
        Ok(mut guard) => {
            *guard = None;
            0
        }
        Err(_) => -1,
    }
}
