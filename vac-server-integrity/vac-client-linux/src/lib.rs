use vac_client_core::run_module;
use vac_core::buffer::{DataBuffer, DATA_BUFFER_DWORDS};
use vac_crypto::seal;
use vac_crypto::seal::{HEADER_LEN, AES_NONCE_LEN, AES_TAG_LEN, KYBER_CT_LEN};

/// Initialize the client scanner. Kept for ABI compatibility; no keys are
/// stored client-side anymore.
///
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn vac_client_init() -> i32 {
    0
}

/// Run a client-side scan module and return the sealed result.
///
/// Results are sealed encryption-only (Kyber-768 + AES-256-GCM): clients never
/// receive signing key material. Integrity is enforced by the AES-GCM tag and
/// the server's per-scan challenge nonce.
///
/// module_id: which scan module to run (1-6, or 10 = game memory scan)
/// kyber_pk: Kyber-768 public key bytes
/// kyber_pk_len: length in bytes
/// output: buffer receiving the sealed wire-format payload
/// output_len: in = capacity, out = bytes written
///
/// Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn vac_client_scan(
    module_id: u32,
    kyber_pk: *const u8,
    kyber_pk_len: i32,
    output: *mut u8,
    output_len: *mut i32,
) -> i32 {
    if output.is_null() || output_len.is_null() {
        return -1;
    }
    if kyber_pk.is_null() {
        return -2;
    }
    if (module_id < 1 || module_id > 6) && module_id != 10 {
        return -3;
    }

    let capacity = unsafe { *output_len as usize };
    let min_capacity = HEADER_LEN + KYBER_CT_LEN + AES_NONCE_LEN + AES_TAG_LEN
        + (DATA_BUFFER_DWORDS * 4);
    if capacity < min_capacity {
        return -4;
    }

    let kpk = unsafe { std::slice::from_raw_parts(kyber_pk, kyber_pk_len as usize) }.to_vec();

    let sys = vac_sys::linux::LinuxSystem::new();
    let mut buf = DataBuffer::new();

    run_module(module_id, &sys, &mut buf);

    let data_slice = unsafe {
        std::slice::from_raw_parts(
            buf.raw.as_ptr() as *const u8,
            buf.raw.len() * 4,
        )
    };

    let seal_key = seal::SealKey {
        kyber_public_key: kpk,
        mldsa65_secret_key: None,
    };

    let seal_mid = if module_id == 10 { 203 } else { module_id + 100 };

    match seal::seal(data_slice, seal_mid, &seal_key) {
        Ok(sealed) => {
            let write_len = sealed.raw.len().min(capacity);
            unsafe {
                std::ptr::copy_nonoverlapping(sealed.raw.as_ptr(), output, write_len);
                *output_len = write_len as i32;
            }
            0
        }
        Err(_) => -5,
    }
}

/// Shutdown the client scanner.
#[no_mangle]
pub extern "C" fn vac_client_shutdown() -> i32 {
    0
}
