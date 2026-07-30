#[cfg(windows)]
use vac_client_core::run_module;
#[cfg(windows)]
use vac_core::buffer::DataBuffer;
use vac_core::buffer::DATA_BUFFER_DWORDS;
#[cfg(windows)]
use vac_crypto::seal;
use vac_crypto::seal::{HEADER_LEN, AES_NONCE_LEN, AES_TAG_LEN, KYBER_CT_LEN, MLDSA_65_SIG_LEN};

#[no_mangle]
pub extern "C" fn vac_client_init(
    _kyber_pk: *const u8,
    _kyber_pk_len: i32,
    _mldsa65_sk: *const u8,
    _mldsa65_sk_len: i32,
) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn vac_client_scan(
    module_id: u32,
    kyber_pk: *const u8,
    kyber_pk_len: i32,
    mldsa65_sk: *const u8,
    mldsa65_sk_len: i32,
    output: *mut u8,
    output_len: *mut i32,
) -> i32 {
    if output.is_null() || output_len.is_null() {
        return -1;
    }
    if kyber_pk.is_null() || mldsa65_sk.is_null() {
        return -2;
    }
    if module_id < 1 || module_id > 6 {
        return -3;
    }

    let capacity = unsafe { *output_len as i32 as usize };
    let min_capacity = HEADER_LEN + KYBER_CT_LEN + AES_NONCE_LEN + AES_TAG_LEN
        + (DATA_BUFFER_DWORDS * 4) + MLDSA_65_SIG_LEN;
    if capacity < min_capacity {
        return -4;
    }

    // Platform-specific implementation
    #[cfg(not(windows))]
    {
        let _ = (kyber_pk, kyber_pk_len, mldsa65_sk, mldsa65_sk_len);
        return -6;
    }

    #[cfg(windows)]
    {
        let kpk = unsafe { std::slice::from_raw_parts(kyber_pk, kyber_pk_len as usize) }.to_vec();
        let dsk = unsafe { std::slice::from_raw_parts(mldsa65_sk, mldsa65_sk_len as usize) }.to_vec();

        let sys = vac_sys::win32::Win32System::new();
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
            mldsa65_secret_key: dsk,
        };

        match seal::seal(data_slice, module_id + 100, &seal_key) {
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
}

#[no_mangle]
pub extern "C" fn vac_client_shutdown() -> i32 {
    0
}
