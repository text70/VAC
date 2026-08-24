use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk};
use pqcrypto_traits::sign::{PublicKey as SignPk, SecretKey as SignSk};
use vac_core::buffer::DataBuffer;
use vac_core::crc32::crc32_bytes;
use vac_core::hash::vac_hash;
use vac_core::ice::IceKey;
use vac_core::md5::md5;
use vac_core::module::{Module, ScanReport};

fn main() {
    println!("=== VacIntegrity Test Harness ===\n");

    // 1. Core primitives
    test_crc32();
    test_md5();
    test_vac_hash();
    test_ice();
    test_databuffer();

    // 2. Module scans
    test_module(1, "SystemInfo", vac_module_systeminfo::SystemInfoModule);
    test_module(2, "ProcessHandleList", vac_module_processhandle::ProcessHandleListModule);
    test_module(3, "ProcessMonitor", vac_module_processmonitor::ProcessMonitorModule);
    test_module(4, "DeviceInfo", vac_module_deviceinfo::DeviceInfoModule);
    test_module(5, "DriverInfo", vac_module_driverinfo::DriverInfoModule);
    test_module(6, "ReadModules", vac_module_readmodules::ReadModulesModule);

    // 3. Seal round-trip
    test_seal();
    test_seal_unsigned();

    // 4. Full end-to-end via host
    test_via_host();

    // 5. Client-side scan modules
    test_client_scan();

    // 6. Enrollment token lifecycle
    test_token_flow();

    println!("\n=== All tests passed ===");
}

fn test_crc32() {
    let data = b"hello world";
    let hash = crc32_bytes(data);
    assert_ne!(hash, 0, "CRC32 should not be zero");
    println!("[PASS] CRC32: {:#010x}", hash);
}

fn test_md5() {
    let data = b"hello world";
    let hash = md5(data);
    assert_eq!(hash.len(), 16, "MD5 must be 16 bytes");
    println!("[PASS] MD5: {}", hex::encode(&hash));
}

fn test_vac_hash() {
    let h1 = vac_hash(b"test");
    let h2 = vac_hash(b"test");
    assert_eq!(h1, h2, "vac_hash must be deterministic");
    assert_ne!(h1, 0, "vac_hash should not be zero");
    println!("[PASS] vac_hash: {:#010x}", h1);
}

fn test_ice() {
    let key = [0xDEu8; 16];
    let ice = IceKey::new(&key);

    let pt = b"HelloVAC";
    let ct = ice.encrypt(pt);
    assert_ne!(ct, pt, "ICE must change data");

    let decrypted = ice.decrypt(&ct);
    assert_eq!(decrypted, pt, "ICE round-trip must restore plaintext");

    println!("[PASS] ICE cipher");
}

fn test_databuffer() {
    let mut buf = DataBuffer::new();
    assert_eq!(buf.cursor(), 0, "fresh buffer cursor at 0");

    buf.write_u32(42);
    assert_eq!(buf.cursor(), 1, "after one write, cursor at 1");

    buf.reset();
    assert_eq!(buf.cursor(), 0, "reset sets cursor to 0");

    // 2048 u32s fit without overflow
    for i in 0..2048 {
        buf.write_u32(i);
    }
    assert_eq!(buf.cursor(), 2048, "2048 writes fills buffer");
    buf.write_u32(9999); // should be silently dropped
    assert_eq!(buf.cursor(), 2048, "extra writes silently dropped");

    println!("[PASS] DataBuffer");
}

fn test_seal() {
    let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
    let (dsa_pk, dsa_sk) = pqcrypto_dilithium::dilithium3::keypair();

    let seal_key = vac_crypto::seal::SealKey {
        kyber_public_key: pk.as_bytes().to_vec(),
        mldsa65_secret_key: Some(dsa_sk.as_bytes().to_vec()),
    };
    let open_key = vac_crypto::seal::OpenKey {
        kyber_secret_key: sk.as_bytes().to_vec(),
        mldsa65_public_key: dsa_pk.as_bytes().to_vec(),
    };

    let plaintext = b"Hello VAC integrity check payload!";
    let sealed = vac_crypto::seal::seal(plaintext, 42, &seal_key)
        .expect("seal failed");
    assert!(sealed.raw.len() > plaintext.len(), "sealed data must be larger");

    let (opened, module_id, _ts) = vac_crypto::seal::open(&sealed.raw, &open_key)
        .expect("open failed");
    assert_eq!(module_id, 42, "module_id round-trips");
    assert_eq!(&opened, &plaintext, "seal round-trip must restore plaintext");

    println!("[PASS] PQC seal round-trip ({} sealed -> {} opened)",
        sealed.raw.len(), opened.len());
}

fn test_seal_unsigned() {
    // Client-mode seal: no signing key available. Payload must still encrypt,
    // decrypt, and carry the unsigned flag in the wire module id.
    let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
    let (dsa_pk, _dsa_sk) = pqcrypto_dilithium::dilithium3::keypair();

    let seal_key = vac_crypto::seal::SealKey {
        kyber_public_key: pk.as_bytes().to_vec(),
        mldsa65_secret_key: None,
    };
    let open_key = vac_crypto::seal::OpenKey {
        kyber_secret_key: sk.as_bytes().to_vec(),
        mldsa65_public_key: dsa_pk.as_bytes().to_vec(),
    };

    let plaintext = vec![0xABu8; 1024];
    let sealed = vac_crypto::seal::seal(&plaintext, 203, &seal_key)
        .expect("unsigned seal failed");

    // Unsigned payload must be shorter than a signed one (no 3293-byte sig)
    assert_eq!(sealed.raw.len(), 16 + 1088 + 12 + 16 + plaintext.len(),
        "unsigned payload has header+ct+nonce+tag+data only");

    let (opened, module_id, _ts) = vac_crypto::seal::open(&sealed.raw, &open_key)
        .expect("unsigned open failed");
    assert_eq!(module_id, 203, "unsigned flag stripped from returned mid");
    assert_eq!(opened, plaintext, "unsigned round-trip must restore plaintext");

    // Tampering with ciphertext must break AES-GCM integrity
    let mut tampered = sealed.raw.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(vac_crypto::seal::open(&tampered, &open_key).is_err(),
        "tampered unsigned payload must fail to open");

    println!("[PASS] PQC unsigned client seal ({} bytes, tamper-detected)", sealed.raw.len());
}

fn test_module<T: Module>(module_id: u32, name: &str, mut module: T) {
    let mut report = ScanReport::new(module_id);
    module.scan(&mut report);

    let data_len = report.data.cursor();
    let first_sum: u64 = report.data.raw.iter().take(16).map(|x| *x as u64).sum();

    println!("[PASS] {} (id={}): {} u32s written, first 16 sum = {}",
        name, module_id, data_len, first_sum);
}

fn test_via_host() {
    let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
    let (dsa_pk, dsa_sk) = pqcrypto_dilithium::dilithium3::keypair();

    let result = vac_integrity::vac_init_rs(
        pk.as_bytes(), dsa_sk.as_bytes(),
        sk.as_bytes(), dsa_pk.as_bytes(),
    );
    assert!(result.is_ok(), "vac_init_rs should succeed");

    // Test vac_scan + vac_decrypt round trip
    let mut output_len: i32 = 65536;
    let mut output = vec![0u8; output_len as usize];
    let rc = vac_integrity::vac_scan(
        1,
        output.as_mut_ptr(),
        &mut output_len as *mut i32,
    );
    assert_eq!(rc, 0, "vac_scan should succeed, got {}", rc);
    assert!(output_len > 0, "should have output");

    // Decrypt the scan result using the new attestation-aware API
    let mut dwords = 2048i32;
    let mut decrypted = vec![0u32; 2048];
    let mut attestation = vec![0u8; 32];
    
    let dc = vac_integrity::vac_decrypt_with_attestation(
        output.as_ptr(),
        output_len,
        sk.as_bytes().as_ptr(), sk.as_bytes().len() as i32,
        dsa_pk.as_bytes().as_ptr(), dsa_pk.as_bytes().len() as i32,
        decrypted.as_mut_ptr(),
        &mut dwords as *mut i32,
        attestation.as_mut_ptr(),
    );
    assert_eq!(dc, 0, "vac_decrypt_with_attestation should succeed, got {}", dc);
    assert!(dwords > 0, "should have decrypted dwords");
    // First byte = 1 indicates hardware presence flag (kernel module not loaded)
    assert_eq!(attestation[0], 1, "presence flag should be 1");
    assert!(attestation.iter().skip(1).all(|&b| b == 0), "bytes 1-31 should be zero");

    println!("[PASS] vac_integrity::vac_init_rs + vac_scan + vac_decrypt_with_attestation ({} sealed, {} dwords, {} attestation bytes)",
        output_len, dwords, attestation.len());

    vac_integrity::vac_shutdown_rs();
    println!("[PASS] vac_integrity::vac_shutdown_rs");
}

fn test_client_scan() {
    use vac_client_core::run_module;
    use vac_core::buffer::DataBuffer;
    use vac_crypto::seal;

    let sys = vac_sys::linux::LinuxSystem::new();
    let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
    let (dsa_pk, _dsa_sk) = pqcrypto_dilithium::dilithium3::keypair();

    for module_id in 1..=6 {
        let mut buf = DataBuffer::new();
        run_module(module_id, &sys, &mut buf);

        let written = buf.cursor();
        assert!(written > 0, "client module {} must write data", module_id);

        // Seal the data to verify round-trip
        let data_slice = unsafe {
            std::slice::from_raw_parts(
                buf.raw.as_ptr() as *const u8,
                buf.raw.len() * 4,
            )
        };
        let seal_key = seal::SealKey {
            kyber_public_key: pk.as_bytes().to_vec(),
            mldsa65_secret_key: None,
        };
        let open_key = seal::OpenKey {
            kyber_secret_key: sk.as_bytes().to_vec(),
            mldsa65_public_key: dsa_pk.as_bytes().to_vec(),
        };

        let sealed = seal::seal(data_slice, module_id + 100, &seal_key)
            .expect("client seal failed");
        let (opened, _mid, _ts) = seal::open(&sealed.raw, &open_key)
            .expect("client open failed");

        // Verify data integrity
        let opened_slice = unsafe {
            std::slice::from_raw_parts(
                opened.as_ptr() as *const u32,
                opened.len() / 4,
            )
        };
        let match_count = buf.raw.iter()
            .zip(opened_slice.iter())
            .filter(|(a, b)| a == b)
            .count();
        assert!(match_count >= written, "client module {}: opened data must match ({} matches)", module_id, match_count);

        println!("[PASS] Client scan module {} ({} dwords written, {} sealed bytes, {} matches)",
            module_id, written, sealed.raw.len(), match_count);
    }
}

fn test_token_flow() {
    use vac_integrity::{
        vac_client_token_rs, vac_ensure_client_token_rs, vac_listener_start_rs,
        vac_listener_stop_rs, vac_register_client_rs, vac_set_token_db_path_rs,
    };

    let dir = std::env::temp_dir().join(format!("vac-tok-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("tokens.db");
    vac_set_token_db_path_rs(db.to_str().unwrap());

    assert!(vac_listener_start_rs(0), "listener should start on port 0");
    let sid = 76561198000000001u64;

    // Unregistered players have no tokens
    assert!(vac_ensure_client_token_rs(sid).is_none(), "ensure on unregistered must fail");
    assert!(vac_client_token_rs(sid).is_none(), "no token for unregistered");

    // Register, then enroll: 32-hex token
    vac_register_client_rs(sid, "tok_player");
    let t1 = vac_ensure_client_token_rs(sid).expect("enrollment must produce a token");
    assert_eq!(t1.len(), 32, "token is 32 hex chars");

    // Stable across repeated calls and re-registration (player relog)
    assert_eq!(vac_ensure_client_token_rs(sid).as_deref(), Some(t1.as_str()),
        "repeated ensure must be stable");
    vac_register_client_rs(sid, "tok_player_relog");
    assert_eq!(vac_client_token_rs(sid).as_deref(), Some(t1.as_str()),
        "relog re-registration must preserve the enrollment token");
    vac_listener_stop_rs();

    // Persistence: a fresh listener must reuse the stored token from disk
    assert!(vac_listener_start_rs(0), "listener restart");
    vac_register_client_rs(sid, "tok_player_after_restart");
    let t2 = vac_ensure_client_token_rs(sid).expect("token after restart");
    assert_eq!(t1, t2, "enrollment token must survive listener restart via db file");
    vac_listener_stop_rs();

    let _ = std::fs::remove_dir_all(&dir);
    println!("[PASS] Enrollment token lifecycle (generate/stable/relog/restart)");
}
