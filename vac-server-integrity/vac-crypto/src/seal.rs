use std::io::{self, Write};

use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKey, SecretKey as SignSecretKey};

pub const MAGIC: u32 = 0x56414349;
pub const KYBER_CT_LEN: usize = 1088;
pub const AES_NONCE_LEN: usize = 12;
pub const AES_TAG_LEN: usize = 16;
pub const MLDSA_65_SIG_LEN: usize = 3293;
pub const HEADER_LEN: usize = 16;

pub struct SealedPayload {
    pub raw: Vec<u8>,
}

pub struct SealKey {
    pub kyber_public_key: Vec<u8>,
    pub mldsa65_secret_key: Vec<u8>,
}

pub struct OpenKey {
    pub kyber_secret_key: Vec<u8>,
    pub mldsa65_public_key: Vec<u8>,
}

pub fn seal(data: &[u8], module_id: u32, key: &SealKey) -> io::Result<SealedPayload> {
    let total = HEADER_LEN + KYBER_CT_LEN + AES_NONCE_LEN + AES_TAG_LEN + data.len() + MLDSA_65_SIG_LEN;
    let mut payload = Vec::with_capacity(total);

    payload.write_all(&MAGIC.to_le_bytes())?;
    payload.write_all(&module_id.to_le_bytes())?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    payload.write_all(&ts.to_le_bytes())?;

    let kyber_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(key.kyber_public_key.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad kyber pk: {:?}", e)))?;
    let (shared_secret, ct) = pqcrypto_kyber::kyber768::encapsulate(&kyber_pk);
    payload.write_all(ct.as_bytes())?;

    let ss = shared_secret.as_bytes();

    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{AeadInPlace, KeyInit};

    let aes_key = Key::<Aes256Gcm>::from_slice(ss);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    payload.write_all(&nonce_bytes)?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ct_data = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut ct_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("aes encrypt failed: {:?}", e)))?;

    payload.write_all(&tag)?;
    payload.write_all(&ct_data)?;

    let dsa_sk = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(key.mldsa65_secret_key.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad dsa sk: {:?}", e)))?;
    let sig = pqcrypto_dilithium::dilithium3::detached_sign(payload.as_slice(), &dsa_sk);
    payload.write_all(sig.as_bytes())?;

    Ok(SealedPayload { raw: payload })
}

pub fn open(payload: &[u8], key: &OpenKey) -> io::Result<(Vec<u8>, u32, u64)> {
    let min_len = HEADER_LEN + KYBER_CT_LEN + AES_NONCE_LEN + AES_TAG_LEN + MLDSA_65_SIG_LEN;
    if payload.len() < min_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload too short"));
    }

    let mut off = 0;

    let magic = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
    if magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    off += 4;

    let module_id = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
    off += 4;

    let timestamp = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
    off += 8;

    let sig_start = payload.len() - MLDSA_65_SIG_LEN;
    let signed_data = &payload[..sig_start];
    let signature_bytes = &payload[sig_start..];

    let dsa_pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(key.mldsa65_public_key.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad dsa pk: {:?}", e)))?;
    let sig = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad sig: {:?}", e)))?;
    if pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, signed_data, &dsa_pk).is_err() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ML-DSA-65 signature invalid"));
    }

    let kyber_ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&payload[off..off + KYBER_CT_LEN])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad kyber ct: {:?}", e)))?;
    off += KYBER_CT_LEN;

    let nonce_bytes: [u8; AES_NONCE_LEN] = payload[off..off + AES_NONCE_LEN].try_into().unwrap();
    off += AES_NONCE_LEN;

    let tag_bytes: [u8; AES_TAG_LEN] = payload[off..off + AES_TAG_LEN].try_into().unwrap();
    off += AES_TAG_LEN;

    let aes_ct = &payload[off..sig_start];

    let kyber_sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(key.kyber_secret_key.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad kyber sk: {:?}", e)))?;
    let shared_secret = pqcrypto_kyber::kyber768::decapsulate(&kyber_ct, &kyber_sk);
    let ss = shared_secret.as_bytes();

    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{AeadInPlace, KeyInit};

    let aes_key = Key::<Aes256Gcm>::from_slice(ss);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut pt = aes_ct.to_vec();
    let tag = aes_gcm::Tag::from_slice(&tag_bytes);
    cipher
        .decrypt_in_place_detached(&nonce, b"", &mut pt, &tag)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AES-GCM decryption failed"))?;

    Ok((pt, module_id, timestamp))
}
