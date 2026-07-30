use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk};
use pqcrypto_traits::sign::{PublicKey as SignPk, SecretKey as SignSk};
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let out_path = Path::new(&out_dir);

    println!("Generating PQC key material in: {}", out_path.display());

    // ML-KEM-768 (Kyber) keypair
    println!("  Generating ML-KEM-768 keypair...");
    let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
    let kyber_pk_path = out_path.join("kyber_public.der");
    let kyber_sk_path = out_path.join("kyber_secret.der");
    fs::write(&kyber_pk_path, kyber_pk.as_bytes()).expect("write kyber pk");
    fs::write(&kyber_sk_path, kyber_sk.as_bytes()).expect("write kyber sk");
    println!("    Public key:  {} ({})", kyber_pk_path.display(), kyber_pk.as_bytes().len());
    println!("    Secret key:  {} ({})", kyber_sk_path.display(), kyber_sk.as_bytes().len());

    // ML-DSA-65 (Dilithium3) keypair
    println!("  Generating ML-DSA-65 keypair...");
    let (dsa_pk, dsa_sk) = pqcrypto_dilithium::dilithium3::keypair();
    let dsa_pk_path = out_path.join("mldsa65_public.der");
    let dsa_sk_path = out_path.join("mldsa65_secret.der");
    fs::write(&dsa_pk_path, dsa_pk.as_bytes()).expect("write dsa pk");
    fs::write(&dsa_sk_path, dsa_sk.as_bytes()).expect("write dsa sk");
    println!("    Public key:  {} ({})", dsa_pk_path.display(), dsa_pk.as_bytes().len());
    println!("    Secret key:  {} ({})", dsa_sk_path.display(), dsa_sk.as_bytes().len());

    println!("Done. Deploy these to the server:");
    println!("  Server side (server/carbon/native/):");
    println!("    kyber_public.der   ← used by vac_init() for encryption");
    println!("    mldsa65_secret.der  ← used by vac_init() for signing");
    println!("  Decryption side (monitoring service):");
    println!("    kyber_secret.der    ← used to decrypt scan results");
    println!("    mldsa65_public.der  ← used to verify scan signatures");
}
