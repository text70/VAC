use vac_crypto::seal;

pub struct ScanScheduler {
    pub kyber_pk: Vec<u8>,
    pub mldsa65_sk: Vec<u8>,
    pub kyber_sk: Vec<u8>,
    pub mldsa65_pk: Vec<u8>,
}

impl ScanScheduler {
    pub fn new(
        kyber_pk: Vec<u8>, mldsa65_sk: Vec<u8>,
        kyber_sk: Vec<u8>, mldsa65_pk: Vec<u8>,
    ) -> Self {
        Self { kyber_pk, mldsa65_sk, kyber_sk, mldsa65_pk }
    }

    pub fn open_key(&self) -> seal::OpenKey {
        seal::OpenKey {
            kyber_secret_key: self.kyber_sk.clone(),
            mldsa65_public_key: self.mldsa65_pk.clone(),
        }
    }
}
