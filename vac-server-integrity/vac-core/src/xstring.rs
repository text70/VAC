pub struct XorString<const N: usize> {
    data: [u8; N],
    key: u8,
    decoded: [u8; N],
}

impl<const N: usize> XorString<N> {
    pub fn new(encoded: [u8; N], key: u8) -> Self {
        let mut s = Self {
            data: encoded,
            key,
            decoded: [0u8; N],
        };
        s.decode();
        s
    }

    fn decode(&mut self) {
        for i in 0..N {
            self.decoded[i] = self.data[i] ^ self.key;
        }
    }

    pub fn as_str(&self) -> &str {
        let len = self
            .decoded
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(N);
        std::str::from_utf8(&self.decoded[..len]).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        let len = self
            .decoded
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(N);
        &self.decoded[..len]
    }
}

#[macro_export]
macro_rules! xstr {
    ($s:literal, $key:expr) => {{
        const BYTES: &[u8] = $s.as_bytes();
        const N: usize = BYTES.len() + 1;
        let mut enc = [0u8; N];
        let mut i = 0;
        while i < BYTES.len() {
            enc[i] = BYTES[i] ^ $key;
            i += 1;
        }
        enc[i] = 0 ^ $key;
        $crate::xstring::XorString::<N>::new(enc, $key)
    }};
}
