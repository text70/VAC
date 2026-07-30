// djb2-style hash used by original VAC
pub fn vac_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x45D71892;
    for &b in data {
        hash = ((b | 32) as u32).wrapping_add(33u32.wrapping_mul(hash));
    }
    hash
}

pub fn vac_hash_str(s: &str) -> u32 {
    vac_hash(s.as_bytes())
}
