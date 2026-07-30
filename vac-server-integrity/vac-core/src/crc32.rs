// CRC32 with custom polynomial 0x488781ED (matches original VAC)
pub fn crc32(data: &[u8], initial: u32) -> u32 {
    let mut hash = initial;
    for &byte in data {
        hash ^= (byte as u32) << 24;
        for _ in 0..8 {
            if hash & (1 << 31) != 0 {
                hash = (hash << 2) ^ 0x488781ED;
            } else {
                hash <<= 2;
            }
        }
    }
    hash
}

pub fn crc32_bytes(data: &[u8]) -> u32 {
    crc32(data, 0)
}
