const PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000,
    0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000,
    0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000,
    0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000,
    0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

const SMOD: [[u32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

const SXOR: [[u32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

const KEYROT: [i32; 16] = [
    0, 1, 2, 3, 2, 1, 3, 0,
    1, 3, 2, 0, 3, 1, 0, 2,
];

fn perm32(x: u32) -> u32 {
    let mut result = 0;
    let mut x = x;
    let mut pidx = 0;
    while x != 0 {
        if x & 1 != 0 {
            result |= PBOX[pidx];
        }
        pidx += 1;
        x >>= 1;
    }
    result
}

fn gf_mul(a: u32, b: u32, m: u32) -> u32 {
    let mut result = 0;
    let mut a = a;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a <<= 1;
        b >>= 1;
        if a >= 256 {
            a ^= m;
        }
    }
    result
}

fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let x = gf_mul(b, b, m);
    let x = gf_mul(b, x, m);
    let x = gf_mul(x, x, m);
    gf_mul(b, x, m)
}

fn init_sboxes() -> [[u32; 1024]; 4] {
    let mut sbox = [[0u32; 1024]; 4];
    for i in 0..1024 {
        let col = (i >> 1) & 0xff;
        let row = (i & 1) | ((i & 0x200) >> 8);
        let x = gf_exp7(col as u32 ^ SXOR[0][row], SMOD[0][row]) << 24;
        sbox[0][i] = perm32(x);
        let x = gf_exp7(col as u32 ^ SXOR[1][row], SMOD[1][row]) << 16;
        sbox[1][i] = perm32(x);
        let x = gf_exp7(col as u32 ^ SXOR[2][row], SMOD[2][row]) << 8;
        sbox[2][i] = perm32(x);
        let x = gf_exp7(col as u32 ^ SXOR[3][row], SMOD[3][row]);
        sbox[3][i] = perm32(x);
    }
    sbox
}

fn ice_f(p: u32, sk: &[u32; 3], sbox: &[[u32; 1024]; 4]) -> u32 {
    let tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00);
    let tr = (p & 0x3ff) | ((p << 2) & 0xffc00);
    let mix = sk[2] & (tl ^ tr);
    let al = tr ^ mix;
    let ar = tl ^ mix;
    let al = al ^ sk[0];
    let ar = ar ^ sk[1];
    sbox[0][((al >> 10) & 0x3ff) as usize]
        | sbox[1][(al & 0x3ff) as usize]
        | sbox[2][((ar >> 10) & 0x3ff) as usize]
        | sbox[3][(ar & 0x3ff) as usize]
}

pub struct IceKey {
    rounds: usize,
    keys: Vec<[u32; 3]>,
}

impl IceKey {
    pub fn new(key: &[u8]) -> Self {
        let rounds = 16;
        let keys = Self::schedule(key, rounds);
        IceKey { rounds, keys }
    }

    fn schedule(key: &[u8], rounds: usize) -> Vec<[u32; 3]> {
        let mut keys = vec![[0u32; 3]; rounds];
        for i in 0..(key.len() / 8) {
            let mut kb = [0u16; 4];
            for j in 0..4 {
                kb[3 - j] = (key[i * 8 + j * 2] as u16) << 8 | key[i * 8 + j * 2 + 1] as u16;
            }
            Self::schedule_build(&mut keys, &mut kb, i * 8, &KEYROT);
            Self::schedule_build(&mut keys, &mut kb, rounds - 8 - i * 8, &KEYROT[8..]);
        }
        keys
    }

    fn schedule_build(keys: &mut [[u32; 3]], kb: &mut [u16; 4], n: usize, keyrot: &[i32]) {
        for i in 0..8 {
            let subkey = &mut keys[n + i];
            for j in 0..15 {
                let idx = j % 3;
                for k in 0..4 {
                    let kridx = ((keyrot[i] + k) & 3) as usize;
                    let bit = kb[kridx] & 1;
                    subkey[idx] = (subkey[idx] << 1) | bit as u32;
                    kb[kridx] = (kb[kridx] >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    pub fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
        let sbox = init_sboxes();
        let mut ct = pt.to_vec();
        for chunk in ct.chunks_mut(8) {
            if chunk.len() < 8 {
                break;
            }
            let mut l = chunk[3] as u32
                | ((chunk[2] as u32)
                    | ((chunk[1] as u32) | (chunk[0] as u32) << 8) << 8)
                    << 8;
            let mut r = chunk[7] as u32
                | ((chunk[6] as u32)
                    | ((chunk[5] as u32) | (chunk[4] as u32) << 8) << 8)
                    << 8;
            for i in (0..self.rounds).step_by(2) {
                l ^= ice_f(r, &self.keys[i], &sbox);
                r ^= ice_f(l, &self.keys[i + 1], &sbox);
            }
            for i in 0..4 {
                chunk[3 - i] = (r & 0xff) as u8;
                chunk[7 - i] = (l & 0xff) as u8;
                r >>= 8;
                l >>= 8;
            }
        }
        ct
    }

    pub fn decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let sbox = init_sboxes();
        let mut pt = ct.to_vec();
        for chunk in pt.chunks_mut(8) {
            if chunk.len() < 8 {
                break;
            }
            let mut l = chunk[3] as u32
                | ((chunk[2] as u32)
                    | ((chunk[1] as u32) | (chunk[0] as u32) << 8) << 8)
                    << 8;
            let mut r = chunk[7] as u32
                | ((chunk[6] as u32)
                    | ((chunk[5] as u32) | (chunk[4] as u32) << 8) << 8)
                    << 8;
            let mut i = self.rounds - 1;
            loop {
                l ^= ice_f(r, &self.keys[i], &sbox);
                if i == 0 {
                    break;
                }
                r ^= ice_f(l, &self.keys[i - 1], &sbox);
                if i == 1 {
                    break;
                }
                i -= 2;
            }
            for i in 0..4 {
                chunk[3 - i] = (r & 0xff) as u8;
                chunk[7 - i] = (l & 0xff) as u8;
                r >>= 8;
                l >>= 8;
            }
        }
        pt
    }
}
