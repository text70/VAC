const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn left_rotate(x: u32, c: u32) -> u32 {
    (x << c) | (x >> (32 - c))
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    let msg = pad_message(data);
    let mut i = 0;
    while i < msg.len() {
        let mut m = [0u32; 16];
        for j in 0..16 {
            m[j] = msg[i + j * 4] as u32
                | (msg[i + j * 4 + 1] as u32) << 8
                | (msg[i + j * 4 + 2] as u32) << 16
                | (msg[i + j * 4 + 3] as u32) << 24;
        }

        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);

        for j in 0..64 {
            let (f, g) = match j {
                0..=15 => ((bb & cc) | (!bb & dd), j),
                16..=31 => ((dd & bb) | (!dd & cc), (5 * j + 1) % 16),
                32..=47 => (bb ^ cc ^ dd, (3 * j + 5) % 16),
                _ => (cc ^ (bb | !dd), (7 * j) % 16),
            };

            let temp = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(
                left_rotate(aa.wrapping_add(f).wrapping_add(K[j]).wrapping_add(m[g]), S[j]),
            );
            aa = temp;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);

        i += 64;
    }

    let mut result = [0u8; 16];
    for (i, v) in [a, b, c, d].iter().enumerate() {
        result[i * 4] = *v as u8;
        result[i * 4 + 1] = (*v >> 8) as u8;
        result[i * 4 + 2] = (*v >> 16) as u8;
        result[i * 4 + 3] = (*v >> 24) as u8;
    }
    result
}

fn pad_message(data: &[u8]) -> Vec<u8> {
    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() * 8) % 512 != 448 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());
    msg
}
