use std::fmt;

pub const DATA_BUFFER_DWORDS: usize = 2048;

pub struct DataBuffer {
    pub raw: [u32; DATA_BUFFER_DWORDS],
    cursor: usize,
}

impl DataBuffer {
    pub fn new() -> Self {
        Self {
            raw: [0u32; DATA_BUFFER_DWORDS],
            cursor: 0,
        }
    }

    pub fn reset(&mut self) {
        self.raw.fill(0);
        self.cursor = 0;
    }

    pub fn write_u32(&mut self, val: u32) {
        if self.cursor < DATA_BUFFER_DWORDS {
            self.raw[self.cursor] = val;
            self.cursor += 1;
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(4) {
            let mut val: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                val |= (b as u32) << (i * 8);
            }
            self.write_u32(val);
        }
    }

    pub fn write_slice(&mut self, src: &[u32]) {
        let count = src.len().min(DATA_BUFFER_DWORDS - self.cursor);
        self.raw[self.cursor..self.cursor + count].copy_from_slice(&src[..count]);
        self.cursor += count;
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn set_cursor(&mut self, pos: usize) {
        self.cursor = pos.min(DATA_BUFFER_DWORDS);
    }

    pub fn as_bytes(&self) -> &[u8] {
        let len = DATA_BUFFER_DWORDS * 4;
        unsafe { std::slice::from_raw_parts(self.raw.as_ptr() as *const u8, len) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let len = DATA_BUFFER_DWORDS * 4;
        unsafe { std::slice::from_raw_parts_mut(self.raw.as_mut_ptr() as *mut u8, len) }
    }

    pub fn encrypt_xor(&mut self, key: u32) {
        for val in self.raw.iter_mut() {
            *val ^= key;
        }
    }

    pub fn size_in_bytes(&self) -> usize {
        DATA_BUFFER_DWORDS * 4
    }
}

impl Default for DataBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DataBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataBuffer(cursor={})", self.cursor)
    }
}
