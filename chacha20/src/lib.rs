use io_utils::ReadExt;
use std::io::{self, Read};

#[derive(Copy, Clone, Debug)]
struct State([u32; 16]);

// b"expand 32-byte k"
const C0: u32 = u32::from_le_bytes(*b"expa");
const C1: u32 = u32::from_le_bytes(*b"nd 3");
const C2: u32 = u32::from_le_bytes(*b"2-by");
const C3: u32 = u32::from_le_bytes(*b"te k");

#[allow(non_camel_case_types)]
pub type u96 = (u32, u32, u32);

impl State {
    fn new(key: &[u8; 32], b: u32, n: u96) -> Self {
        let mut res = [0; 16];
        res[0] = C0;
        res[1] = C1;
        res[2] = C2;
        res[3] = C3;

        bytemuck::must_cast_slice_mut(&mut res[4..12]).copy_from_slice(key.as_slice());

        res[12] = b;
        res[13] = n.0;
        res[14] = n.1;
        res[15] = n.2;

        Self(res)
    }

    fn quarter_round(&mut self, i: usize, j: usize, k: usize, l: usize) {
        let mut a = self.0[i];
        let mut b = self.0[j];
        let mut c = self.0[k];
        let mut d = self.0[l];

        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);

        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);

        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);

        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);

        self.0[i] = a;
        self.0[j] = b;
        self.0[k] = c;
        self.0[l] = d;
    }

    fn double_round(&mut self) {
        self.quarter_round(0, 4, 8, 12);
        self.quarter_round(1, 5, 9, 13);
        self.quarter_round(2, 6, 10, 14);
        self.quarter_round(3, 7, 11, 15);

        self.quarter_round(0, 5, 10, 15);
        self.quarter_round(1, 6, 11, 12);
        self.quarter_round(2, 7, 8, 13);
        self.quarter_round(3, 4, 9, 14);
    }

    fn block_round(&mut self) {
        let init = self.0;
        for _ in 0..10 {
            self.double_round();
        }
        self.0
            .iter_mut()
            .zip(init)
            .for_each(|(s, i)| *s = s.wrapping_add(i));
    }

    fn serialize(&self) -> &[u8; 64] {
        bytemuck::must_cast_ref(&self.0)
    }
}

pub fn block(key: &[u8; 32], counter: u32, nonce: u96) -> [u8; 64] {
    let mut state = State::new(key, counter, nonce);
    state.block_round();
    *state.serialize()
}

pub struct Cipher<R: Read> {
    key: [u8; 32],
    nonce: u96,
    reader: R,

    counter: u32,
    block: [u8; 64],
    pos: usize,
}

impl<R: Read> Read for Cipher<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= 64 {
            self.counter += 1;
            let n = self.reader.read_all(self.block.as_mut_slice())?;
            self.pos = 64 - n;

            self.block.copy_within(..n, self.pos);
            let data = block(&self.key, self.counter, self.nonce);
            self.block[self.pos..]
                .iter_mut()
                .zip(data)
                .for_each(|(d, c)| *d ^= c);
        }
        let n = (&self.block[self.pos..]).read(buf)?;
        self.pos += n;
        Ok(n)
    }
}

pub fn cipher<R: Read>(key: &[u8; 32], nonce: u96, input: R) -> Cipher<R> {
    Cipher {
        reader: input,
        key: *key,
        nonce,
        block: [0; 64],
        pos: 64,
        counter: 0,
    }
}

pub fn parse_nonce(data: &str) -> Result<u96, String> {
    let data: [u32; 3] = bytemuck::must_cast(
        io_utils::parse_hex::<12>(data)
            .ok_or_else(|| "Invalid nonce: must be a 12 bytes hex number".to_string())?,
    );
    let data = data.map(u32::to_le);

    Ok((data[0], data[1], data[2]))
}

#[cfg(test)]
#[test]
fn chacha20() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let b = 1;

    let n = (
        u32::from_le_bytes([0x00, 0x00, 0x00, 0x09]),
        u32::from_le_bytes([0x00, 0x00, 0x00, 0x4a]),
        u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
    );

    let end_block = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];

    let mut state = State::new(&key, b, n);
    state.block_round();

    assert_eq!(state.serialize(), &end_block);
}
