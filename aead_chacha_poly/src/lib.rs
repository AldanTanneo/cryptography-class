use chacha20::u96;
use io_utils::ReadExt;
use std::io::{self, Read, Write};

struct Pad16<R: Read> {
    reader: R,
    bytes_read: usize,
    full_len: usize,
    reached_eof: bool,
}

impl<R: Read> Pad16<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            bytes_read: 0,
            full_len: 0,
            reached_eof: false,
        }
    }

    pub fn finished(&self) -> bool {
        self.reached_eof && self.bytes_read % 16 == 0
    }

    pub fn len_at_eof(&self) -> Option<usize> {
        self.reached_eof.then_some(self.full_len)
    }
}

impl<R: Read> Read for Pad16<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.reached_eof {
            let n = self.reader.read(buf)?;
            self.bytes_read += n;
            if n == 0 {
                self.full_len = self.bytes_read;
                self.reached_eof = true;
            } else {
                return Ok(n);
            }
        }

        let pad_left = (16 - (self.bytes_read % 16)) % 16;
        if pad_left == 0 {
            return Ok(0);
        }

        let len = buf.len();
        let buf = &mut buf[..pad_left.min(len)];
        buf.fill(0);
        self.bytes_read += buf.len();
        Ok(buf.len())
    }
}

pub struct ConcatLen<Aad: Read, Input: Read> {
    aad: Pad16<Aad>,
    input: Pad16<Input>,
    lens: [u8; 16],
    pos: Option<u8>,
}

impl<Aad: Read, Input: Read> ConcatLen<Aad, Input> {
    pub fn new(aad: Aad, input: Input) -> Self {
        Self {
            aad: Pad16::new(aad),
            input: Pad16::new(input),
            lens: [0; 16],
            pos: None,
        }
    }
}

impl<Aad: Read, Input: Read> Read for ConcatLen<Aad, Input> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        if !self.aad.finished() {
            n += self.aad.read(buf)?;
        }
        if n == 0 && !self.input.finished() {
            n += self.input.read(buf)?;
        }
        if n == 0 {
            if self.pos.is_none() {
                self.pos = Some(0);
                self.lens[..8]
                    .copy_from_slice(self.aad.len_at_eof().unwrap().to_le_bytes().as_slice());
                self.lens[8..]
                    .copy_from_slice(self.input.len_at_eof().unwrap().to_le_bytes().as_slice());
            }

            let pos = self.pos.unwrap();
            if pos >= 16 {
                return Ok(0);
            }

            n = (&self.lens[pos as usize..]).read(buf)?;
            *self.pos.as_mut().unwrap() += n as u8;
        }

        Ok(n)
    }
}

pub fn compute_tag(
    key: &[u8; 32],
    nonce: u96,
    aad: impl Read,
    input: impl Read,
    output: impl Write,
) -> io::Result<u128> {
    let otk: [u8; 32] = chacha20::block(key, 0, nonce)[..32].try_into().unwrap();

    let cipher = chacha20::cipher(key, nonce, input).tee(output);

    let mac_data = ConcatLen::new(aad, cipher);

    poly1305::poly1305(mac_data, &otk)
}

pub fn check_tag(
    key: &[u8; 32],
    nonce: u96,
    aad: impl Read,
    cipher: impl Read,
) -> io::Result<u128> {
    let otk: [u8; 32] = chacha20::block(key, 0, nonce)[..32].try_into().unwrap();

    let mac_data = ConcatLen::new(aad, cipher);

    poly1305::poly1305(mac_data, &otk)
}
