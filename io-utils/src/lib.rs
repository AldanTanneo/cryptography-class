use std::io::{self, Read, Write};

/// Duplicates the output of a reader and pipes it in a writer.
///
/// See the documentation on [`ReadExt::tee`].
pub struct Tee<R: Read, W: Write> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.writer.write_all(&buf[..n])?;
        Ok(n)
    }
}

pub trait ReadExt: Read {
    /// Attempts to read an entire buffer from this reader.
    ///
    /// This method will continuously call [`read`] until the buffer is filled,
    /// or there is no more data to be [`read`]. This method will not
    /// return until the entire buffer has been successfully [`read`], EOF is
    /// reached or an an error occurs.
    ///
    /// If the buffer is empty, this will never call [`read`].
    ///
    /// # Errors
    /// This function will return the first error that [`read`] returns.
    ///
    /// [`read`]: std::io::Read::read
    fn read_all(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;

        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    read += n;
                    buf = &mut buf[n..];
                }
                Err(e) => return Err(e),
            };
        }

        Ok(read)
    }

    /// Duplicate the output of this reader, piping it into the provided writer.
    ///
    /// This works by calling [`write_all`] for each call to [`read`], writing
    /// all the data that was just read from self. Therefore, it is best used
    /// with a [`BufWriter`], or wrapped in a [`BufReader`], to avoid the cost
    /// of frequent small writes.
    ///
    /// # Errors
    /// The returned reader will return an error on [`read`] if the call to
    /// [`write_all`] returned an error, in addition to regular read errors.
    ///
    /// [`read`]: std::io::Read::read
    /// [`write_all`]: std::io::Write::write_all
    /// [`BufWriter`]: std::io::BufWriter
    /// [`BufReader`]: std::io::BufReader
    fn tee<W: Write>(self, writer: W) -> Tee<Self, W>
    where
        Self: Sized,
    {
        Tee {
            reader: self,
            writer,
        }
    }
}

impl<T: Read> ReadExt for T {}

pub fn parse_hex<const N: usize>(data: &str) -> Option<[u8; N]> {
    if data.len() != N * 2 {
        return None;
    }

    fn hex_digit(x: u8) -> Option<u8> {
        Some(match x {
            b'0'..=b'9' => x - b'0',
            b'a'..=b'f' => x - b'a' + 10,
            b'A'..=b'F' => x - b'A' + 10,
            _ => return None,
        })
    }

    let mut res = [0; N];
    for (i, byte) in data.as_bytes().chunks_exact(2).enumerate() {
        res[i] = (hex_digit(byte[0])? * 16) | hex_digit(byte[1])?;
    }

    Some(res)
}
