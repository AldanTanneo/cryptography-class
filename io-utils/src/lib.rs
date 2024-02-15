use std::{
    fmt::{Debug, Display},
    io::{self, Read, Write},
};

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

pub const fn parse_hex<const N: usize>(data: &str) -> Option<[u8; N]> {
    if data.len() != N * 2 {
        return None;
    }

    const fn hex_digit(x: u8) -> Option<u8> {
        Some(match x {
            b'0'..=b'9' => x - b'0',
            b'a'..=b'f' => x - b'a' + 10,
            b'A'..=b'F' => x - b'A' + 10,
            _ => return None,
        })
    }

    let mut res = [0; N];
    let mut i = 0;
    while i < N {
        let Some(d0) = hex_digit(data.as_bytes()[2 * i]) else {
            return None;
        };
        let Some(d1) = hex_digit(data.as_bytes()[2 * i + 1]) else {
            return None;
        };
        res[i] = (d0 * 16) | d1;
        i += 1;
    }

    Some(res)
}

#[macro_export]
macro_rules! hex {
    ($data:literal) => {{
        const DATA: &'static str = $data;
        const N: usize = DATA.len();
        const RES: [u8; N / 2] = match $crate::parse_hex::<{ N / 2 }>(DATA) {
            Some(arr) => arr,
            None => panic!("Invalid hex data"),
        };
        RES
    }};
}

pub fn hexfmt<'a>(digest: &'a impl AsRef<[u8]>) -> impl Display + Debug + 'a {
    struct Digest<'a>(&'a [u8]);

    impl Digest<'_> {
        fn inner_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for byte in self.0.as_ref() {
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }

    impl Display for Digest<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Digest::inner_fmt(self, f)
        }
    }

    impl Debug for Digest<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Digest::inner_fmt(self, f)
        }
    }

    Digest(digest.as_ref())
}
