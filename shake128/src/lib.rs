use std::{
    io::{self, Read},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use bytemuck::{Pod, Zeroable};
use io_utils::ReadExt;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct State {
    data: [[u64; 5]; 5],
}

impl From<[[u64; 5]; 5]> for State {
    fn from(value: [[u64; 5]; 5]) -> Self {
        State { data: value }
    }
}

impl From<[u8; 200]> for State {
    fn from(value: [u8; 200]) -> Self {
        State {
            data: bytemuck::cast(value),
        }
    }
}

impl From<State> for [u8; 200] {
    fn from(value: State) -> Self {
        bytemuck::cast(value.data)
    }
}

pub fn theta(state: &mut State) -> &mut State {
    let mut c = [0; 5];
    for x in 0..5 {
        for y in 0..5 {
            c[x] ^= state.data[y][x];
        }
    }
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            state.data[y][x] ^= d;
        }
    }
    state
}

const fn compute_rho_offsets() -> [[u32; 5]; 5] {
    let mut offsets = [0; 24];
    let mut t = 0;
    while t < 24 {
        offsets[t as usize] = ((t + 1) * (t + 2) / 2) % 64;
        t += 1;
    }

    let mut res = [[0; 5]; 5];
    let (mut x, mut y) = (1, 0);
    let mut t = 0;
    while t < 24 {
        res[y][x] = offsets[t];
        (x, y) = (y, (2 * x + 3 * y) % 5);
        t += 1
    }
    res
}

// precomputing rho offsets
// leads to a >3x reduction in the time spent in rho
// (measured using cargo-flamegraph and hashing a 2GB file)
const RHO_OFFSETS: [[u32; 5]; 5] = compute_rho_offsets();

pub fn rho(state: &mut State) -> &mut State {
    for y in 0..5 {
        for x in 0..5 {
            state.data[y][x] = state.data[y][x].rotate_left(RHO_OFFSETS[y][x]);
        }
    }
    state
}

pub fn pi(state: &mut State) -> &mut State {
    let mut new = State::default();
    for x in 0..5 {
        for y in 0..5 {
            new.data[y][x] = state.data[x][(x + 3 * y) % 5];
        }
    }
    *state = new;
    state
}

pub fn chi(state: &mut State) -> &mut State {
    for row in &mut state.data {
        let mut new = [0; 5];
        for x in 0..5 {
            new[x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5])
        }
        *row = new;
    }
    state
}

const fn rc(round: usize) -> bool {
    let iterations = round % 255;

    let mut r: u8 = 1;
    let mut i = 0;

    while i < iterations {
        i += 1;
        r = r.rotate_left(1);
        r ^= 0b1110000 * (r & 1);
    }

    r & 1 == 1
}

pub const fn make_round_constants<const N: usize>() -> [u64; N] {
    let mut res = [0; N];

    let mut ir = 0;
    while ir < N {
        let mut j = 0;
        while j <= 6 {
            res[ir] |= (rc(j + 7 * ir) as u64) << ((1 << j) - 1);
            j += 1;
        }
        ir += 1;
    }

    res
}

const RC: [u64; 24] = make_round_constants();

pub fn iota(state: &mut State, ir: usize) -> &mut State {
    assert!(ir < 24, "Invalid round index");

    state.data[0][0] ^= RC[ir];

    state
}

pub fn round(state: &mut State, index: usize) {
    iota(chi(pi(rho(theta(state)))), index);
}

// will panic if data is not aligned to 8
// (required to cast &mut [u8; 200] to &mut State)
pub fn keccak_p(data: &mut [u8; 200]) {
    let state = bytemuck::cast_mut(data);

    for index in 0..24 {
        round(state, index);
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Suffix {
    S01 = 0b10,
    S1111 = 0b1111,
}

impl Suffix {
    pub const fn len(self) -> u8 {
        match self {
            Self::S01 => 2,
            Self::S1111 => 4,
        }
    }
}

pub trait KeccakFlavour {
    const CAPACITY: usize;
    const SUFFIX: Suffix;
}

// bypass Rust's const generics limitations
// by using a trait to compute R from C
trait Rate: KeccakFlavour {
    const R: usize = {
        assert!(Self::CAPACITY < 1600 && Self::CAPACITY % 8 == 0);
        (1600 - Self::CAPACITY) / 8
    };
}

impl<T: KeccakFlavour> Rate for T {}

pub struct Hasher<F: KeccakFlavour> {
    current: usize,
    data: [u8; 200],
    #[doc(hidden)]
    flavour: PhantomData<F>,
}

impl<F: KeccakFlavour> Read for Hasher<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current >= F::R {
            keccak_p(&mut self.data);
            self.current = 0;
        }
        // a read from a slice can never fail
        let r = (&self.data[self.current..F::R]).read(buf).unwrap();
        self.current += r;
        Ok(r)
    }
}

// using iterators allows us to fetch bytes as-needed, and not load the entire data range in memory
pub fn keccak<F: KeccakFlavour>(mut msg: impl Read) -> io::Result<impl Iterator<Item = u8>> {
    // ensure our 'data' array is correctly aligned
    // so that we can safely cast it to State
    #[repr(align(8))]
    struct AlignedData([u8; 200]);

    impl Deref for AlignedData {
        type Target = [u8; 200];
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for AlignedData {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    let mut data = AlignedData([0; 200]);

    // absorption

    loop {
        let mut buf = [0; 200];
        let n = msg.read_all(&mut buf[..F::R])?;
        data.iter_mut().zip(&buf[..F::R]).for_each(|(s, p)| *s ^= p);

        assert!(n <= F::R);

        if n == F::R {
            keccak_p(&mut data);
        } else {
            data[n] ^= F::SUFFIX as u8 | (1 << F::SUFFIX.len()); // suffix and pad10*1's first "1"
            data[F::R - 1] ^= 0b1000_0000; // pad10*1's final "1"
            keccak_p(&mut data);

            break;
        }
    }

    // squeezing

    let mut current = 0;

    Ok(std::iter::repeat_with(move || {
        if current < F::R {
            let byte = data[current];
            current += 1;
            byte
        } else {
            keccak_p(&mut data);
            let byte = data[0];
            current = 1;
            byte
        }
    }))
}

// Keccak Flavour for extendable output functions
struct Shake<const SIZE: usize>;

impl<const SIZE: usize> KeccakFlavour for Shake<SIZE> {
    const CAPACITY: usize = 2 * SIZE;
    const SUFFIX: Suffix = Suffix::S1111;
}

pub fn shake128(msg: impl Read) -> io::Result<impl Iterator<Item = u8>> {
    keccak::<Shake<128>>(msg)
}

pub fn shake256(msg: impl Read) -> io::Result<impl Iterator<Item = u8>> {
    keccak::<Shake<256>>(msg)
}

// Keccak Flavour for fixed size hash functions
struct Sha3<const SIZE: usize>;

impl<const SIZE: usize> KeccakFlavour for Sha3<SIZE> {
    const CAPACITY: usize = 2 * SIZE;
    const SUFFIX: Suffix = Suffix::S01;
}

fn sha3<const SIZE: usize>(msg: impl Read) -> io::Result<Vec<u8>> {
    keccak::<Sha3<SIZE>>(msg).map(|hash| hash.take(SIZE / 8).collect())
}

pub fn sha3_224(msg: impl Read) -> io::Result<Vec<u8>> {
    sha3::<224>(msg)
}

pub fn sha3_256(msg: impl Read) -> io::Result<Vec<u8>> {
    sha3::<256>(msg)
}

pub fn sha3_384(msg: impl Read) -> io::Result<Vec<u8>> {
    sha3::<384>(msg)
}

pub fn sha3_512(msg: impl Read) -> io::Result<Vec<u8>> {
    sha3::<512>(msg)
}
