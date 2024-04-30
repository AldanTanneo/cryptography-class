use std::{
    hint::black_box,
    io::{self, Cursor, Read, Write},
    ops::{
        Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
    },
};

use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, Rng,
};
use shake128::shake128;
use x25519::{x25519, Curve25519};

// utility trait that covers all main
// characteristics of [u8; N] arrays
pub trait ByteArray:
    AsRef<[u8]>
    + AsMut<[u8]>
    + Index<usize, Output = u8>
    + IndexMut<usize, Output = u8>
    + Index<Range<usize>, Output = [u8]>
    + IndexMut<Range<usize>, Output = [u8]>
    + Index<RangeFrom<usize>, Output = [u8]>
    + IndexMut<RangeFrom<usize>, Output = [u8]>
    + Index<RangeTo<usize>, Output = [u8]>
    + IndexMut<RangeTo<usize>, Output = [u8]>
    + Index<RangeInclusive<usize>, Output = [u8]>
    + IndexMut<RangeInclusive<usize>, Output = [u8]>
    + Index<RangeToInclusive<usize>, Output = [u8]>
    + IndexMut<RangeToInclusive<usize>, Output = [u8]>
    + Index<RangeFull, Output = [u8]>
    + IndexMut<RangeFull, Output = [u8]>
    + IntoIterator<Item = u8>
    + Copy
    + for<'a> TryFrom<&'a [u8]>
    + for<'a> TryFrom<&'a mut [u8]>
    + TryFrom<Vec<u8>>
{
    const N: usize;
    fn default() -> Self;
}

impl<const N: usize> ByteArray for [u8; N] {
    const N: usize = N;
    fn default() -> Self {
        [0; N]
    }
}

pub trait BytesIterator: Iterator<Item = u8> {
    fn next_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut res = [0; N];
        for r in &mut res {
            *r = self.next()?;
        }
        Some(res)
    }
}

impl<I: Iterator<Item = u8>> BytesIterator for I {}

pub trait Pke {
    type PublicKey: ByteArray;
    type SecretKey: ByteArray;
    type Randomness: ByteArray;

    fn keygen(rng: &mut (impl Rng + CryptoRng)) -> (Self::PublicKey, Self::SecretKey);
    fn enc(
        plaintext: impl Read,
        public_key: &Self::PublicKey,
        randomness: Self::Randomness,
    ) -> impl Read;
    fn dec(ciphertext: impl Read, private_key: &Self::SecretKey) -> io::Result<impl Read>;
}

pub struct HashElGamal25519;

impl HashElGamal25519 {
    fn hash_and_cipher(text: impl Read, shared_secret: [u8; 32]) -> impl Read {
        assert!(
            shared_secret.iter().fold(0, |acc, x| black_box(acc | x)) != 0,
            "used x25519 with a small order point, giving an all-zero shared secret"
        );

        // hash the shared secret first
        let mut hash = shake128(&shared_secret[..]).unwrap();

        // derive an encryption key
        let key = hash.next_array().unwrap();
        // use a fixed zero nonce (the key is supposed to be random)
        let nonce = (0, 0, 0);

        // apply chacha20 to the text
        chacha20::cipher(&key, nonce, text)
    }
}

impl Pke for HashElGamal25519 {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Randomness = [u8; 32];

    fn keygen(rng: &mut (impl Rng + CryptoRng)) -> (Self::PublicKey, Self::SecretKey) {
        let secret: Self::SecretKey = rng.gen();
        let public: Self::PublicKey = x25519(&secret, Curve25519::BASE_POINT_BYTES);
        (public, secret)
    }

    fn enc(
        plaintext: impl Read,
        public_key: &Self::PublicKey,
        randomness: Self::Randomness,
    ) -> impl Read {
        let mut y = [0; 32];
        // use chacha20 as a RNG seeded by randomness (with 0-filled message)
        chacha20::cipher(&randomness, (0, 0, 0), io::repeat(0))
            .read_exact(&mut y)
            .unwrap();

        let shared = x25519(&y, public_key);
        let c1 = x25519(&y, Curve25519::BASE_POINT_BYTES);
        let c2 = Self::hash_and_cipher(plaintext, shared);

        Cursor::new(c1).chain(c2)
    }

    fn dec(mut ciphertext: impl Read, private_key: &Self::SecretKey) -> io::Result<impl Read> {
        let mut c1 = [0; 32];
        ciphertext.read_exact(c1.as_mut_slice())?;

        let shared = x25519(private_key, &c1);

        Ok(Self::hash_and_cipher(ciphertext, shared))
    }
}

#[derive(Clone)]
pub struct SecretKey<K: Kem>
where
    // ensures that we can generate S and M randomly
    Standard: Distribution<K::S> + Distribution<K::Message>,
{
    sk: K::SecretKey,
    s: K::S,
    pk: K::PublicKey,
    pkh: K::PKHash,
}

impl SecretKey<HashElGamal25519> {
    pub fn serialize(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_all(&self.sk)?;
        writer.write_all(&self.s)?;
        writer.write_all(&self.pk)?;
        writer.write_all(&self.pkh)?;
        Ok(())
    }

    pub fn deserialize(mut reader: impl Read) -> io::Result<Self> {
        let mut res = Self {
            sk: [0; 32],
            s: [0; 16],
            pk: [0; 32],
            pkh: [0; 16],
        };
        reader.read_exact(&mut res.sk)?;
        reader.read_exact(&mut res.s)?;
        reader.read_exact(&mut res.pk)?;
        reader.read_exact(&mut res.pkh)?;
        let n = reader.read(&mut [0][..])?;
        if n != 0 {
            Err(io::Error::other(
                "extra data in reader after deserializing secret key",
            ))
        } else {
            Ok(res)
        }
    }
}

pub trait Kem: Pke + Sized
where
    // ensures that we can generate S and M randomly
    Standard: Distribution<Self::S> + Distribution<Self::Message>,
{
    /// s array
    type S: ByteArray;
    /// hashed public key
    type PKHash: ByteArray;
    /// random message
    type Message: ByteArray;
    /// ciphertext
    type Ciphertext: ByteArray;
    /// symmetric key output
    type Key: ByteArray;

    // hash functions. the data to g2 and f are split in a tuple
    // for implementation convenience
    fn g1(data: &Self::PublicKey) -> Self::PKHash;
    fn g2(data: (&Self::PKHash, &Self::Message)) -> (Self::Randomness, impl ByteArray);
    fn f(data: (&Self::Ciphertext, &impl ByteArray)) -> Self::Key;

    fn keygen(rng: &mut (impl Rng + CryptoRng)) -> (Self::PublicKey, SecretKey<Self>) {
        let (pk, sk) = <Self as Pke>::keygen(rng);

        let s: Self::S = rng.gen();
        let pkh = Self::g1(&pk);

        let sk2 = SecretKey { sk, s, pk, pkh };
        (pk, sk2)
    }

    fn encaps(
        rng: &mut (impl Rng + CryptoRng),
        public_key: &Self::PublicKey,
    ) -> (Self::Ciphertext, Self::Key) {
        let msg: Self::Message = rng.gen();
        let pkh = Self::g1(public_key);
        let (r, k) = Self::g2((&pkh, &msg));

        let mut c = Self::Ciphertext::default();
        Self::enc(msg.as_ref(), public_key, r)
            .read_exact(c.as_mut())
            .unwrap(); // cannot fail

        let key = Self::f((&c, &k));

        (c, key)
    }

    fn decaps(
        ciphertext: &Self::Ciphertext,
        SecretKey { sk, s, pk, pkh }: &SecretKey<Self>,
    ) -> Self::Key {
        let mut m = Self::Message::default();
        // cannot fail once c1 has been extracted
        Self::dec(&ciphertext[..], sk)
            .unwrap()
            .read_exact(m.as_mut())
            .unwrap();

        let (r, k) = Self::g2((&pkh, &m));
        let key0 = Self::f((ciphertext, &k));
        let key1 = Self::f((ciphertext, s));

        let mut cipher2 = Self::Ciphertext::default();
        Self::enc(m.as_ref(), pk, r)
            .read_exact(cipher2.as_mut())
            .unwrap(); // cannot fail

        // constant time selection of the key:

        // reduce C and C' to a logical OR of their xored bytes,
        // compare it once to zero at the end.
        // it is true iff C and C' are equal
        let equal = cipher2
            .into_iter()
            .zip(&ciphertext[..])
            .map(|(c1, c2)| c1 ^ c2)
            .fold(0, |acc, x| acc | x)
            == 0;

        // turn it into a mask; true => 0xff, false => 0
        // black box prevents compiler optimisations
        let mask = !black_box(black_box(equal as u8).wrapping_sub(1));

        let mut key = Self::Key::default();
        key0.into_iter()
            .zip(key1)
            // mask each byte of the key to get the end result
            .map(|(k0, k1)| (k0 & mask) | (k1 & !mask))
            .zip(key.as_mut())
            .for_each(|(k, s): (u8, &mut u8)| *s = k);

        key
    }
}

impl Kem for HashElGamal25519 {
    type S = [u8; 16];
    type PKHash = [u8; 16];
    type Message = [u8; 16];
    type Ciphertext = [u8; 48];
    type Key = [u8; 16];

    fn g1(data: &Self::PublicKey) -> Self::PKHash {
        shake128(data.chain(&b"g1"[..]))
            .unwrap()
            .next_array()
            .unwrap()
    }

    fn g2((pkh, m): (&Self::PKHash, &Self::Message)) -> (Self::Randomness, impl ByteArray) {
        let mut hash = shake128(pkh[..].chain(&m[..]).chain(&b"g2"[..])).unwrap();

        let randomness = hash.next_array().unwrap();
        (randomness, hash.next_array::<32>().unwrap())
    }

    fn f(data: (&Self::Ciphertext, &impl ByteArray)) -> Self::Key {
        shake128(data.0.chain(&data.1[..]).chain(&b"kdf"[..]))
            .unwrap()
            .next_array()
            .unwrap()
    }
}

pub fn keygen(rng: &mut (impl Rng + CryptoRng)) -> ([u8; 32], SecretKey<HashElGamal25519>) {
    Kem::keygen(rng)
}

pub fn encaps(rng: &mut (impl Rng + CryptoRng), public_key: &[u8; 32]) -> ([u8; 48], [u8; 16]) {
    HashElGamal25519::encaps(rng, public_key)
}

pub fn decaps(ciphertext: &[u8; 48], secret_key: &SecretKey<HashElGamal25519>) -> [u8; 16] {
    HashElGamal25519::decaps(ciphertext, secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pke() {
        let text: &[u8] =
            b"The world is indeed full of peril and in it there are many dark places.";

        let (public, private) = <HashElGamal25519 as Pke>::keygen(&mut rand::thread_rng());
        let randomness = rand::random();

        let mut cipher = Vec::new();
        HashElGamal25519::enc(text, &public, randomness)
            .read_to_end(&mut cipher)
            .unwrap();

        let mut decipher = Vec::new();
        HashElGamal25519::dec(&cipher[..], &private)
            .unwrap()
            .read_to_end(&mut decipher)
            .unwrap();

        assert_eq!(decipher, text);
    }

    #[test]
    fn encaps_decaps() {
        let (public, private) = keygen(&mut rand::thread_rng());
        let (cipher, key1) = encaps(&mut rand::thread_rng(), &public);
        let key2 = decaps(&cipher, &private);

        assert_eq!(key1, key2)
    }
}
