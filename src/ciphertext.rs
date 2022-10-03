use std::convert::AsMut;

use crate::bitlist::BitList;
use crate::cipher::Cipher;
use crate::ciphersuite::CipherSuite;
use crate::cmp::Comparator;
use crate::error::Error;
use crate::hash::HashFunction;
use crate::kbkdf::KBKDF;
use crate::plaintext::PlainText;
use crate::prf::PseudoRandomFunction;

pub trait Serializable<const N: usize, const W: u16, const M: u8> {
    fn from_slice(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn to_vec(&self) -> Vec<u8>;
}

fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

#[derive(Debug)]
pub struct LeftCipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    f: [<<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType; N],
    px: [u16; N],
    cipher: Option<&'a Cipher<S, CMP, N, W, M>>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    LeftCipherText<'a, S, CMP, N, W, M>
{
    pub fn new(cipher: &'a Cipher<S, CMP, N, W, M>) -> Self {
        LeftCipherText {
            f: [Default::default(); N],
            px: [0; N],
            cipher: Some(cipher),
        }
    }

    pub fn set_block(&mut self, n: usize, value: u16) {
        assert!(n <= N, "{} <= {} violated", value, N);
        assert!(value < W, "{} < {} violated", value, W);

        self.px[n] = self
            .cipher
            .expect("attempted to set_block on a read-only left ciphertext")
            .permuted_value(value);

        self.cipher
            .unwrap()
            .pseudorandomise(self.px[n], &mut self.f[n]);
    }

    pub fn f(
        &self,
        n: usize,
    ) -> <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType {
        assert!(n < N, "{} < {} violated", n, N);
        self.f[n]
    }

    pub fn px(&self, n: usize) -> u16 {
        assert!(n < N, "{} < {} violated", n, N);
        self.px[n]
    }
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for LeftCipherText<'a, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut f: [<<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType; N] =
            [Default::default(); N];
        // Like I'm typing this out more often than I absolutely need to...
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;
        let mut px = [0u16; N];
        let px_start = N * f_size;

        for i in 0..N {
            let block = bytes.get((i * f_size)..((i + 1) * f_size)).ok_or_else(|| {
                Error::ParseError(format!("reached end of data while looking for f[{}]", i))
            })?;
            f[i] = clone_into_array(block);

            px[i] = if W <= 256 {
                *bytes.get(px_start + i).ok_or_else(|| {
                    Error::ParseError(format!("reached end of data while looking for px[{}]", i))
                })? as u16
            } else {
                let px_bytes = bytes
                    .get((px_start + 2 * i)..(px_start + 2 * i + 1))
                    .ok_or_else(|| {
                        Error::ParseError(format!(
                            "reached end of data while looking for px[{}]",
                            i
                        ))
                    })?;
                u16::from_be_bytes(px_bytes.try_into().map_err(|_| {
                    Error::ParseError(format!(
                        "failed to convert {:?} into u16 for px[{}]",
                        px_bytes, i
                    ))
                })?)
            }
        }

        Ok(Self {
            f,
            px,
            cipher: None,
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;

        let mut v: Vec<u8> = Vec::with_capacity(N * (f_size + 2));

        for n in 0..N {
            v.extend_from_slice(&self.f[n].into());
        }
        for n in 0..N {
            if W <= 256 {
                v.extend_from_slice(&(self.px[n] as u8).to_be_bytes());
            } else {
                v.extend_from_slice(&self.px[n].to_be_bytes());
            }
        }

        v
    }
}

#[derive(Debug)]
pub struct RightCipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    nonce_base: [u8; 16],
    nonce_cache: [[u8; 16]; N],
    values: Vec<Vec<u8>>,
    cipher: Option<&'a Cipher<S, CMP, N, W, M>>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    RightCipherText<'a, S, CMP, N, W, M>
{
    pub fn new(cipher: &'a Cipher<S, CMP, N, W, M>) -> Result<Self, Error> {
        let values: Vec<Vec<u8>> = (0..N).map(|_| vec![0u8; W as usize]).collect();
        let mut rct = RightCipherText {
            nonce_base: Default::default(),
            nonce_cache: [Default::default(); N],
            values,
            cipher: Some(cipher),
        };

        cipher.fill_nonce(&mut rct.nonce_base)?;

        Self::cache_nonces(&mut rct)?;

        Ok(rct)
    }

    fn cache_nonces(rct: &mut RightCipherText<'a, S, CMP, N, W, M>) -> Result<(), Error> {
        let ndf = KBKDF::new(rct.nonce_base)?;

        for i in 0..N {
            let mut k = Vec::<u8>::with_capacity(11);
            k.extend_from_slice(b"RCTnonce.");
            k.extend_from_slice(&(i as u16).to_be_bytes());

            ndf.derive_key(&mut rct.nonce_cache[i], &k)?;
        }

        Ok(())
    }

    pub fn set_block(&mut self, n: usize, value: u16) -> Result<(), Error> {
        assert!(n <= N, "{} <= {} violated", n, N);
        assert!(value <= W, "{} <= {} violated", value, W);

        for i in 0..W {
            let mut b: <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType =
                Default::default();

            self.cipher
                .expect("set_block called on a read-only right ciphertext")
                .pseudorandomise(i, &mut b);

            let v = self
                .cipher
                .unwrap()
                .compare_values(self.cipher.unwrap().inverse_permuted_value(i), value)
                + self
                    .cipher
                    .unwrap()
                    .hashed_value(&b.into(), &self.nonce(n))?;
            self.values[n][i as usize] = v % M;
        }

        Ok(())
    }

    pub fn value(&self, n: usize, px: u16) -> u8 {
        self.values[n][px as usize]
    }

    pub fn nonce(&self, n: usize) -> [u8; 16] {
        assert!(n < N, "{} < {} violated", n, N);
        self.nonce_cache[n]
    }

    fn unpack_binary_values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut v = BitList::from_slice(bytes);
        let mut vals: Vec<Vec<u8>> = Vec::with_capacity(N);

        for n in 0..N {
            vals.push(Vec::with_capacity(W.into()));
            for _w in 0..W {
                let b = if v.shift().ok_or_else(|| {
                    Error::ParseError(
                        "end-of-data reached while unpacking binary values".to_string(),
                    )
                })? {
                    1
                } else {
                    0
                };
                vals[n].push(b);
            }
        }

        Ok(vals)
    }

    fn pack_binary_values(&self) -> Vec<u8> {
        let mut v = BitList::new(N * W as usize);

        for n in 0..N {
            for w in 0..W {
                v.push(self.values[n][w as usize] > 0);
            }
        }

        v.vec()
    }

    fn unpack_trinary_values(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut v = BitList::from_slice(bytes);
        let mut vals: Vec<Vec<u8>> = Vec::with_capacity(N);

        for n in 0..N {
            vals.push(Vec::with_capacity(W.into()));
            for _w in 0..W {
                let b = if v.shift().ok_or_else(|| {
                    Error::ParseError(
                        "end-of-data reached while unpacking trinary values".to_string(),
                    )
                })? {
                    if v.shift().ok_or_else(|| {
                        Error::ParseError(
                            "end-of-data reached while unpacking trinary values".to_string(),
                        )
                    })? {
                        2
                    } else {
                        1
                    }
                } else {
                    0
                };
                vals[n].push(b);
            }
        }

        Ok(vals)
    }

    fn pack_trinary_values(&self) -> Vec<u8> {
        // This capacity calculation is excessive, but safe
        let mut v = BitList::new(N * W as usize * 2);

        for n in 0..N {
            for w in 0..W {
                let val = self.values[n][w as usize];

                if val == 0 {
                    v.push(false);
                } else {
                    v.push(true);
                    if val > 1 {
                        v.push(true);
                    } else {
                        v.push(false);
                    }
                }
            }
        }

        v.vec()
    }
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for RightCipherText<'a, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let nonce_base: [u8; 16] = clone_into_array(bytes.get(0..16).ok_or_else(|| {
            Error::ParseError("end-of-data found while looking for nonce base".to_string())
        })?);

        let values = if M == 2 {
            Self::unpack_binary_values(&bytes[16..])?
        } else if M == 3 {
            Self::unpack_trinary_values(&bytes[16..])?
        } else {
            panic!("don't know how to unpack bytes for M={}", M);
        };

        let mut rct = RightCipherText::<'a, S, CMP, N, W, M> {
            nonce_base,
            values,
            nonce_cache: [Default::default(); N],
            cipher: None,
        };
        Self::cache_nonces(&mut rct)?;

        Ok(rct)
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(16 + N * W as usize / 4);

        v.extend_from_slice(&self.nonce_base);

        let value_slice = if M == 2 {
            self.pack_binary_values()
        } else if M == 3 {
            self.pack_trinary_values()
        } else {
            panic!("don't know how to pack values for M={}", M);
        };

        v.extend_from_slice(&value_slice);

        v
    }
}

#[derive(Debug)]
pub struct CipherText<
    'a,
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    pub left: Option<LeftCipherText<'a, S, CMP, N, W, M>>,
    pub right: RightCipherText<'a, S, CMP, N, W, M>,
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    CipherText<'a, S, CMP, N, W, M>
{
    pub fn new(
        cipher: &'a Cipher<S, CMP, N, W, M>,
        plaintext: &PlainText<N, W>,
    ) -> Result<Self, Error> {
        let mut left = LeftCipherText::new(cipher);
        let mut right = RightCipherText::new(cipher)?;

        for n in 0..N {
            left.set_block(n, plaintext.block(n));
            right.set_block(n, plaintext.block(n))?;
        }

        Ok(CipherText {
            left: Some(left),
            right,
        })
    }

    pub fn new_right(
        cipher: &'a Cipher<S, CMP, N, W, M>,
        plaintext: &PlainText<N, W>,
    ) -> Result<Self, Error> {
        let mut right = RightCipherText::new(cipher)?;

        for n in 0..N {
            right.set_block(n, plaintext.block(n))?;
        }

        Ok(CipherText { left: None, right })
    }

    pub fn compare(&self, other: &Self) -> Result<u8, Error> {
        match &self.left {
            None => Err(Error::ComparisonError(
                "No left part in this ciphertext".to_string(),
            )),
            Some(v) => Self::compare_parts(v, &other.right),
        }
    }

    fn compare_parts(
        left: &LeftCipherText<'a, S, CMP, N, W, M>,
        right: &RightCipherText<'a, S, CMP, N, W, M>,
    ) -> Result<u8, Error> {
        let mut result: Option<u8> = None;

        for n in 0..N {
            let v_h = right.value(n, left.px(n));
            let h_k_r = S::HF::hash(&left.f(n).into(), &right.nonce(n))?;

            let res = (v_h as i16 - h_k_r as i16).rem_euclid(M as i16) as u8;

            if res != 0 && result == None {
                result = Some(res);
            }
        }

        Ok(result.unwrap_or(0))
    }
}

impl<'a, S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Serializable<N, W, M> for CipherText<'a, S, CMP, N, W, M>
{
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let mut v = bytes;

        let t = v.first().ok_or_else(|| {
            Error::ParseError("end of data while looking for ciphertext type marker".to_string())
        })?;
        v = &v[1..];

        let left: Option<LeftCipherText<'a, S, CMP, N, W, M>> = if *t == 0 {
            None
        } else if *t == 1 {
            let len_bytes = v.get(..2).ok_or_else(|| {
                Error::ParseError(
                    "end of data while looking for left ciphertext length".to_string(),
                )
            })?;
            v = &v[2..];
            let len = u16::from_be_bytes(len_bytes.try_into().map_err(|_| {
                Error::ParseError(format!(
                    "failed to convert {:?} into u16 for left ciphertext length",
                    len_bytes
                ))
            })?) as usize;
            let left_bytes = v.get(..len).ok_or_else(|| {
                Error::ParseError("end of data while looking for left ciphertext".to_string())
            })?;
            v = &v[len..];
            Some(LeftCipherText::<'a, S, CMP, N, W, M>::from_slice(
                left_bytes,
            )?)
        } else {
            return Err(Error::ParseError(format!("unrecognised type byte {}", t)));
        };

        let len_bytes = v.get(..2).ok_or_else(|| {
            Error::ParseError("end of data while looking for right ciphertext length".to_string())
        })?;
        v = &v[2..];
        let len = u16::from_be_bytes(len_bytes.try_into().map_err(|_| {
            Error::ParseError(format!(
                "failed to convert {:?} into u16 for right ciphertext length",
                len_bytes
            ))
        })?) as usize;
        let right_bytes = v.get(..len).ok_or_else(|| {
            Error::ParseError("end of data while looking for right ciphertext".to_string())
        })?;
        let right = RightCipherText::<'a, S, CMP, N, W, M>::from_slice(right_bytes)?;

        Ok(CipherText::<'a, S, CMP, N, W, M> { left, right })
    }

    fn to_vec(&self) -> Vec<u8> {
        let f_size = <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BLOCK_SIZE;

        // 5 for type byte, left CT len, right CT len
        // N * (f_size + 2) for left CT (if needed)
        // 16 + N * W / 4 for right CT
        let mut v: Vec<u8> = Vec::with_capacity(5 + N * (f_size + 2) + 16 + N * W as usize / 4);

        // Type byte -- 0 is just a right CT, 1 is left+right
        // other values to be worried about later
        match &self.left {
            Some(l) => {
                v.push(1);
                let left_bytes = l.to_vec();
                v.extend_from_slice(&(left_bytes.len() as u16).to_be_bytes());
                v.extend_from_slice(&left_bytes);
            }
            None => v.push(0),
        };

        let right_bytes = self.right.to_vec();
        v.extend_from_slice(&(right_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(&right_bytes);

        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn key() -> [u8; 16] {
        let mut k: [u8; 16] = Default::default();

        // Yes, using a potentially-weak RNG would normally be terribad, but
        // for testing purposes, it's not going to break anything
        let mut rng = rand::thread_rng();

        rng.try_fill(&mut k).unwrap();

        k
    }

    mod ere {
        use super::*;
        use crate::aes128v1::ere;

        #[test]
        fn binary_full_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n = cipher.full_encrypt(31_337u64.into()).unwrap();

            let v = n.to_vec();

            let n_rt = ere::CipherText::<8, 256>::from_slice(&v).unwrap();

            assert_eq!(n, n_rt);
            assert_eq!(n_rt, n);
        }

        #[test]
        fn binary_right_ciphertext_roundtrips_correctly() {
            let cipher = ere::Cipher::<8, 256>::new(key()).unwrap();

            let n1 = cipher.full_encrypt(31_337u64.into()).unwrap();
            let mut n2 = cipher.full_encrypt(31_337u64.into()).unwrap();
            n2.left = None;

            let v = n2.to_vec();

            let n_rt = ere::CipherText::<8, 256>::from_slice(&v).unwrap();

            assert_eq!(n1, n_rt);
        }
    }

    mod ore {
        use super::*;
        use crate::aes128v1::ore;

        #[test]
        fn trinary_full_ciphertext_roundtrips_correctly() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n1 = cipher.full_encrypt(42u64.into()).unwrap();
            let n2 = cipher.full_encrypt(31_337u64.into()).unwrap();

            let v1 = n1.to_vec();
            let v2 = n2.to_vec();

            let n1_rt = ore::CipherText::<8, 256>::from_slice(&v1).unwrap();
            let n2_rt = ore::CipherText::<8, 256>::from_slice(&v2).unwrap();

            assert!(n1 == n1_rt);
            assert!(n2 == n2_rt);
            assert!(n1 < n2_rt);
            assert!(n2 > n1_rt);

            assert!(n1_rt == n1);
            assert!(n2_rt == n2);
            assert!(n1_rt < n2);
            assert!(n2_rt > n1);
        }

        #[test]
        fn trinary_right_ciphertext_roundtrips_correctly() {
            let cipher = ore::Cipher::<8, 256>::new(key()).unwrap();

            let n1f = cipher.full_encrypt(42u64.into()).unwrap();
            let mut n1r = cipher.full_encrypt(42u64.into()).unwrap();
            n1r.left = None;

            let v1r = n1r.to_vec();

            let n1r_rt = ore::CipherText::<8, 256>::from_slice(&v1r).unwrap();

            let n2f = cipher.full_encrypt(31_337u64.into()).unwrap();
            let mut n2r = cipher.full_encrypt(31_337u64.into()).unwrap();
            n2r.left = None;

            let v2r = n2r.to_vec();

            let n2r_rt = ore::CipherText::<8, 256>::from_slice(&v2r).unwrap();

            assert!(n1f == n1r_rt);
            assert!(n2f == n2r_rt);
            assert!(n1f < n2r_rt);
            assert!(n2f > n1r_rt);
        }
    }
}
