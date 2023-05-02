//! Order-Revealing Encryption using AES128 as the primary cryptographic primitive.
//!
//! AES is usually high-performance (because hardware acceleration is widely available) and
//! generally considered secure.
//!
//! # Examples
//!
//! Encrypting a 32 bit unsigned integer so it can be ordered:
//!
//! ```rust
//! use cretrit::aes128v1::ore;
//! # use rand::{RngCore, Rng, SeedableRng};
//! # use rand_chacha::ChaCha20Rng;
//! #
//! # fn main() -> Result<(), cretrit::Error> {
//! // All ciphertexts encrypted with the same block size/width and key can be compared
//! // ALWAYS USE A CRYPTOGRAPHICALLY SECURE KEY!
//! let mut key: [u8; 32] = Default::default();
//! let mut rng = ChaCha20Rng::from_entropy();
//! rng.fill_bytes(&mut key);
//!
//! let cipher = ore::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! # Ok(())
//! # }
//! ```
//!
//! Comparing two encrypted ciphertexts is trivial, because Cretrit ciphertexts implement
//! `Eq`, `Ord`, etc as appropriate:
//!
//! ```rust
//! # use cretrit::aes128v1::ore;
//! #
//! # fn main() -> Result<(), cretrit::Error> {
//! # let key = [0u8; 32];
//! #
//! # let cipher = ore::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! let over_nine_thousand = cipher.full_encrypt(&9001u32.try_into()?)?;
//!
//! assert!(forty_two == forty_two);
//! assert!(forty_two != over_nine_thousand);
//! assert!(forty_two < over_nine_thousand);
//! # Ok(())
//! # }
//! ```
//!
//!
//! Serializing an encrypted integer so it can be stored somewhere (such as in a database):
//!
//! ```rust
//! # use cretrit::aes128v1::ore;
//! use cretrit::SerializableCipherText;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! #
//! # let key = [0u8; 32];
//! #
//! # let cipher = ore::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! let serialized = forty_two.to_vec()?;
//! # Ok(())
//! # }
//! ```
//!
//! Deserializing it again, so it can be compared:
//!
//! ```rust
//! # use cretrit::aes128v1::ore;
//! use cretrit::SerializableCipherText;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! #
//! # let key = [0u8; 32];
//! #
//! # let cipher = ore::Cipher::<4, 256>::new(&key)?;
//! # let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! # let serialized = forty_two.to_vec()?;
//! let deserialized = ore::CipherText::<4, 256>::from_slice(&serialized)?;
//! # Ok(())
//! # }
//! ```
use std::cmp::Ordering;

use super::CipherSuite;
use crate::cipher::Cipher as C;
use crate::ciphertext::CipherText as CT;
use crate::cmp::OrderingCMP;

/// [`Cipher`](crate::Cipher) specialisation for the [`aes128v1`](super) ciphersuite.
///
/// See the documentation for [`Cipher`](crate::Cipher) for usage information.
///
pub type Cipher<const N: usize, const W: u16> = C<CipherSuite<W, 3>, OrderingCMP, N, W, 3>;

/// [`CipherText`](crate::ciphertext::CipherText) specialisation for the [`aes128v1`](super) ciphersuite.
///
/// See the documentation for [`CipherText`](crate::CipherText) for usage information.
///
pub type CipherText<const N: usize, const W: u16> = CT<CipherSuite<W, 3>, OrderingCMP, N, W, 3>;

impl<const N: usize, const W: u16> Ord for CipherText<N, W> {
    fn cmp(&self, other: &CipherText<N, W>) -> Ordering {
        match self.left {
            None => match other.left {
                #[allow(clippy::panic)] // No way to return an error when implementing Ord
                None => panic!("Neither ciphertext in comparison has a left component"),
                Some(_) => match other.cmp(self) {
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less,
                },
            },
            #[allow(clippy::expect_used)] // No way to return an error when implementing Ord
            Some(_) => OrderingCMP::invert(self.compare(other).expect("comparison failed"))
                .expect("could not invert comparison value"),
        }
    }
}

impl<const N: usize, const W: u16> PartialOrd for CipherText<N, W> {
    fn partial_cmp(&self, other: &CipherText<N, W>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize, const W: u16> PartialEq for CipherText<N, W> {
    fn eq(&self, other: &CipherText<N, W>) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<const N: usize, const W: u16> Eq for CipherText<N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlainText;
    use rand::Rng;
    use std::cmp::Ordering;

    fn key() -> [u8; 32] {
        let mut k: [u8; 32] = Default::default();

        // Yes, using a potentially-weak RNG would normally be terribad, but
        // for testing purposes, it's not going to break anything
        let mut rng = rand::thread_rng();

        rng.try_fill(&mut k).unwrap();

        k
    }

    #[test]
    fn tiny_self_equality() {
        let cipher = Cipher::<1, 4>::new(&key()).unwrap();

        let n = cipher
            .full_encrypt(&PlainText::<1, 4>::new([2u16]))
            .unwrap();

        assert_eq!(0, n.compare(&n).unwrap());
    }

    #[test]
    fn tiny_equality() {
        let cipher = Cipher::<1, 4>::new(&key()).unwrap();

        let n2_1 = cipher
            .full_encrypt(&PlainText::<1, 4>::new([2u16]))
            .unwrap();
        let n2_2 = cipher
            .full_encrypt(&PlainText::<1, 4>::new([2u16]))
            .unwrap();

        assert_eq!(0, n2_1.compare(&n2_2).unwrap());
        assert_eq!(0, n2_2.compare(&n2_1).unwrap());
    }

    #[test]
    fn tiny_inequality() {
        let cipher = Cipher::<1, 4>::new(&key()).unwrap();

        let n1 = cipher
            .full_encrypt(&PlainText::<1, 4>::new([1u16]))
            .unwrap();
        let n2 = cipher
            .full_encrypt(&PlainText::<1, 4>::new([2u16]))
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    #[test]
    fn smol_self_equality() {
        let cipher = Cipher::<2, 16>::new(&key()).unwrap();

        let n12 = cipher
            .full_encrypt(&PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();

        assert_eq!(0, n12.compare(&n12).unwrap());
    }

    #[test]
    fn smol_equality() {
        let cipher = Cipher::<2, 16>::new(&key()).unwrap();

        let n12_1 = cipher
            .full_encrypt(&PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();
        let n12_2 = cipher
            .full_encrypt(&PlainText::<2, 16>::new([0u16, 12]))
            .unwrap();

        assert_eq!(0, n12_1.compare(&n12_2).unwrap());
        assert_eq!(0, n12_2.compare(&n12_1).unwrap());
    }

    #[test]
    fn smol_inequality() {
        let cipher = Cipher::<2, 16>::new(&key()).unwrap();

        let n1 = cipher
            .full_encrypt(&PlainText::<2, 16>::new([0u16, 1]))
            .unwrap();
        let n2 = cipher
            .full_encrypt(&PlainText::<2, 16>::new([0u16, 2]))
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    #[test]
    fn big_diff_energy() {
        let cipher = Cipher::<8, 256>::new(&key()).unwrap();

        let n1 = cipher.full_encrypt(&1u64.try_into().unwrap()).unwrap();
        let n2 = cipher
            .full_encrypt(&372_363_178_678_738_176u64.try_into().unwrap())
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(2, n2.compare(&n1).unwrap());
    }

    quickcheck! {
        fn u64_compare(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca.compare(&cb).unwrap() == 0,
                Ordering::Less    => ca.compare(&cb).unwrap() == 1,
                Ordering::Greater => ca.compare(&cb).unwrap() == 2,
            }
        }

        fn u64_cmp(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca == cb,
                Ordering::Less    => ca < cb,
                Ordering::Greater => ca > cb,
            }
        }

        fn u32_compare(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca.compare(&cb).unwrap() == 0,
                Ordering::Less    => ca.compare(&cb).unwrap() == 1,
                Ordering::Greater => ca.compare(&cb).unwrap() == 2,
            }
        }

        fn u32_cmp(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            match a.cmp(&b) {
                Ordering::Equal   => ca == cb,
                Ordering::Less    => ca < cb,
                Ordering::Greater => ca > cb,
            }
        }
    }
}
