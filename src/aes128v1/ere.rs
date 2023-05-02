//! Equality-Revealing Encryption (ERE) using AES128 as the Pseudo-Random Function and Hash Function.
//!
//! ERE is a means by which data can be encrypted in such a way that two ciphertexts can be
//! compared for equality, but no other useful information about the underlying plaintexts, or
//! the relationship between them, can be determined.
//!
//! # Examples
//!
//! Encrypting a 32 bit unsigned integer so it can be compared:
//!
//! ```rust
//! use cretrit::aes128v1::ere;
//! # use rand::{RngCore, Rng, SeedableRng};
//! # use rand_chacha::ChaCha20Rng;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! // All ciphertexts encrypted with the same block size/width and key can be compared
//! // ALWAYS USE A CRYPTOGRAPHICALLY SECURE KEY!
//! let mut key: [u8; 32] = Default::default();
//! let mut rng = ChaCha20Rng::from_entropy();
//! rng.fill_bytes(&mut key);
//!
//! let cipher = ere::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! # Ok(())
//! # }
//! ```
//!
//! Comparing two encrypted ciphertexts is trivial, because Cretrit ciphertexts implement
//! `Eq`:
//!
//! ```rust
//! # use cretrit::aes128v1::ere;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! # let key = [0u8; 32];
//!
//! # let cipher = ere::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! let over_nine_thousand = cipher.full_encrypt(&9001u32.try_into()?)?;
//!
//! assert!(forty_two == forty_two);
//! assert!(forty_two != over_nine_thousand);
//! # Ok(())
//! # }
//! ```
//!
//!
//! Serializing an encrypted integer so it can be stored somewhere (such as in a database) is
//! strightforward with [`to_vec()`](crate::ciphertext::Serializable.to_vec):
//!
//! ```rust
//! # use cretrit::aes128v1::ere;
//! use cretrit::SerializableCipherText;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! # let key = [0u8; 32];
//! # let cipher = ere::Cipher::<4, 256>::new(&key)?;
//! let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! let serialized = forty_two.to_vec()?;
//! # Ok(())
//! # }
//! ```
//!
//! Deserializing it again, so it can be compared, is done with
//! [`from_slice()`](crate::ciphertext::Serializable::from_slice):
//!
//! ```rust
//! # use cretrit::aes128v1::ere;
//! use cretrit::SerializableCipherText;
//!
//! # fn main() -> Result<(), cretrit::Error> {
//! # let key = [0u8; 32];
//! # let cipher = ere::Cipher::<4, 256>::new(&key)?;
//! # let forty_two = cipher.full_encrypt(&42u32.try_into()?)?;
//! # let serialized = forty_two.to_vec()?;
//! let deserialized = ere::CipherText::<4, 256>::from_slice(&serialized)?;
//! # Ok(())
//! # }
//! ```

use super::CipherSuite;
use crate::cipher::Cipher as C;
use crate::ciphertext::CipherText as CT;
use crate::cmp::EqualityCMP;

/// [`Cipher`](crate::Cipher) specialisation for the [`aes128v1`](super) ciphersuite.
///
/// See the documentation for [`Cipher`](crate::Cipher) for usage information.
///
pub type Cipher<const N: usize, const W: u16> = C<CipherSuite<W, 2>, EqualityCMP, N, W, 2>;

/// [`CipherText`](crate::ciphertext::CipherText) specialisation for the [`aes128v1`](super) ciphersuite.
///
/// See the documentation for [`CipherText`](crate::CipherText) for usage information.
///
pub type CipherText<const N: usize, const W: u16> = CT<CipherSuite<W, 2>, EqualityCMP, N, W, 2>;

impl<const N: usize, const W: u16> PartialEq for CipherText<N, W> {
    #[allow(clippy::panic, clippy::expect_used)] // No way to return error in impl Ord
    fn eq(&self, other: &CipherText<N, W>) -> bool {
        match self.left {
            None => match other.left {
                None => panic!("Neither ciphertext in comparison has a left component"),
                Some(_) => other.eq(self),
            },
            Some(_) => EqualityCMP::invert(self.compare(other).expect("comparison failed"))
                .expect("could not invert comparison value"),
        }
    }
}

impl<const N: usize, const W: u16> Eq for CipherText<N, W> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlainText;
    use rand::Rng;

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
        assert_eq!(1, n2.compare(&n1).unwrap());
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
        assert_eq!(1, n2.compare(&n1).unwrap());
    }

    #[test]
    fn big_diff_energy() {
        let cipher = Cipher::<8, 256>::new(&key()).unwrap();

        let n1 = cipher.full_encrypt(&1u64.try_into().unwrap()).unwrap();
        let n2 = cipher
            .full_encrypt(&372_363_178_678_738_176u64.try_into().unwrap())
            .unwrap();

        assert_eq!(1, n1.compare(&n2).unwrap());
        assert_eq!(1, n2.compare(&n1).unwrap());
    }

    quickcheck! {
        fn u64_compare(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            if a == b {
                ca.compare(&cb).unwrap() == 0
            } else {
                ca.compare(&cb).unwrap() == 1
            }
        }

        fn u32_compare(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            if a == b {
                ca.compare(&cb).unwrap() == 0
            } else {
                ca.compare(&cb).unwrap() == 1
            }
        }

        fn u64_eq(a: u64, b: u64) -> bool {
            let cipher = Cipher::<8, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            if a == b {
                ca == cb
            } else {
                ca != cb
            }
        }

        fn u32_eq(a: u32, b: u32) -> bool {
            let cipher = Cipher::<4, 256>::new(&key()).unwrap();

            let ca = cipher.full_encrypt(&a.try_into().unwrap()).unwrap();
            let cb = cipher.full_encrypt(&b.try_into().unwrap()).unwrap();

            if a == b {
                ca == cb
            } else {
                ca != cb
            }
        }
    }
}
