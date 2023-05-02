//! Equality-Revealing Encryption using AES128 as the core cryptographic primitive.
//!

use std::convert::TryFrom;

use crate::Error;

/// A plaintext suitable for encrypting using a comparison-revealing scheme.
///
/// Lewi-Wu Comparison-Revealing Encryption works on a per-block basis, where the block size is
/// determined by parameters set when creating the [`Cipher`](crate::Cipher) instance.  This type
/// stores the plaintexts required for encryption by a [`Cipher`](crate::Cipher).
///
/// Conversion operations from common integer types are provided, to make it easier to encrypt
/// the values most likely to be of interest.
///
/// # Examples
///
/// It is rare that you will need to manually construct `PlainText` values very often.  Instead,
/// you'll just call `into()` on an integer you want to encrypt, like this:
///
/// ```rust
/// use cretrit::aes128v1::ore;
/// # fn main() -> Result<(), cretrit::Error> {
/// # let key = [0u8; 16];
///
/// let cipher = ore::Cipher::<4, 256>::new(key)?;
/// let encrypted_value = cipher.full_encrypt(&42u32.try_into()?)?;
/// # Ok(())
/// # }
/// ```
///
#[derive(Debug)]
pub struct PlainText<const N: usize, const W: u16>([u16; N]);

impl<const N: usize, const W: u16> PlainText<N, W> {
    /// Create a new `PlainText`.
    #[must_use]
    pub fn new(a: [u16; N]) -> PlainText<N, W> {
        PlainText(a)
    }

    /// Get the `n`th block of the plaintext
    pub(crate) fn block(&self, n: usize) -> Result<u16, Error> {
        self.0
            .get(n)
            .ok_or_else(|| {
                Error::RangeError(format!("Couldn't get block {n} from PlainText<{N}, {W}>"))
            })
            .copied()
    }
}

/// Generate an implementation of [`TryFrom`] for an unsigned integer type
macro_rules! from_uint_to_plaintext {
    ($ty:ident) => {
        impl<const N: usize, const W: u16> TryFrom<$ty> for PlainText<N, W> {
            type Error = Error;

            fn try_from(value: $ty) -> Result<Self, Self::Error>  {
                let mut u: u128 = value.try_into().map_err(|e| Self::Error::RangeError(format!("Couldn't represent value {value} as u128 ({e})")))?;
                let mut p = [0u16; N];
                let width: u128 = W.try_into().map_err(|e| Self::Error::InternalError(format!("Couldn't represent W {W} as u128 ({e})")))?;

                for i in 0..N {
                    let idx = N.saturating_sub(i).saturating_sub(1);
                    let p_ref = p.get_mut(idx).ok_or_else(|| Self::Error::InternalError(format!("could not get element {idx} in PlainText<{N}, {W}>::try_from({value}{})", stringify!($ty))))?;
                    *p_ref = u16::try_from(u.rem_euclid(width)).map_err(|e| Self::Error::InternalError(format!("Somehow couldn't represent {u} % {width} as u16?!?i ({e})")))?;
                    u = num::Integer::div_floor(&u, &width);
                }

                if u == 0 {
                    Ok(PlainText::<N, W>::new(p))
                } else {
                    Err(Self::Error::RangeError(format!("Could not represent {value}{} in PlainText<{N}, {W}>",
                    stringify!($ty)
                )))
                }
            }
        }
    };
}

from_uint_to_plaintext!(u128);
from_uint_to_plaintext!(u64);
from_uint_to_plaintext!(u32);
from_uint_to_plaintext!(u16);
from_uint_to_plaintext!(u8);

impl<const N: usize, const W: u16> TryFrom<bool> for PlainText<N, W> {
    type Error = Error;

    fn try_from(value: bool) -> Result<PlainText<N, W>, Self::Error> {
        PlainText::<N, W>::try_from(u8::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod pt_4_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16; 4], PlainText::<4, 256>::try_from(0u32).unwrap().0);
        }

        #[test]
        fn tiny() {
            assert_eq!(
                [0u16, 0, 0, 42],
                PlainText::<4, 256>::try_from(42u32).unwrap().0
            );
        }

        #[test]
        fn smol() {
            assert_eq!(
                [0u16, 0, 91, 42],
                PlainText::<4, 256>::try_from(23_338u32).unwrap().0
            );
        }

        #[test]
        fn yuuuge() {
            assert_eq!(
                [4u16, 3, 2, 1],
                PlainText::<4, 256>::try_from(67_305_985u32).unwrap().0
            );
        }
    }

    mod pt_8_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16; 8], PlainText::<8, 256>::try_from(0u64).unwrap().0);
        }

        #[test]
        fn one() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 0, 1],
                PlainText::<8, 256>::try_from(1u64).unwrap().0
            );
        }

        #[test]
        fn tiny() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 0, 42],
                PlainText::<8, 256>::try_from(42u64).unwrap().0
            );
        }

        #[test]
        fn smol() {
            assert_eq!(
                [0u16, 0, 0, 0, 0, 0, 91, 42],
                PlainText::<8, 256>::try_from(23_338u64).unwrap().0
            );
        }

        #[test]
        fn yuuuge() {
            assert_eq!(
                [8u16, 7, 6, 5, 4, 3, 2, 1],
                PlainText::<8, 256>::try_from(578_437_695_752_307_201u64)
                    .unwrap()
                    .0
            );
        }
    }

    mod pt_1_256 {
        use super::*;

        #[test]
        fn zero() {
            assert_eq!([0u16], PlainText::<1, 256>::try_from(0u8).unwrap().0);
        }

        #[test]
        fn tiny() {
            assert_eq!([42u16], PlainText::<1, 256>::try_from(42u8).unwrap().0);
        }
    }

    mod pt_1_2_bool {
        use super::*;

        #[test]
        fn from_true() {
            assert_eq!([1u16; 1], PlainText::<1, 2>::try_from(true).unwrap().0);
        }

        #[test]
        fn from_false() {
            assert_eq!([0u16], PlainText::<1, 2>::try_from(false).unwrap().0);
        }
    }
}
