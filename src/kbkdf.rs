//! Key-based Key Derivation
//!
//! With a hash function, and some guidance from NIST SP800-108, one can derive new keys from an
//! existing key, as many as one might like.  Very handy stuff when you need a lot of keys, and
//! would rather not spend a fortune on KMS.
//!

use aes::Aes256;
use cmac::{Cmac, Mac};
use std::fmt;
use zeroize::ZeroizeOnDrop;

use crate::{util::check_overflow, Error};

/// Initialisation of a KBKDF
///
#[allow(clippy::upper_case_acronyms)]
#[doc(hidden)]
pub trait KBKDFInit: KBKDF {
    /// Create a KBKDF instance
    ///
    /// # Errors
    ///
    /// Different KBKDFs have different requirements for the size of their key, which will be the
    /// most likely cause of errors.
    ///
    fn new(root_key: &[u8; 32]) -> Result<Box<Self>, Error>;
}

/// The key-generating functionality of a KBKDF
///
#[allow(clippy::upper_case_acronyms)]
pub trait KBKDF {
    /// Generate a new key
    ///
    /// The derived key is written to `subkey`, which can be of arbitrary length.
    /// If the same `id` is passed to a KBKDF created with the same `root_key`, the same subkey will be generated each time.
    /// Thus, make your `id`s distinct for each different use of the same KBKDF.
    ///
    /// # Errors
    ///
    /// Will fail if an underlying cryptographic operation fails.
    ///
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error>;
}

/// A KBKDF based on CMACAES256
///
/// NIST SP800-108 has caveats around using CMAC, however those caveats don't apply to our use, and
/// AES-128 is typically hardware accelerated, giving a performance boost over a construction using
/// HMAC SHA-256, for example.
///
#[derive(ZeroizeOnDrop, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct CMACAES256 {
    /// The key from which all our new keys are derived
    root_key: [u8; 32],
}

impl CMACAES256 {
    /// The number of bytes that the underlying cryptographic primitive generates on each call
    const BLOCK_SIZE: usize = 16;
}

impl KBKDFInit for CMACAES256 {
    fn new(root_key: &[u8; 32]) -> Result<Box<Self>, Error> {
        let mut kbkdf = Self {
            root_key: Default::default(),
        };
        kbkdf.root_key.copy_from_slice(root_key);

        Ok(Box::new(kbkdf))
    }
}

impl KBKDF for CMACAES256 {
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error> {
        let subkey_len = subkey.len();
        let count: u16 = num::Integer::div_ceil(&subkey_len, &CMACAES256::BLOCK_SIZE)
            .try_into()
            .map_err(|e| {
                Error::KeyError(format!(
                    "Attempted to derive key greater than maximum supported size ({e})"
                ))
            })?;
        let mut keygen = Cmac::<Aes256>::new_from_slice(&self.root_key).map_err(|e| {
            Error::KeyError(format!(
                "CAN'T HAPPEN: KBKDF key is of invalid length ({e})"
            ))
        })?;

        let mut key_len_remaining = subkey_len;

        for i in 0..count {
            keygen.update(&i.to_be_bytes());
            keygen.update(b"\0");
            keygen.update(id);

            let key_block = keygen.finalize_reset().into_bytes();
            let key_segment_len = std::cmp::min(key_len_remaining, CMACAES256::BLOCK_SIZE);
            let key_segment = key_block.get(..key_segment_len).ok_or_else(|| Error::InternalError(format!("key_block did not have bytes in range 0..{key_segment_len} in KBKDF.derive_key")))?;

            let subkey_start = check_overflow(usize::from(i).overflowing_mul(CMACAES256::BLOCK_SIZE), &format!("overflow while attempting to determine subkey_start of block {i} (BLOCK_SIZE = {})", CMACAES256::BLOCK_SIZE))?;
            let subkey_end = std::cmp::min(subkey_len, check_overflow(subkey_start.overflowing_add(CMACAES256::BLOCK_SIZE), &format!("overflow while attempting to determine subkey_end of block {i} (BLOCK_SIZE = {})", CMACAES256::BLOCK_SIZE))?);

            let subkey_seg: &mut [u8] = subkey.get_mut(subkey_start..subkey_end).ok_or_else(|| Error::InternalError(format!("subkey did not have bytes in range {subkey_start}..{subkey_end} in KBKDF.derive_key")))?;
            (*subkey_seg).copy_from_slice(key_segment);
            key_len_remaining = check_overflow(key_len_remaining.overflowing_sub(key_segment_len), &format!("key_len_remaining ({key_len_remaining}) < key_segment_len ({key_segment_len}) in KBKDF.derive_key"))?;
        }

        if key_len_remaining == 0 {
            Ok(())
        } else {
            Err(Error::InternalError(
                "key_len_remaining == {key_len_remaining} after KBKDF.derive_key".to_string(),
            ))
        }
    }
}

impl fmt::Debug for CMACAES256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KBKDF")
            .field("key", &"**REDACTED**")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    mod cmacaes256 {
        use super::*;

        #[test]
        fn derive_short_subkey() {
            let key =
                hex!["d742ccd1 686b7bce af5d4183 06efe6d6 fe6e4a1d c73a7ef4 3c8f16fb c07c8999"];
            let mut subkey = [0u8; 4];

            CMACAES256::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"testing")
                .unwrap();

            assert_eq!(hex!["3ba5490a"], subkey);
        }

        #[test]
        fn derive_one_block_subkey() {
            let key =
                hex!["d742ccd1 686b7bce af5d4183 06efe6d6 fe6e4a1d c73a7ef4 3c8f16fb c07c8999"];
            let mut subkey = [0u8; 16];

            CMACAES256::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"blocktest")
                .unwrap();

            assert_eq!(hex!["58844a69 d2e3d790 86770ea1 2fe70c0e"], subkey);
        }

        #[test]
        fn derive_multiblock_subkey() {
            let key =
                hex!["d742ccd1 686b7bce af5d4183 06efe6d6 fe6e4a1d c73a7ef4 3c8f16fb c07c8999"];
            let mut subkey = [0u8; 128];

            CMACAES256::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"yugeblocktest")
                .unwrap();

            assert_eq!(
                hex![
                    "feecb570 6fb7c2b7 7d4c05e3 6f379363 6e8eee75 30986d21 fda0173b e4bab445
                      f7722e79 5b495cae bc3b19f1 fa49b5c5 f35feda0 b2745f42 40706454 58e52c7e
                      77b46fb1 704f0b59 5961bb13 da9adcc2 9c24e1f7 e7577a17 76485614 0b94dcaf
                      57790515 81eee28c 97a5b3f7 a377e10d 43553cfb b245dacf 097818f8 bd28c218
                   "
                ],
                subkey
            );
        }

        #[test]
        fn derive_odd_sized_subkey() {
            let key =
                hex!["d742ccd1 686b7bce af5d4183 06efe6d6 fe6e4a1d c73a7ef4 3c8f16fb c07c8999"];
            let mut subkey = [0u8; 39];

            CMACAES256::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"oddbod")
                .unwrap();

            assert_eq!(
                hex!["cbec9336 64d9230e 975be577 8cc185ec d359e69e 7c4f7020 368146da 154f15e8 630c7d44 720d61"],
                subkey
            );
        }

        #[test]
        fn different_keys_produce_different_subkeys() {
            let k1 = [0u8; 32];
            let k2 = [1u8; 32];

            let mut sk1 = [0u8; 32];
            let mut sk2 = [0u8; 32];

            let id = b"subkey_id";

            CMACAES256::new(&k1)
                .unwrap()
                .derive_key(&mut sk1, id)
                .unwrap();
            CMACAES256::new(&k2)
                .unwrap()
                .derive_key(&mut sk2, id)
                .unwrap();

            assert_ne!(sk1, sk2);

            // Worth just double checking this
            assert_ne!(k1, sk1);
            assert_ne!(k1, sk2);
            assert_ne!(k2, sk1);
            assert_ne!(k2, sk2);
        }
    }
}
