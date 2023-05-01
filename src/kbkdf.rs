//! Key-based Key Derivation
//!
//! With a hash function, and some guidance from NIST SP800-108, one can derive new keys from an
//! existing key, as many as one might like.  Very handy stuff when you need a lot of keys, and
//! would rather not spend a fortune on KMS.
//!

use aes::Aes128;
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
    fn new(root_key: &[u8]) -> Result<Box<Self>, Error>;
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

/// A KBKDF based on CMACAES128
///
/// NIST SP800-108 has caveats around using CMAC, however those caveats don't apply to our use, and
/// AES-128 is typically hardware accelerated, giving a performance boost over a construction using
/// HMAC SHA-256, for example.
///
#[derive(ZeroizeOnDrop)]
#[allow(clippy::upper_case_acronyms)]
pub struct CMACAES128 {
    /// The key from which all our new keys are derived
    root_key: [u8; 16],
}

/// The number of bytes that the underlying cryptographic primitive generates on each call
const KBKDF_BLOCK_SIZE: usize = 16;

impl KBKDFInit for CMACAES128 {
    fn new(root_key: &[u8]) -> Result<Box<Self>, Error> {
        if root_key.len() != 16 {
            return Err(Error::KeyError(format!(
                "key for a CMACAES128 KBKDF must be exactly 16 bytes (got {})",
                root_key.len()
            )));
        }

        let mut kbkdf = Self {
            root_key: Default::default(),
        };
        kbkdf.root_key.copy_from_slice(root_key);

        Ok(Box::new(kbkdf))
    }
}

impl KBKDF for CMACAES128 {
    fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error> {
        let subkey_len = subkey.len();
        let count: u16 = num::Integer::div_ceil(&subkey_len, &KBKDF_BLOCK_SIZE)
            .try_into()
            .map_err(|e| {
                Error::KeyError(format!(
                    "Attempted to derive key greater than maximum supported size ({e})"
                ))
            })?;
        let mut keygen = Cmac::<Aes128>::new_from_slice(&self.root_key).map_err(|e| {
            Error::KeyError(format!(
                "CAN'T HAPPEN: KBKDF key is of invalid length ({e})"
            ))
        })?;

        let mut key_len_remaining: usize = subkey_len;

        for i in 0..count {
            keygen.update(&i.to_be_bytes());
            keygen.update(b"\0");
            keygen.update(id);

            let key_block = keygen.finalize_reset().into_bytes().to_vec();
            let key_segment_len = std::cmp::min(key_len_remaining, KBKDF_BLOCK_SIZE);
            let key_segment = key_block.get(..key_segment_len).ok_or_else(|| Error::InternalError(format!("key_block did not have bytes in range 0..{key_segment_len} in KBKDF.derive_key")))?;

            let subkey_start = check_overflow(usize::from(i).overflowing_mul(KBKDF_BLOCK_SIZE), &format!("overflow while attempting to determine subkey_start of block {i} (BLOCK_SIZE = {KBKDF_BLOCK_SIZE})"))?;
            let subkey_end = std::cmp::min(subkey_len, check_overflow(subkey_start.overflowing_add(KBKDF_BLOCK_SIZE), &format!("overflow while attempting to determine subkey_end of block {i} (BLOCK_SIZE = {KBKDF_BLOCK_SIZE})"))?);

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

impl fmt::Debug for CMACAES128 {
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

    mod cmacaes128 {
        use super::*;

        #[test]
        fn derive_short_subkey() {
            let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
            let mut subkey = [0u8; 4];

            CMACAES128::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"testing")
                .unwrap();

            assert_eq!(hex!["152879b9"], subkey);
        }

        #[test]
        fn derive_one_block_subkey() {
            let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
            let mut subkey = [0u8; 16];

            CMACAES128::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"blocktest")
                .unwrap();

            assert_eq!(hex!["2cd97a3a 50e559d7 f5cceccc 6b008ce7"], subkey);
        }

        #[test]
        fn derive_multiblock_subkey() {
            let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
            let mut subkey = [0u8; 128];

            CMACAES128::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"yugeblocktest")
                .unwrap();

            assert_eq!(
                hex![
                    "f3b2707c 81d7915d 6a24ade4 5d09dc25
                      10e1f77d a720a63e bc0f58b7 05c329ed
                      b4d00b54 83f553e5 8d35fb52 0d97d2dd
                      2ae16e9f dcb88664 27d4d3bd d78c1be0
                      18dfebb8 58698cf9 492caa4c 6a0d7552
                      9ba4bb06 d003eaf0 12f97eb2 e8c21e4a
                      389b00e9 d3dae4ad d1546eed 679d5b16
                      6744c064 5ca26639 9ef24733 7f0de875
                "
                ],
                subkey
            );
        }

        #[test]
        fn derive_odd_sized_subkey() {
            let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
            let mut subkey = [0u8; 39];

            CMACAES128::new(&key)
                .unwrap()
                .derive_key(&mut subkey, b"oddbod")
                .unwrap();

            assert_eq!(
                hex![
                    "6219883e c4a3d6c4 8463f593 8002b2a9
                      8b63f33a 1023193a 38961489 1fa40380
                      6c24ff49 374d68
                "
                ],
                subkey
            );
        }
    }
}
