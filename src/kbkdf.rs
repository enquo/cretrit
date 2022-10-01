use aes::Aes128;
use cmac::{Cmac, Mac};
use zeroize::ZeroizeOnDrop;

use crate::Error;

#[derive(ZeroizeOnDrop)]
#[allow(clippy::upper_case_acronyms)]
pub struct KBKDF {
    key: [u8; 16],
}

const KBKDF_BLOCK_SIZE: usize = 16;

impl KBKDF {
    pub fn new(key: [u8; 16]) -> Result<Self, Error> {
        Ok(KBKDF { key })
    }

    pub fn derive_key(&self, subkey: &mut [u8], id: &[u8]) -> Result<(), Error> {
        let subkey_len = subkey.len();
        let count: u16 = num::Integer::div_ceil(&subkey_len, &KBKDF_BLOCK_SIZE)
            .try_into()
            .map_err(|_| {
                Error::KeyError(
                    "Attempted to derive key greater than maximum supported size".to_string(),
                )
            })?;
        let mut keygen = Cmac::<Aes128>::new_from_slice(&self.key).map_err(|_| {
            Error::KeyError("CAN'T HAPPEN: KBKDF key is of invalid length".to_string())
        })?;

        let mut key_len_remaining: usize = subkey_len;

        for i in 0..count {
            keygen.update(&i.to_be_bytes());
            keygen.update(b"\0");
            keygen.update(id);

            let key_block = keygen.finalize_reset().into_bytes().to_vec();
            let key_segment_len = std::cmp::min(key_len_remaining, KBKDF_BLOCK_SIZE);
            let key_segment = &key_block[..key_segment_len];

            let subkey_start = i as usize * KBKDF_BLOCK_SIZE;
            let subkey_end = std::cmp::min(subkey_len, (i as usize + 1) * KBKDF_BLOCK_SIZE);

            subkey[subkey_start..subkey_end].copy_from_slice(key_segment);
            key_len_remaining -= key_segment_len;
        }

        assert!(key_len_remaining == 0);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn derive_short_subkey() {
        let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
        let mut subkey = [0u8; 4];

        KBKDF::new(key)
            .unwrap()
            .derive_key(&mut subkey, b"testing")
            .unwrap();

        assert_eq!(hex!["152879b9"], subkey);
    }

    #[test]
    fn derive_one_block_subkey() {
        let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
        let mut subkey = [0u8; 16];

        KBKDF::new(key)
            .unwrap()
            .derive_key(&mut subkey, b"blocktest")
            .unwrap();

        assert_eq!(hex!["2cd97a3a 50e559d7 f5cceccc 6b008ce7"], subkey);
    }

    #[test]
    fn derive_multiblock_subkey() {
        let key = hex!["d742ccd1 686b7bce af5d4183 06efe6d6"];
        let mut subkey = [0u8; 128];

        KBKDF::new(key)
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

        KBKDF::new(key)
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
