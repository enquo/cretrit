use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Fill;
use zeroize::Zeroize;

use crate::kbkdf::*;
use crate::Error;

pub trait PseudoRandomFunction: Sized {
    type BlockType: Default + Copy + Fill + core::fmt::Debug + Into<Vec<u8>> + AsMut<[u8]>;
    const BLOCK_SIZE: usize;

    fn new(key: &KBKDF) -> Result<Self, Error>;
    fn randomise(&self, value: u16, block: &mut Self::BlockType);
}

pub struct AES128PRF {
    cipher: Aes128,
}

impl PseudoRandomFunction for AES128PRF {
    type BlockType = [u8; 16];
    const BLOCK_SIZE: usize = 16;

    fn new(kdf: &KBKDF) -> Result<Self, Error> {
        let mut k: [u8; 16] = Default::default();

        kdf.derive_key(&mut k, b"AES128PRF.subkey")?;

        let cipher = Aes128::new(&GenericArray::from(k));
        k.zeroize();

        Ok(AES128PRF { cipher })
    }

    fn randomise(&self, value: u16, block: &mut Self::BlockType) {
        let mut a = [0u8; 16];
        let v = value.to_be_bytes();
        a[0] = v[0];
        a[1] = v[1];
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut a));
        block.copy_from_slice(a.as_slice());
    }
}
