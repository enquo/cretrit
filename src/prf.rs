//! Pseudo-random transposition functionality
//!
//! A big part of the work in the Lewi-Wu CRE scheme is deterministically
//! transforming a chunk of data into a different value, and doing so in
//! a way that is indistinguishable from randomness to anyone who doesn't
//! know the key.
//!
//! This module defines the necessary traits to expose this functionality,
//! as well as (for now, anyway) the available implementations.
//!

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Fill;
use zeroize::Zeroize;

use crate::kbkdf::KBKDF;
use crate::Error;

/// Initialisation of a PRF
pub trait PseudoRandomFunctionInit: Sized + PseudoRandomFunction {
    /// Create a new PRF
    ///
    /// The key, derived from the KBKDF, allows us to have PRFs that are deterministic (as long as
    /// the same key is given) while being totally different for a different key.
    fn new(key: &dyn KBKDF) -> Result<Self, Error>;
}

/// Operation of a PRF
pub trait PseudoRandomFunction: Sized {
    /// The exact type of the block of data that will be returned by randomise()
    ///
    /// In practice this will always be a u8 array of some size
    type BlockType: Default + Copy + Fill + core::fmt::Debug + Into<Vec<u8>> + AsMut<[u8]>;

    /// The number of elements in the block returned from randomise()
    ///
    /// Unsurprisingly, this must match the number of elements in `BlockType`
    const BLOCK_SIZE: usize;

    /// Generate a block of data whose content is dependent on
    /// the value
    ///
    /// Also the key passed to the PRF when it was initialised, of course.
    fn randomise(&self, value: u16, block: &mut Self::BlockType);
}

/// A PRF based on using AES128
#[allow(unreachable_pub)] // I think this is a bug in the lint; see also https://github.com/rust-lang/rust/issues/110923
#[derive(Debug)]
pub struct AES128PRF {
    /// Wot does the encryption -- stored so that we don't have to redo the
    /// keying schedule for every call
    cipher: Aes128,
}

impl PseudoRandomFunctionInit for AES128PRF {
    fn new(kdf: &dyn KBKDF) -> Result<Self, Error> {
        let mut k: [u8; 16] = Default::default();

        kdf.derive_key(&mut k, b"AES128PRF.subkey")?;

        let cipher = Aes128::new(&GenericArray::from(k));
        k.zeroize();

        Ok(AES128PRF { cipher })
    }
}

impl PseudoRandomFunction for AES128PRF {
    type BlockType = [u8; 16];
    const BLOCK_SIZE: usize = 16;

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
