//! Hash function trait and implementations
//!
//! Some parts of the CRE scheme require the use of a keyed hash function.
//!
//! These are their stories.
//!
//! (dum dum)

use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::Error;

/// Defines what you need to do in order to be a hash function
#[allow(unreachable_pub)]
// I can't help thinking this is a bug in the lint; see https://github.com/rust-lang/rust/issues/110923
#[allow(clippy::module_name_repetitions)] // it's a trait, get over it
pub trait HashFunction<const M: u8>: Sized {
    /// Turns a nonce and a key into a smol value (between 0 and M-1 inclusive, as it happens)
    fn hash(key: &[u8], nonce: &[u8]) -> Result<u8, Error>;
}

/// A "hash" function based on CMAC with AES128.
///
/// This is likely to be quicker in most cases than, say, HMAC-SHA256, because AES128 has hardware
/// acceleration.
#[allow(unreachable_pub)] // I think this is a bug in the lint; see also https://github.com/rust-lang/rust/issues/110923
#[derive(Debug)]
pub struct CMACAES128HF<const M: u8> {}

impl<const M: u8> HashFunction<M> for CMACAES128HF<M> {
    fn hash(key: &[u8], input: &[u8]) -> Result<u8, Error> {
        let mut mac = Cmac::<Aes128>::new_from_slice(key).map_err(|e| {
            Error::KeyError(format!(
                "CMACAES128HF received a key of invalid length ({e})"
            ))
        })?;
        mac.update(input);
        mac.finalize()
            .into_bytes()
            .first()
            .ok_or_else(|| Error::InternalError("CMACAES128HF returned no data?!?".to_string()))?
            .checked_rem(M)
            .ok_or_else(|| Error::RangeError("M cannot be 0".to_string()))
    }
}
