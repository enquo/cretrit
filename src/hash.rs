use aes::Aes128;
use cmac::{Cmac, Mac};

use crate::Error;

pub trait HashFunction<const M: u8>: Sized {
    fn hash(key: &[u8], nonce: &[u8]) -> Result<u8, Error>;
}

pub struct CMACAES128HF<const M: u8> {}

impl<const M: u8> HashFunction<M> for CMACAES128HF<M> {
    fn hash(key: &[u8], nonce: &[u8]) -> Result<u8, Error> {
        let mut mac = Cmac::<Aes128>::new_from_slice(key).map_err(|_| {
            Error::KeyError("CMACAES128 received a key of invalid length".to_string())
        })?;
        mac.update(nonce);
        Ok(mac.finalize().into_bytes()[0] % M)
    }
}
