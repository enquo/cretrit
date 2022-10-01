pub mod ere;
pub mod ore;

use rand_chacha::ChaCha20Rng;

use crate::ciphersuite::CipherSuite as SuperSweet;
use crate::hash::CMACAES128HF;
use crate::prf::AES128PRF;
use crate::prp::KnuthShufflePRP;

#[derive(Debug)]
pub struct CipherSuite<const W: u16, const M: u8> {}

impl<const W: u16, const M: u8> SuperSweet<W, M> for CipherSuite<W, M> {
    type RNG = ChaCha20Rng;
    type PRF = AES128PRF;
    type HF = CMACAES128HF<M>;
    type PRP = KnuthShufflePRP<W>;
}
