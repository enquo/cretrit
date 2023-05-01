//! Comparison-Revealing Encryption using AES128 as the Pseudo-Random Function and Hash Function.
//!
//! The module provides two comparison functions, one for orderable ciphertexts (in the [`ore`]
//! module) and one for ciphertexts that only have to be compared for equality (in the [`ere`]
//! module).
//!
//! Order-revealing encryption (ORE) is more versatile, but produces ciphertexts which are around
//! 60% larger than those produced by equality-revealing encryption (ERE).  Thus, if you know you
//! only need equality comparisons, choosing ERE will give you more data for your disk space.

pub mod ere;
pub mod ore;

use rand_chacha::ChaCha20Rng;

use crate::ciphersuite::CipherSuite as SuperSweet;
use crate::{hash, kbkdf, prf, prp};

/// The full set of parameters that make up the [`aes128v1`](super) ciphersuite.
///
/// This struct simply represents the concrete choices about which cryptographic operators to use
/// for the various parts of the Comparison-Revealing Encryption system.  These can *never* change;
/// if anything needs to change, for any reason, a new ciphersuite is defined with the different
/// parameters.
///
#[derive(Debug)]
#[non_exhaustive]
pub struct CipherSuite<const W: u16, const M: u8> {}

impl<const W: u16, const M: u8> SuperSweet<W, M> for CipherSuite<W, M> {
    type RNG = ChaCha20Rng;
    type PRF = prf::AES128PRF;
    type HF = hash::CMACAES128HF<M>;
    type PRP = prp::RandShufflePRP<W>;
    type KBKDF = kbkdf::CMACAES128;
}
