use rand::{Rng, SeedableRng};

use crate::hash::HashFunction;
use crate::prf::PseudoRandomFunction;
use crate::prp::PseudoRandomPermutation;

pub trait CipherSuite<const W: u16, const M: u8> {
    type RNG: Rng + SeedableRng;
    type PRF: PseudoRandomFunction;
    type HF: HashFunction<M>;
    type PRP: PseudoRandomPermutation<W>;
}
