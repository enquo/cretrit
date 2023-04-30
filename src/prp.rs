//! Everything you ever wanted to permute
//!
//! Elements of the CRE algorithm require the ability to deterministically permute a value to another
//! value in the same range.  This is the module that contains everything you need to do that.
//!

use rand::distributions::Uniform;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fmt;
use zeroize::ZeroizeOnDrop;

use crate::Error;

use crate::kbkdf::KBKDF;

/// Functionality for an initialising PRP
pub trait PseudoRandomPermutationInit<const W: u16>: Sized + PseudoRandomPermutation<W> {
    /// Create a new PRP
    ///
    /// The PRP is initialised with a subkey from the KBKDF, so that PRPs
    /// for different purposes end up with different permutations, while still
    /// being deterministic whenever they're given the same key.
    fn new(key: &KBKDF) -> Result<Self, Error>;
}

/// Functionality for a PRP
pub trait PseudoRandomPermutation<const W: u16>: Sized {
    /// Fetch the permuted value for a given data value, data -> permutation
    fn value(&self, data: u16) -> Result<u16, Error>;
    /// Fetch the value for which the given data is the permutation, ie permutation -> value
    fn inverse(&self, data: u16) -> Result<u16, Error>;
}

/// A pseudo-random permutation based on the "Knuth" shuffle (aka Fisher-Yates Shuffle, but that's
/// more of a mouthful)
#[allow(unreachable_pub)] // I think this is a bug in the lint; see also https://github.com/rust-lang/rust/issues/110923
#[derive(ZeroizeOnDrop)]
#[doc(hidden)]
pub struct KnuthShufflePRP<const W: u16> {
    /// The "forward" direction lookup of value -> permutation
    p: Vec<u16>,
    /// The "inverse" direction lookup, of permutation -> value
    p_1: Vec<u16>,
}

impl<const W: u16> PseudoRandomPermutationInit<W> for KnuthShufflePRP<W> {
    fn new(kdf: &KBKDF) -> Result<Self, Error> {
        let mut seed: [u8; 32] = Default::default();
        kdf.derive_key(&mut seed, b"KnuthShufflePRP.rngseed")?;
        let rng: ChaCha20Rng = SeedableRng::from_seed(seed);

        let mut p: Vec<u16> = (0..W).collect();
        let mut p_1 = vec![0u16; W as usize];

        let sample_range = Uniform::from(0..W);
        for (idx, val) in rng.sample_iter(sample_range).take(W as usize).enumerate() {
            p.swap(idx, val as usize);
        }

        // In theory, it should be possible to construct p_1 in the main loop
        // above, but I'll be jiggered if I can figure out how, so we do an
        // extra loop
        for (idx, val) in p.iter().enumerate() {
            let v = p_1.get_mut(*val as usize).ok_or_else(|| {
                Error::InternalError(format!(
                    "attempted to set element {val} of p_1 array which only has {W} values"
                ))
            })?;
            *v = u16::try_from(idx).map_err(|e| Error::RangeError(e.to_string()))?;
        }

        Ok(KnuthShufflePRP { p, p_1 })
    }
}

impl<const W: u16> fmt::Debug for KnuthShufflePRP<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(&format!("KnuthShufflePRP<W: {W}>"))
            .finish_non_exhaustive()
    }
}

impl<const W: u16> PseudoRandomPermutation<W> for KnuthShufflePRP<W> {
    fn value(&self, data: u16) -> Result<u16, Error> {
        self.p
            .get(data as usize)
            .ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to retrieve element {data} from p array which only has {} values",
                    self.p.len()
                ))
            })
            .copied()
    }

    fn inverse(&self, data: u16) -> Result<u16, Error> {
        self.p_1
            .get(data as usize)
            .ok_or_else(|| {
                Error::RangeError(format!(
                    "attempted to retrieve element {data} from p_1 array which only has {} values",
                    self.p_1.len()
                ))
            })
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KBKDF {
        KBKDF::new([0u8; 16])
    }

    #[test]
    fn small_shuffle_isnt_a_sequential_list() {
        let prp = KnuthShufflePRP::<16>::new(&kdf()).unwrap();

        assert!(!(0..16).all(|i| prp.value(i).unwrap() == i));
    }

    #[test]
    fn small_shuffle_round_trips_correctly() {
        let prp = KnuthShufflePRP::<16>::new(&kdf()).unwrap();

        for i in 0..16 {
            assert_eq!(i, prp.inverse(prp.value(i).unwrap()).unwrap());
        }
    }
}
