use rand::distributions::Uniform;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::ZeroizeOnDrop;

use crate::Error;

use crate::kbkdf::*;

pub trait PseudoRandomPermutationInit<const W: u16>: Sized + PseudoRandomPermutation<W> {
    fn new(key: &KBKDF) -> Result<Self, Error>;
}

pub trait PseudoRandomPermutation<const W: u16>: Sized {
    fn value(&self, data: u16) -> u16;
    fn inverse(&self, data: u16) -> u16;
}

#[derive(ZeroizeOnDrop)]
pub struct KnuthShufflePRP<const W: u16> {
    p: Vec<u16>,
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
            p_1[*val as usize] = idx as u16;
        }

        Ok(KnuthShufflePRP { p, p_1 })
    }
}

impl<const W: u16> PseudoRandomPermutation<W> for KnuthShufflePRP<W> {
    fn value(&self, data: u16) -> u16 {
        self.p[data as usize]
    }

    fn inverse(&self, data: u16) -> u16 {
        self.p_1[data as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> KBKDF {
        KBKDF::new([0u8; 16]).unwrap()
    }

    #[test]
    fn small_shuffle_isnt_a_sequential_list() {
        let prp = KnuthShufflePRP::<16>::new(&kdf()).unwrap();

        assert!(!(0..16).all(|i| prp.value(i) == i));
    }

    #[test]
    fn small_shuffle_round_trips_correctly() {
        let prp = KnuthShufflePRP::<16>::new(&kdf()).unwrap();

        for i in 0..16 {
            assert_eq!(i, prp.inverse(prp.value(i)));
        }
    }
}
