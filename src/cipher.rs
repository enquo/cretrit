use core::fmt::Debug;
use rand::{Rng, SeedableRng};
use std::cell::RefCell;
use std::marker::PhantomData;

use crate::ciphersuite::CipherSuite;
use crate::ciphertext::CipherText;
use crate::cmp::Comparator;
use crate::hash::HashFunction;
use crate::kbkdf::KBKDF;
use crate::plaintext::PlainText;
use crate::prf::{PseudoRandomFunction, PseudoRandomFunctionInit};
use crate::prp::{PseudoRandomPermutation, PseudoRandomPermutationInit};
use crate::Error;

pub struct Cipher<
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    rng: RefCell<S::RNG>,
    prf: S::PRF,
    prp: S::PRP,
    _ffs: PhantomData<CMP>,
}

impl<S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8> Debug
    for Cipher<S, CMP, N, W, M>
{
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Ok(())
    }
}

impl<S: CipherSuite<W, M>, CMP: Comparator<M>, const N: usize, const W: u16, const M: u8>
    Cipher<S, CMP, N, W, M>
{
    pub fn new(key: [u8; 16]) -> Result<Self, Error>
    where
        <S as CipherSuite<W, M>>::PRF: PseudoRandomFunctionInit,
        <S as CipherSuite<W, M>>::PRP: PseudoRandomPermutationInit<W>,
    {
        let kbkdf = KBKDF::new(key)?;

        let prf: S::PRF = PseudoRandomFunctionInit::new(&kbkdf)?;
        let prp: S::PRP = PseudoRandomPermutationInit::new(&kbkdf)?;
        let rng: S::RNG = SeedableRng::from_entropy();

        Ok(Cipher {
            rng: RefCell::new(rng),
            prf,
            prp,
            _ffs: PhantomData,
        })
    }

    pub fn new_with_ciphersuite(
        prf: <S as CipherSuite<W, M>>::PRF,
        prp: <S as CipherSuite<W, M>>::PRP,
        rng: <S as CipherSuite<W, M>>::RNG,
    ) -> Result<Self, Error> {
        Ok(Cipher {
            rng: RefCell::new(rng),
            prf,
            prp,
            _ffs: PhantomData,
        })
    }

    pub fn full_encrypt(
        &self,
        value: PlainText<N, W>,
    ) -> Result<CipherText<'_, S, CMP, N, W, M>, Error> {
        CipherText::<S, CMP, N, W, M>::new(self, &value)
    }

    pub fn right_encrypt(
        &self,
        value: PlainText<N, W>,
    ) -> Result<CipherText<'_, S, CMP, N, W, M>, Error> {
        CipherText::<S, CMP, N, W, M>::new_right(self, &value)
    }

    pub(crate) fn fill_nonce(&self, nonce: &mut [u8]) -> Result<(), Error> {
        self.rng
            .borrow_mut()
            .try_fill(nonce)
            .map_err(|_| Error::CryptoError("RNG failed to fill random bytes".to_string()))?;

        Ok(())
    }

    pub(crate) fn pseudorandomise(
        &self,
        value: u16,
        block: &mut <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType,
    ) {
        self.prf.randomise(value, block);
    }

    pub(crate) fn hashed_value(&self, key: &[u8], nonce: &[u8]) -> Result<u8, Error> {
        S::HF::hash(key, nonce)
    }

    pub(crate) fn permuted_value(&self, value: u16) -> u16 {
        assert!(value < W, "{value} < {W} violated");
        self.prp.value(value)
    }

    pub(crate) fn inverse_permuted_value(&self, value: u16) -> u16 {
        assert!(value < W, "{value} < {W} violated");
        self.prp.inverse(value)
    }

    pub(crate) fn compare_values(&self, a: u16, b: u16) -> u8 {
        CMP::compare(a, b)
    }
}
