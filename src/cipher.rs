//! Where the `Cipher` lives.
//!

use core::fmt::Debug;
use rand::{Rng, SeedableRng};
use std::cell::RefCell;
use std::marker::PhantomData;

use crate::ciphersuite::CipherSuite;
use crate::ciphertext::CipherText;
use crate::cmp::Comparator;
use crate::kbkdf::KBKDF;
use crate::plaintext::PlainText;
use crate::prf::{PseudoRandomFunction, PseudoRandomFunctionInit};
use crate::prp::{PseudoRandomPermutation, PseudoRandomPermutationInit};
use crate::Error;

/// Something capable of turning [`PlainText`s](crate::PlainText) into comparable
/// [`CipherText`s](crate::CipherText) by means of encryption.
///
/// A Cipher consists of a key, a ciphersuite (which is, itself, a whole bunch of possibilities
/// jammed into one neat little package), a comparator (which defines how ciphertexts can be
/// compared while encrypted), as well as parameters for the number of blocks (`N`), the "width" of
/// each block (the total number of values that each block can represent, `W`), and the number of
/// values that the comparator is able to use to represent comparison values (`M`).
///
/// Since all of this is a heck of a lot to have to specify everytime you want to encrypt
/// something, it's not recommended that you try and use this type directly.  Instead, use the
/// Cipher types provided by the comparison-specific modules defined by each available
/// ciphersuites.  At the moment, those are:
///
/// * [`aes128v1`](crate::aes128v1) -- ciphersuite using AES128 as the primary cryptographic
/// primitive, which provides
///   * [`ere::Cipher`](crate::aes128v1::ere::Cipher) for equality comparisons (`==`, `!=`), and
///   * [`ore::Cipher`](crate::aes128v1::ore::Cipher) for ordering comparisons (`<`, `>`, `<=`,
///   `>=`, `==`, `!=`).
///
///
/// These more-contrained Cipher types only require you to specify the block count and width (`N`
/// and `W`) and the key to use for encryption, which is far more tractable.
///
pub struct Cipher<
    S: CipherSuite<W, M>,
    CMP: Comparator<M>,
    const N: usize,
    const W: u16,
    const M: u8,
> {
    /// The CSPRNG we're using for our random numbers
    rng: RefCell<S::RNG>,

    /// The instance of the PRF in use
    prf: S::PRF,

    /// The instance of the PRP in use
    prp: S::PRP,

    /// Bumf to keep the compiler happy
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
    /// Create a new Cipher.
    ///
    /// All ciphertexts produced with the same key (and all other parameters) can be compared
    /// against each other.  As such, it is just as important that the key used for these
    /// encryptions is as secure and secret as any other cryptographic key.
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub fn new(key: [u8; 16]) -> Result<Self, Error>
    where
        <S as CipherSuite<W, M>>::PRF: PseudoRandomFunctionInit,
        <S as CipherSuite<W, M>>::PRP: PseudoRandomPermutationInit<W>,
    {
        #![allow(clippy::similar_names)] // I think we can keep things clear in here, prf/prp is totes different
        let kbkdf = KBKDF::new(key);

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

    /// Encrypt a value and produce a ciphertext that contains both "left" and "right" parts
    ///
    /// For details on ciphertexts and their components, see the struct-level documentation for
    /// [`CipherText`](crate::CipherText).
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub fn full_encrypt(
        &self,
        value: &PlainText<N, W>,
    ) -> Result<CipherText<'_, S, CMP, N, W, M>, Error> {
        CipherText::<S, CMP, N, W, M>::new(self, value)
    }

    /// Encrypt a value and produce a ciphertext that contains only a "right" part
    ///
    /// For details on ciphertexts and their components, see the struct-level documentation for
    /// [`CipherText`](crate::CipherText).
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub fn right_encrypt(
        &self,
        value: &PlainText<N, W>,
    ) -> Result<CipherText<'_, S, CMP, N, W, M>, Error> {
        CipherText::<S, CMP, N, W, M>::new_right(self, value)
    }

    /// Write a random value into the given slice
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub(crate) fn fill_nonce(&self, nonce: &mut [u8]) -> Result<(), Error> {
        self.rng
            .borrow_mut()
            .try_fill(nonce)
            .map_err(|e| Error::CryptoError(format!("RNG failed to fill random bytes ({e})")))?;

        Ok(())
    }

    /// Calculate the pseudo-random block corresponding to the given value
    ///
    /// Writes the result into the given block, rather than return by value, because the data can
    /// be of non-trivial size, and the caller has already allocated the space anyway.
    ///
    pub(crate) fn pseudorandomise(
        &self,
        value: u16,
        block: &mut <<S as CipherSuite<W, M>>::PRF as PseudoRandomFunction>::BlockType,
    ) {
        self.prf.randomise(value, block);
    }

    /// Return the value->permutation mapping for the given value
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub(crate) fn permuted_value(&self, value: u16) -> Result<u16, Error> {
        if value >= W {
            return Err(Error::RangeError(format!(
                "permuted_value received value={value} greater than block width W={W}"
            )));
        }
        self.prp.value(value)
    }

    /// Return the permutation->value mapping
    ///
    /// # Errors
    ///
    /// Can return an error if any of the underlying cryptographic operations can't complete, or if
    /// there's a bug somewhere.
    ///
    pub(crate) fn inverse_permuted_value(&self, permutation: u16) -> Result<u16, Error> {
        if permutation >= W {
            return Err(Error::RangeError(format!("inverse_permuted_value received permutation={permutation} greater than block width W={W}")));
        }
        self.prp.inverse(permutation)
    }
}
