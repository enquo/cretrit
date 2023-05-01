//! The home of the `CipherSuite` trait.
//!

use rand::{CryptoRng, Rng, SeedableRng};

use crate::hash::HashFunction;
use crate::kbkdf::{KBKDFInit, KBKDF};
use crate::prf::PseudoRandomFunction;
use crate::prp::PseudoRandomPermutation;

/// The collection of cryptographic primitives required to produce a comparable ciphertext.
///
/// The Lewi-Wu comparison-revealing encryption scheme requires several operations to do its thing.
/// As changing any one of those primitives changes the output of the scheme, it's important to be
/// able to refer to the collection of primitives as a cohesive unit, so as to fully define an
/// implementation in terms of its primitives.
///
pub trait CipherSuite<const W: u16, const M: u8> {
    /// The random-number generator
    ///
    /// A quality RNG is required both for generating random values (like nonces), but also as a
    /// source of *deterministic* randomness, by being seeded by a key of some kind.
    ///
    type RNG: Rng + SeedableRng + CryptoRng;

    /// The pseudo-random function
    ///
    /// This is a weird term, really, but it's what the Lewi-Wu paper calls it, so we stick with
    /// the same convention.  Essentially, it's a way of deterministically translating an input to
    /// an output, in such a way that the output *looks* random, but... isn't, really.  It takes a
    /// key so that the translation of input->output is different for different keys.
    ///
    /// Annoyingly, a (keyed) cryptographic hash function is a quite reasonable pseudo-random
    /// function, but although we have one of those, too, this one is the *pseudo-random* function,
    /// and not the hash function.  The difference is that the PRF generates a large block of data
    /// for a given (small) input, while the hash function produces a small value from a large input.
    ///
    type PRF: PseudoRandomFunction;

    /// The hash function
    ///
    /// Turns a large input (specifically, the block nonce) into a small input.  See the `PRF`
    /// field for more details on how this is different to that.
    ///
    type HF: HashFunction<M>;

    /// The pseudo-random permutation
    ///
    /// Produces a (reversible) mapping of all values in a domain to other values within that same
    /// domain.  The PRP is also keyed, so that if you give it a different key, the same input set
    /// will be "scrambled" differently.
    ///
    type PRP: PseudoRandomPermutation<W>;

    /// The key-based key derivation function
    ///
    /// How we generate subkeys from a "root" key for the various cryptographic operations is an
    /// important property of the ciphersuite -- a differently-behaving KBKDF will produce
    /// completely different ciphertexts.
    ///
    type KBKDF: KBKDF + KBKDFInit;
}
