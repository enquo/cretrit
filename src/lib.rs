#![doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

mod cipher;
mod ciphersuite;
mod ciphertext;
mod error;
mod plaintext;
mod util;

#[doc(inline)]
pub use {
    cipher::Cipher, ciphertext::CipherText, ciphertext::Serializable as SerializableCipherText,
    error::Error, plaintext::PlainText,
};

#[doc(hidden)]
// For some reason, every *other* trait gets exported automatically, but this trait isn't.
// But it's really an implementation detail, and shouldn't be part of the public API, so let's at
// least hide it from the crate docs.
pub use kbkdf::KBKDFInit;

pub mod aes128v1;

mod bitlist;
mod cmp;
mod hash;
mod prf;
mod prp;

#[doc(hidden)]
pub mod kbkdf;

#[cfg(feature = "serde")]
mod serde;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

// Tells unused_crate_dependencies to STFU about the "unused dev dependency"
#[cfg(test)]
use criterion as _;
#[cfg(test)]
use serde_json as _;
