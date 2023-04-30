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

pub mod aes128v1;

mod bitlist;
mod cmp;
mod hash;
mod kbkdf;
mod prf;
mod prp;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

// Tells unused_crate_dependencies to STFU about the "unused dev dependency"
#[cfg(test)]
use criterion as _;
