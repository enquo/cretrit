mod cipher;
mod ciphersuite;
mod ciphertext;
mod error;
mod plaintext;

pub use ciphertext::Serializable as SerializableCipherText;
pub use error::Error;
pub use plaintext::PlainText;

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

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
