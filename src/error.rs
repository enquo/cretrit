//! Defines the Error type for everything Cretrit.

use thiserror::Error;

/// Error type for all Cretrit operations
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    /// The key provided was not useable, or a key derivation operation was not successful
    #[error("invalid key: {0}")]
    KeyError(String),

    /// There was a problem performing some sort of cryptographic operation
    #[error("a cryptographic primitive failed: {0}")]
    CryptoError(String),

    /// A comparison operation could not be completed
    #[error("a problem occurred during comparison: {0}")]
    ComparisonError(String),

    /// The serialized data provided as a ciphertext was not valid
    #[error("could not parse ciphertext: {0}")]
    ParseError(String),

    /// Something tried to walk off the end of an array
    #[error("{0}")]
    RangeError(String),

    /// Arithmetic overflow (or underflow)
    #[error("{0}")]
    OverflowError(String),

    /// Congratulations, you've found a bug!
    #[error("Internal error: {0} (please report as a bug)")]
    InternalError(String),
}
