use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key: {0}")]
    KeyError(String),

    #[error("a cryptographic primitive failed: {0}")]
    CryptoError(String),

    #[error("a problem occurred during comparison: {0}")]
    ComparisonError(String),

    #[error("could not parse ciphertext: {0}")]
    ParseError(String),
}
