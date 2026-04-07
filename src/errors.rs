use halo2_proofs::plonk::Error as PlonkError;
use thiserror::Error;

/// Errors that can occur during ballot construction, validation, or decryption.
#[derive(Error, Debug)]
pub enum VoteError {
    /// A Halo2/PLONK proof system error (keygen, proving, or verification failure).
    #[error(transparent)]
    PlonkError(#[from] PlonkError),

    /// The ballot data is malformed or fails a validity check.
    #[error("Invalid Ballot: {0}")]
    InvalidBallot(String),

    /// A spend-auth or binding signature failed verification.
    #[error("Invalid Signature: {0}")]
    InvalidSignature(String),

    /// A cryptographic key is invalid (e.g. not on the curve or wrong encoding).
    #[error("Invalid Key: {0}")]
    InvalidKey(String),

    /// Note decryption failed (wrong key or corrupt ciphertext).
    #[error("Decryption Error")]
    DecryptionError,

    /// A caller-supplied input value is out of range or otherwise invalid.
    #[error("Input Error")]
    InputError,

    /// The selected notes do not cover the requested vote amount.
    #[error("Not Enough Funds")]
    NotEnoughFunds,
}
