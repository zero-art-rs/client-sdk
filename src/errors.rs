use ark_serialize::SerializationError;
use bulletproofs::r1cs::R1CSError;
use prost::{DecodeError, UnknownEnumValue};
use thiserror::Error;
use zrt_art::errors::ArtError;
use zrt_zk::errors::ZKError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ART error")]
    ArtError(#[from] ArtError),
    #[error("Serialization error")]
    SerializationError(#[from] SerializationError),
    #[error("Cryptography error")]
    CryptoError(#[from] zrt_crypto::CryptoError),
    #[error("Decode error")]
    DecodeError(#[from] DecodeError),
    #[error("HKDF error")]
    HKDFError(#[from] hkdf::InvalidLength),
    #[error("R1CS error")]
    R1CSError(#[from] R1CSError),
    #[error("Invalid verification method")]
    InvalidVerificationMethod,
    #[error("Required field absent")]
    RequiredFieldAbsent,
    #[error("AES encryption error")]
    AesEncryptionError,
    #[error("AES decryption error")]
    AesDecryptionError,
    #[error("Unknown enum value")]
    UnknownEnumError(#[from] UnknownEnumValue),
    #[error("ART logic error")]
    ArtLogicError,
    #[error("Invalid input provided")]
    InvalidInput,
    #[error("Invalid group")]
    InvalidGroup,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid node")]
    InvalidNode,
    #[error("Path to the given node does not exist")]
    PathNotFound,
    #[error("Cannot remove the node: insufficient proximity")]
    NodeRemovalError,
    #[error("Failed to convert &[u8] into &[u8;32]: {0}")]
    ConversionError(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point")]
    PointCoordinateError,
    #[error("No changes provided in the BranchChanges structure")]
    NoChangesProvided,
    #[error("Invalid epoch")]
    InvalidEpoch,
    #[error("Sender is not a member of the group")]
    SenderNotInGroup,
    #[error("Postcard serialization error")]
    PostcardError(#[from] postcard::Error),
    #[error("User removed from group")]
    UserRemovedFromGroup,
    #[error("User don't have permission for action")]
    Forbidden,
    #[error("Failure in prover core")]
    ZK(#[from] ZKError),

    #[error("Changes already applied or merged")]
    ChangesAlreadyApplied,
}

pub type Result<T> = std::result::Result<T, Error>;
