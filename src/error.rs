use ark_serialize::SerializationError;
use art::errors::ARTError;
use bulletproofs::r1cs::R1CSError;
use prost::{DecodeError, UnknownEnumValue};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ART error")]
    ArtError(#[from] ARTError),
    #[error("Serialization error")]
    SerializationError(#[from] SerializationError),
    #[error("Cryptography error")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("Decode error")]
    DecodeError(#[from] DecodeError),
    #[error("HKDF error")]
    HKDFError(#[from] hkdf::InvalidLength),
    #[error("R1CS error")]
    R1CSError(#[from] R1CSError),

    #[error("Invalid verificatio method")]
    InvalidVerificationMethod,

    #[error("Required field absent")]
    RequiredFieldAbsent,

    #[error("AES encryption error")]
    AesError,

    #[error("awd")]
    Errr(#[from] UnknownEnumValue),

    #[error("ART logic error")]
    ARTLogicError,
    #[error("Invalid input provided")]
    InvalidInput,
    #[error("Invalid group")]
    InvalidGroup,
    // #[error("Postcard error: {0}")]
    // Postcard(#[from] postcard::Error),
    // #[error("Serde JSON error: {0}")]
    // SerdeJson(#[from] serde_json::Error),
    // #[error("Node error: {0}")]
    // Node(#[from] ARTNodeError),
    #[error("Can't find path to given node.")]
    PathNotExists,
    #[error("Can't remove the node. It isn't close enough")]
    RemoveError,
    #[error("Failed to convert &[u8] into &[u8;32]: {0}")]
    ConversionError(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point")]
    XCoordinateError,
    #[error("No changes provided in given BranchChanges structure")]
    NoChanges,

    #[error("Invalid epoch")]
    InvalidEpoch,
    #[error("Sender absent in group")]
    InvalidSender,
}

pub type Result<T> = std::result::Result<T, Error>;
