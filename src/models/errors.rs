use bulletproofs::r1cs::R1CSError;

use crate::utils;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Serialization Error")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Serialization Error")]
    ProtoError(#[from] prost::UnknownEnumValue),
    #[error("Decode Error")]
    ProtoDecodeError(#[from] prost::DecodeError),
    #[error("ART Error")]
    ArtError(#[from] art::errors::ARTError),
    #[error("Utils Error")]
    UtilsError(#[from] utils::Error),

    #[error("Crypto Error")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("R1CS Error")]
    R1CSError(#[from] R1CSError),

    #[error("Required Field Absent")]
    RequiredFieldAbsent,

    #[error("Invalid proof verification method")]
    InvalidVerificationMethod,
}
