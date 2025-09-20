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

    #[error("Required Field Absent")]
    RequiredFieldAbsent,
}
