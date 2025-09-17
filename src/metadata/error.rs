use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Serialization Error")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Serialization Error")]
    ProtoError(#[from] prost::UnknownEnumValue),
    #[error("Required Field Absent")]
    RequiredFieldAbsent,
}
