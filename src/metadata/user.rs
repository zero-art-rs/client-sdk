use crate::{metadata::error::Error, zero_art_proto};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::CortadoAffine;

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: String,
    pub name: String,
    pub public_key: CortadoAffine,
    pub metadata: Vec<u8>,
    // ?: Should we create separate enum?
    pub role: zero_art_proto::Role,
}

impl User {
    pub fn new(id: String, name: String, metadata: Vec<u8>) -> Self {
        Self {
            id,
            name,
            metadata,
            ..Self::default()
        }
    }
}

impl TryFrom<zero_art_proto::User> for User {
    type Error = Error;

    fn try_from(value: zero_art_proto::User) -> Result<Self, Self::Error> {
        let public_key = CortadoAffine::deserialize_uncompressed(&value.public_key[..])?;
        let role = zero_art_proto::Role::try_from(value.role)?;

        Ok(Self {
            id: value.id,
            name: value.name,
            public_key,
            metadata: value.picture,
            role,
        })
    }
}

impl From<User> for zero_art_proto::User {
    fn from(value: User) -> Self {
        let mut public_key_bytes = Vec::new();
        value
            .public_key
            .serialize_uncompressed(&mut public_key_bytes)
            .unwrap();

        Self {
            id: value.id,
            name: value.name,
            public_key: public_key_bytes,
            picture: value.metadata,
            role: value.role as i32,
        }
    }
}
