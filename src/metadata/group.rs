use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::{metadata::user, zero_art_proto};

pub struct GroupInfo {
    id: String,
    name: String,
    created: DateTime<Utc>,
    picture: Vec<u8>,
    users: HashMap<user::Id, user::User>,
}

// TODO: Replace .unwrap() with errors
// TODO: Add TryFrom/From trait impls
impl GroupInfo {
    // pub fn serialize() {

    // }

    // pub fn deserialize() {

    // }

    pub fn to_proto(&self) -> zero_art_proto::GroupInfo {
        let mut public_key_bytes = Vec::new();
        self.public_key
            .serialize_uncompressed(&mut public_key_bytes)
            .unwrap();

        zero_art_proto::GroupInfo {
            id: self.id.0.clone(),
            name: self.name.clone(),
            public_key: public_key_bytes,
            picture: self.picture.clone(),
            role: self.role as i32,
        }
    }

    pub fn from_proto(user: &zero_art_proto::GroupInfo) -> Self {
        let public_key = CortadoAffine::deserialize_uncompressed(&user.public_key[..]).unwrap();
        let role = zero_art_proto::Role::try_from(user.role).unwrap();

        Self {
            id: Id(user.id.clone()),
            name: user.name.clone(),
            public_key,
            picture: user.picture.clone(),
            role,
        }
    }

    pub fn to_proto_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn from_proto_bytes(proto: &[u8]) -> Self {
        Self::from_proto(&zero_art_proto::GroupInfo::decode(proto).unwrap())
    }
}
