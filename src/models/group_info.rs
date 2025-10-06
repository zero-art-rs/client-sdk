use crate::{
    error::{Error, Result},
    utils::{deserialize, serialize},
    zero_art_proto,
};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
use indexmap::IndexMap;
use prost::Message;
use sha3::Digest;
use std::collections::HashMap;
use uuid::Uuid;

const USER_ID_LENGTH: usize = 32;

#[derive(Debug, Default, Clone)]
pub struct GroupInfo {
    id: Uuid,
    name: String,
    created: DateTime<Utc>,
    metadata: Vec<u8>,
    members: GroupMembers,
}

impl GroupInfo {
    pub fn new(
        id: Uuid,
        name: String,
        created: DateTime<Utc>,
        metadata: Vec<u8>,
        members: GroupMembers,
    ) -> Self {
        Self {
            id,
            name,
            created,
            metadata,
            members,
        }
    }

    // Getters
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    pub fn members(&self) -> &GroupMembers {
        &self.members
    }

    pub fn members_mut(&mut self) -> &mut GroupMembers {
        &mut self.members
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let inner: zero_art_proto::GroupInfo = self.clone().into();
        inner.encode_to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::GroupInfo::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::GroupInfo> for GroupInfo {
    type Error = Error;

    fn try_from(value: zero_art_proto::GroupInfo) -> Result<Self> {
        let timestamp_proto = value.created.ok_or(Error::RequiredFieldAbsent)?;
        let created =
            DateTime::from_timestamp(timestamp_proto.seconds, timestamp_proto.nanos as u32)
                .ok_or(Error::RequiredFieldAbsent)?;

        Ok(Self {
            id: Uuid::parse_str(&value.id).map_err(|_| Error::RequiredFieldAbsent)?,
            name: value.name,
            created,
            metadata: value.picture,
            members: value.members.try_into()?,
        })
    }
}

impl From<GroupInfo> for zero_art_proto::GroupInfo {
    fn from(value: GroupInfo) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            created: Some(prost_types::Timestamp {
                seconds: value.created.timestamp(),
                nanos: value.created.timestamp_subsec_nanos() as i32,
            }),
            picture: value.metadata,
            members: value.members.into(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct GroupMembers(IndexMap<String, User>);

impl GroupMembers {
    pub fn insert(&mut self, id: String, user: User) {
        self.0.insert(id, user);
    }

    pub fn remove(&mut self, id: &str) -> Option<User> {
        self.0.shift_remove(id)
    }

    /// Find index of `id` and then replace this key-value with (user.id, user)
    pub fn replace(&mut self, id: &str, user: User) -> Option<User> {
        if let Some(index) = self.0.get_index_of(id) {
            let (_, replaced_user) = self.0.swap_remove_index(index)?;

            let (insert_index, _) = self.0.insert_full(user.id().to_string(), user);

            if insert_index != index {
                self.0.swap_indices(insert_index, index);
            }

            Some(replaced_user)
        } else {
            None
        }
        // self.0.insert(id, user);
        // Some(self.0.swap_remove_index(index)?.1)
    }

    pub fn reorder(&mut self, keys_indexes: HashMap<String, usize>) {
        self.0
            .sort_by_key(|k, _| *keys_indexes.get(k).unwrap_or(&usize::MAX));
    }

    pub fn get(&self, id: &str) -> Option<&User> {
        self.0.get(id)
    }

    pub fn get_by_index(&self, index: usize) -> Option<(&String, &User)> {
        self.0.get_index(index)
    }

    pub fn get_index_by_id(&self, id: &str) -> Option<usize> {
        self.0.get_index_of(id)
    }

    pub fn get_by_public_key(&self, public_key: &CortadoAffine) -> Option<&User> {
        self.0.get(&public_key_to_id(*public_key))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &User> {
        self.0.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut User> {
        self.0.values_mut()
    }

    pub fn iter_with_ids(&self) -> impl Iterator<Item = (&String, &User)> {
        self.0.iter()
    }
}

impl TryFrom<Vec<zero_art_proto::User>> for GroupMembers {
    type Error = Error;
    fn try_from(value: Vec<zero_art_proto::User>) -> Result<Self> {
        let mut members = GroupMembers::default();

        for proto_user in value {
            let user: User = proto_user.try_into()?;
            members.insert(user.id().to_string(), user);
        }

        Ok(members)
    }
}

impl From<GroupMembers> for Vec<zero_art_proto::User> {
    fn from(value: GroupMembers) -> Self {
        value.0.into_values().map(|user| user.into()).collect()
    }
}

impl From<Vec<User>> for GroupMembers {
    fn from(users: Vec<User>) -> Self {
        let mut gm = GroupMembers::default();
        for user in users.into_iter() {
            gm.insert(user.id().to_string(), user);
        }
        gm
    }
}

#[derive(Debug, Clone, Default)]
pub struct User {
    id: String,
    name: String,
    public_key: CortadoAffine,
    metadata: Vec<u8>,
    role: zero_art_proto::Role,
}

impl User {
    pub fn new(
        name: String,
        public_key: CortadoAffine,
        metadata: Vec<u8>,
        role: zero_art_proto::Role,
    ) -> Self {
        Self {
            id: public_key_to_id(public_key),
            name,
            public_key,
            metadata,
            role,
        }
    }

    pub fn new_with_id(
        id: String,
        name: String,
        public_key: CortadoAffine,
        metadata: Vec<u8>,
        role: zero_art_proto::Role,
    ) -> Self {
        Self {
            id,
            name,
            public_key,
            metadata,
            role,
        }
    }

    pub fn is_pending_invite(&self) -> bool {
        self.public_key == CortadoAffine::default()
    }

    // Getters
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> CortadoAffine {
        self.public_key
    }

    pub fn public_key_mut(&mut self) -> &mut CortadoAffine {
        &mut self.public_key
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    pub fn role(&self) -> zero_art_proto::Role {
        self.role
    }

    pub fn role_mut(&mut self) -> &mut zero_art_proto::Role {
        &mut self.role
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let inner: zero_art_proto::User = self.clone().into();
        inner.encode_to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::User::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::User> for User {
    type Error = Error;

    fn try_from(value: zero_art_proto::User) -> Result<Self> {
        let public_key = deserialize(&value.public_key)?;
        let role = zero_art_proto::Role::try_from(value.role)?;
        if value.id.len() != USER_ID_LENGTH || !value.id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput);
        }

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
        Self {
            id: value.id,
            name: value.name,
            public_key: serialize(value.public_key).unwrap(),
            picture: value.metadata,
            role: value.role as i32,
        }
    }
}

pub fn public_key_to_id(public_key: CortadoAffine) -> String {
    if public_key == CortadoAffine::default() {
        hex::encode(rand::random::<[u8; USER_ID_LENGTH / 2]>())
    } else {
        // TODO: Remove expect
        hex::encode(
            &sha3::Sha3_256::digest(
                &crate::utils::serialize(public_key).expect("failed to serialize public key"),
            )[..USER_ID_LENGTH / 2],
        )
    }
}
