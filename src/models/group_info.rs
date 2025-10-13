use crate::{
    errors::{Error, Result},
    utils::{deserialize, serialize},
    zero_art_proto,
};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
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
    pub fn new(id: Uuid, name: String, created: DateTime<Utc>, metadata: Vec<u8>) -> Self {
        Self {
            id,
            name,
            created,
            metadata,
            members: GroupMembers::default(),
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
pub struct GroupMembers {
    members: HashMap<String, User>,
    leaf_members: bimap::BiMap<CortadoAffine, String>,
}

impl GroupMembers {
    pub fn insert(&mut self, leaf: CortadoAffine, user: User) {
        let id = user.id().to_string();
        self.members.insert(id.clone(), user);
        self.leaf_members.insert(leaf, id);
    }

    pub fn remove(&mut self, id: &str) -> Option<User> {
        let user = self.members.remove(id);
        self.leaf_members.remove_by_right(id);
        user
    }

    pub fn remove_by_leaf(&mut self, leaf: &CortadoAffine) -> Option<User> {
        let id = self.leaf_members.remove_by_left(leaf)?.1;
        self.members.remove(&id)
    }

    /// Find index of `id` and then replace this key-value with (user.id, user)
    pub fn update_user(&mut self, leaf: CortadoAffine, user: User) -> Option<User> {
        let id = self.leaf_members.get_by_left(&leaf)?;
        let replaced_user = self.members.remove(id)?;

        self.leaf_members.insert(leaf, user.id.to_string());
        self.members.insert(user.id().to_string(), user);

        Some(replaced_user)
    }

    pub fn update_leaf(&mut self, old_leaf: CortadoAffine, new_leaf: CortadoAffine) -> Option<()> {
        let user_id = self.leaf_members.get_by_left(&old_leaf)?.to_owned();
        let _ = self.leaf_members.remove_by_left(&old_leaf)?;
        self.leaf_members.insert(new_leaf, user_id);

        None
    }

    pub fn get(&self, id: &str) -> Option<&User> {
        self.members.get(id)
    }

    pub fn get_leaf(&self, id: &str) -> Option<&CortadoAffine> {
        self.leaf_members.get_by_right(id)
    }

    pub fn get_id(&self, leaf: &CortadoAffine) -> Option<&String> {
        self.leaf_members.get_by_left(leaf)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &User> {
        self.members.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut User> {
        self.members.values_mut()
    }

    pub fn iter_with_ids(&self) -> impl Iterator<Item = (&String, &User)> {
        self.members.iter()
    }
}

impl TryFrom<Vec<zero_art_proto::User>> for GroupMembers {
    type Error = Error;
    fn try_from(value: Vec<zero_art_proto::User>) -> Result<Self> {
        let mut members = GroupMembers::default();

        for proto_user in value {
            let user: User = proto_user.try_into()?;

            let leaf: CortadoAffine = deserialize(&user.metadata)?;

            members.insert(leaf, user);
        }

        Ok(members)
    }
}

impl From<GroupMembers> for Vec<zero_art_proto::User> {
    fn from(value: GroupMembers) -> Self {
        let mut items: Vec<(String, User)> = value.members.into_iter().collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));

        items
            .into_iter()
            .map(|(id, mut user)| {
                user.metadata = serialize(value.leaf_members.get_by_right(&id).unwrap()).unwrap();
                user.into()
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct User {
    id: String,
    name: String,
    public_key: CortadoAffine,
    metadata: Vec<u8>,
    role: Role,
}

impl User {
    pub fn new(name: String, public_key: CortadoAffine, metadata: Vec<u8>) -> Self {
        Self {
            id: public_key_to_id(public_key),
            name,
            public_key,
            metadata,
            role: Role::default(),
        }
    }

    pub fn new_with_id(
        id: String,
        name: String,
        public_key: CortadoAffine,
        metadata: Vec<u8>,
    ) -> Self {
        Self {
            id,
            name,
            public_key,
            metadata,
            role: Role::default(),
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

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn role_mut(&mut self) -> &mut Role {
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
            role: role.into(),
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

#[derive(Debug, Clone, Default, Copy)]
pub enum Role {
    Read,
    #[default]
    Write,
    Ownership,
    Admin,
}

impl From<zero_art_proto::Role> for Role {
    fn from(value: zero_art_proto::Role) -> Self {
        match value {
            zero_art_proto::Role::Read => Self::Read,
            zero_art_proto::Role::Write => Self::Write,
            zero_art_proto::Role::Ownership => Self::Ownership,
            zero_art_proto::Role::Admin => Self::Admin,
        }
    }
}

impl From<Role> for zero_art_proto::Role {
    fn from(value: Role) -> Self {
        match value {
            Role::Read => zero_art_proto::Role::Read,
            Role::Write => zero_art_proto::Role::Write,
            Role::Ownership => zero_art_proto::Role::Ownership,
            Role::Admin => zero_art_proto::Role::Admin,
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
                crate::utils::serialize(public_key).expect("failed to serialize public key"),
            )[..USER_ID_LENGTH / 2],
        )
    }
}
