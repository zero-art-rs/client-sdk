use crate::{
    error::{Error, Result},
    zero_art_proto,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
use indexmap::IndexMap;
use prost::Message;
use std::collections::HashMap;
use uuid::Uuid;

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
pub struct GroupMembers {
    by_id: HashMap<Uuid, User>,
    by_public_key: IndexMap<CortadoAffine, Uuid>,
}

impl GroupMembers {
    pub fn add_user(&mut self, user: User) {
        let id = user.id.clone();
        let key = user.public_key;
        self.by_public_key.insert(key, id.clone());
        self.by_id.insert(id, user);
    }

    pub fn remove_by_id(&mut self, id: &Uuid) -> Option<User> {
        if let Some(user) = self.by_id.remove(id) {
            self.by_public_key.shift_remove(&user.public_key);
            Some(user)
        } else {
            None
        }
    }

    pub fn remove_by_public_key(&mut self, public_key: &CortadoAffine) -> Option<User> {
        if let Some(id) = self.by_public_key.shift_remove(public_key) {
            self.by_id.remove(&id)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn get_by_id(&self, id: &Uuid) -> Option<&User> {
        self.by_id.get(id)
    }

    pub fn get_by_public_key(&self, public_key: &CortadoAffine) -> Option<&User> {
        self.by_public_key
            .get(public_key)
            .and_then(|id| self.by_id.get(id))
    }

    pub fn get_index_by_public_key(&self, public_key: &CortadoAffine) -> Option<usize> {
        self.by_public_key.get_index_of(public_key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &User> {
        self.by_id.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut User> {
        self.by_id.values_mut()
    }

    pub fn iter_with_ids(&self) -> impl Iterator<Item = (&Uuid, &User)> {
        self.by_id.iter()
    }

    pub fn reindex(&mut self, order: HashMap<CortadoAffine, usize>) {
        self.by_public_key
            .sort_by_key(|k, _| order.get(k).unwrap_or(&usize::MAX));
    }
}

impl TryFrom<Vec<zero_art_proto::User>> for GroupMembers {
    type Error = Error;
    fn try_from(value: Vec<zero_art_proto::User>) -> Result<Self> {
        let mut members = GroupMembers::default();

        for proto_user in value {
            let user: User = proto_user.try_into()?;
            members.add_user(user);
        }

        Ok(members)
    }
}

impl From<GroupMembers> for Vec<zero_art_proto::User> {
    fn from(value: GroupMembers) -> Self {
        value.by_id.into_values().map(|user| user.into()).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct User {
    id: Uuid,
    name: String,
    public_key: CortadoAffine,
    metadata: Vec<u8>,
    // ?: Should we create separate enum?
    role: zero_art_proto::Role,
}

impl User {
    pub fn new(
        id: Uuid,
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

    // Getters
    pub fn id(&self) -> Uuid {
        self.id
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
        let public_key = CortadoAffine::deserialize_uncompressed(&value.public_key[..])?;
        let role = zero_art_proto::Role::try_from(value.role)?;

        Ok(Self {
            id: Uuid::parse_str(&value.id).map_err(|_| Error::RequiredFieldAbsent)?,
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
            id: value.id.to_string(),
            name: value.name,
            public_key: public_key_bytes,
            picture: value.metadata,
            role: value.role as i32,
        }
    }
}
