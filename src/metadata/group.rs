use crate::{
    metadata::{error::Error, user::User},
    zero_art_proto,
};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Default, Clone)]
pub struct GroupMembers {
    by_id: HashMap<String, User>,
    by_public_key: HashMap<CortadoAffine, String>,
}

impl GroupMembers {
    pub fn add_user(&mut self, user: User) {
        let id = user.id.clone();
        let key = user.public_key;
        self.by_public_key.insert(key, id.clone());
        self.by_id.insert(id, user);
    }

    pub fn remove_by_id(&mut self, id: &str) -> Option<User> {
        if let Some(user) = self.by_id.remove(id) {
            self.by_public_key.remove(&user.public_key);
            Some(user)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn get_by_id(&self, id: &str) -> Option<&User> {
        self.by_id.get(id)
    }

    pub fn get_by_public_key(&self, public_key: &CortadoAffine) -> Option<&User> {
        self.by_public_key
            .get(public_key)
            .and_then(|id| self.by_id.get(id))
    }

    pub fn iter(&self) -> impl Iterator<Item = &User> {
        self.by_id.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut User> {
        self.by_id.values_mut()
    }

    pub fn iter_with_ids(&self) -> impl Iterator<Item = (&String, &User)> {
        self.by_id.iter()
    }
}

impl TryFrom<Vec<zero_art_proto::User>> for GroupMembers {
    type Error = Error;
    fn try_from(value: Vec<zero_art_proto::User>) -> Result<Self, Self::Error> {
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

#[derive(Debug, Default, Clone)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub created: DateTime<Utc>,
    pub metadata: Vec<u8>,
    pub members: GroupMembers,
}

impl GroupInfo {
    pub fn new(id: Uuid, name: String, metadata: Vec<u8>) -> Self {
        Self {
            id,
            name,
            created: Utc::now(),
            metadata,
            members: GroupMembers::default(),
        }
    }
}

impl TryFrom<zero_art_proto::GroupInfo> for GroupInfo {
    type Error = Error;

    fn try_from(value: zero_art_proto::GroupInfo) -> Result<Self, Self::Error> {
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
