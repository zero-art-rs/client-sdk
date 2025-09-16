use indexmap::IndexMap;

use chrono::{DateTime, Utc};
use prost::Message;

use crate::{
    metadata::user::{self, User},
    zero_art_proto,
};

#[derive(Default)]
pub struct GroupInfoBuilder(GroupInfo);

impl GroupInfoBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(mut self, id: String) -> Self {
        self.0.id = id;
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.0.name = name;
        self
    }

    pub fn picture(mut self, picture: Vec<u8>) -> Self {
        self.0.picture = picture;
        self
    }

    pub fn build(self) -> GroupInfo {
        self.0
    }
}

#[derive(Default, Clone)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub created: DateTime<Utc>,
    pub picture: Vec<u8>,
    pub members: IndexMap<String, user::User>,
}

// TODO: Replace .unwrap() with errors
// TODO: Add TryFrom/From trait impls
impl GroupInfo {
    // pub fn serialize() {

    // }

    // pub fn deserialize() {

    // }

    pub fn to_proto(&self) -> zero_art_proto::GroupInfo {
        zero_art_proto::GroupInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            created: Some(prost_types::Timestamp {
                seconds: self.created.timestamp(),
                nanos: self.created.timestamp_subsec_nanos() as i32,
            }),
            picture: self.picture.clone(),
            members: self.members.values().map(|x| x.to_proto()).collect(),
        }
    }

    pub fn from_proto(group: &zero_art_proto::GroupInfo) -> Self {
        let timestamp_proto = group.created.unwrap_or_default();
        let created =
            DateTime::from_timestamp(timestamp_proto.seconds, timestamp_proto.nanos as u32)
                .unwrap_or_default();

        let members: IndexMap<String, User> = group
            .members
            .iter()
            .map(|u| {
                let member = User::from_proto(u);
                (member.id(), member)
            })
            .collect();

        // let owner_id = members.get_index(0).unwrap().1.id().clone();

        Self {
            id: group.id.clone(),
            name: group.name.clone(),
            created,
            picture: group.picture.clone(),
            members,
        }
    }

    pub fn to_proto_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    pub fn from_proto_bytes(proto: &[u8]) -> Self {
        Self::from_proto(&zero_art_proto::GroupInfo::decode(proto).unwrap())
    }
}
