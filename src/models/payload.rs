use prost::Message;

use crate::{
    error::{Error, Result},
    models::group_info::{GroupInfo, User},
    zero_art_proto,
};

#[derive(Debug, Clone)]
pub enum Payload {
    Action(GroupActionPayload),
    Crdt(zero_art_proto::crdt_payload::Payload),
    Chat(zero_art_proto::chat_payload::Payload),
}

impl Payload {
    pub fn encode_to_vec(&self) -> Vec<u8> {
        zero_art_proto::Payload::from(self.clone()).encode_to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::Payload::decode(data)?.try_into()
    }
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Action(GroupActionPayload::default())
    }
}

impl TryFrom<zero_art_proto::Payload> for Payload {
    type Error = Error;

    fn try_from(value: zero_art_proto::Payload) -> Result<Self> {
        let payload = match value.content.ok_or(Error::RequiredFieldAbsent)? {
            zero_art_proto::payload::Content::Action(action) => Payload::Action(action.try_into()?),
            zero_art_proto::payload::Content::Crdt(crtd) => {
                Payload::Crdt(crtd.payload.ok_or(Error::RequiredFieldAbsent)?)
            }
            zero_art_proto::payload::Content::Chat(chat) => {
                Payload::Chat(chat.payload.ok_or(Error::RequiredFieldAbsent)?)
            }
        };

        Ok(payload)
    }
}

impl From<Payload> for zero_art_proto::Payload {
    fn from(value: Payload) -> Self {
        let content = match value {
            Payload::Action(action) => zero_art_proto::payload::Content::Action(action.into()),
            Payload::Crdt(crdt) => {
                zero_art_proto::payload::Content::Crdt(zero_art_proto::CrdtPayload {
                    payload: Some(crdt),
                })
            }
            Payload::Chat(chat) => {
                zero_art_proto::payload::Content::Chat(zero_art_proto::ChatPayload {
                    payload: Some(chat),
                })
            }
        };

        zero_art_proto::Payload {
            content: Some(content),
        }
    }
}

#[derive(Debug, Clone)]
pub enum GroupActionPayload {
    Init(GroupInfo),
    InviteMember(GroupInfo),
    RemoveMember(User),
    JoinGroup(User),
    ChangeUser(User),
    ChangeGroup(GroupInfo),
    LeaveGroup(User),
    FinalizeRemoval(User),
}

impl Default for GroupActionPayload {
    fn default() -> Self {
        GroupActionPayload::Init(GroupInfo::default())
    }
}

impl TryFrom<zero_art_proto::GroupActionPayload> for GroupActionPayload {
    type Error = Error;

    fn try_from(value: zero_art_proto::GroupActionPayload) -> Result<Self> {
        let group_action_payload = match value.action.ok_or(Error::RequiredFieldAbsent)? {
            zero_art_proto::group_action_payload::Action::Init(group) => {
                GroupActionPayload::Init(group.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::InviteMember(group) => {
                GroupActionPayload::InviteMember(group.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::RemoveMember(user) => {
                GroupActionPayload::RemoveMember(user.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::JoinGroup(user) => {
                GroupActionPayload::JoinGroup(user.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::ChangeUser(user) => {
                GroupActionPayload::ChangeUser(user.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::ChangeGroup(group) => {
                GroupActionPayload::ChangeGroup(group.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::LeaveGroup(user) => {
                GroupActionPayload::LeaveGroup(user.try_into()?)
            }
            zero_art_proto::group_action_payload::Action::FinalizeRemoval(user) => {
                GroupActionPayload::FinalizeRemoval(user.try_into()?)
            }
        };

        Ok(group_action_payload)
    }
}

impl From<GroupActionPayload> for zero_art_proto::GroupActionPayload {
    fn from(value: GroupActionPayload) -> Self {
        let action = match value {
            GroupActionPayload::Init(group) => {
                zero_art_proto::group_action_payload::Action::Init(group.into())
            }
            GroupActionPayload::InviteMember(group) => {
                zero_art_proto::group_action_payload::Action::InviteMember(group.into())
            }
            GroupActionPayload::RemoveMember(user) => {
                zero_art_proto::group_action_payload::Action::RemoveMember(user.into())
            }
            GroupActionPayload::JoinGroup(user) => {
                zero_art_proto::group_action_payload::Action::JoinGroup(user.into())
            }
            GroupActionPayload::ChangeUser(user) => {
                zero_art_proto::group_action_payload::Action::ChangeUser(user.into())
            }
            GroupActionPayload::ChangeGroup(group) => {
                zero_art_proto::group_action_payload::Action::ChangeGroup(group.into())
            }
            GroupActionPayload::LeaveGroup(user) => {
                zero_art_proto::group_action_payload::Action::LeaveGroup(user.into())
            }
            GroupActionPayload::FinalizeRemoval(user) => {
                zero_art_proto::group_action_payload::Action::FinalizeRemoval(user.into())
            }
        };

        zero_art_proto::GroupActionPayload {
            action: Some(action),
        }
    }
}
