use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use art::types::{BranchChanges, PublicART};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
use prost::Message;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;
use zk::art::ARTProof;

use crate::{
    group_context::{SDKError, utils::decrypt},
    metadata, zero_art_proto,
};

#[derive(Clone)]
pub struct Frame {
    pub frame_tbs: FrameTbs,
    pub proof: Proof,
}

impl TryFrom<zero_art_proto::Frame> for Frame {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::Frame) -> Result<Self, Self::Error> {
        let frame_tbs: FrameTbs = value.frame.ok_or(SDKError::InvalidInput)?.try_into()?;

        let proof = if let Some(group_operation) = frame_tbs.group_operation.clone() {
            match group_operation {
                GroupOperation::AddMember(_) => {
                    Proof::ArtProof(ARTProof::deserialize_uncompressed(&value.proof[..])?)
                }
                GroupOperation::RemoveMember(_) => {
                    Proof::ArtProof(ARTProof::deserialize_uncompressed(&value.proof[..])?)
                }
                GroupOperation::KeyUpdate(_) => {
                    Proof::ArtProof(ARTProof::deserialize_uncompressed(&value.proof[..])?)
                }
                _ => Proof::SchnorrSignature(value.proof),
            }
        } else {
            Proof::SchnorrSignature(value.proof)
        };

        Ok(Self { frame_tbs, proof })
    }
}

impl TryFrom<Frame> for zero_art_proto::Frame {
    type Error = SDKError;

    fn try_from(value: Frame) -> Result<Self, Self::Error> {
        let proof = match value.proof {
            Proof::ArtProof(art_proof) => {
                let mut art_proof_bytes = Vec::new();
                art_proof.serialize_uncompressed(&mut art_proof_bytes)?;
                art_proof_bytes
            }
            Proof::SchnorrSignature(signature) => signature,
        };

        Ok(Self {
            frame: Some(value.frame_tbs.try_into()?),
            proof,
        })
    }
}

#[derive(Clone)]
pub enum Proof {
    ArtProof(ARTProof),
    SchnorrSignature(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct FrameTbs {
    pub group_id: Uuid,
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub group_operation: Option<GroupOperation>,

    pub protected_payload: Vec<u8>,
    pub decrypted_payload: Option<ProtectedPayload>,

    inner: zero_art_proto::FrameTbs,
}

impl FrameTbs {
    pub fn decrypt(&mut self, stage_key: &[u8; 32]) -> Result<(), SDKError> {
        let mut inner = self.inner.clone();
        std::mem::take(&mut inner.protected_payload);
        let associated_data = Sha3_256::digest(inner.encode_to_vec());
        let payload_bytes = decrypt(stage_key, &self.protected_payload, &associated_data)?;
        let payload = zero_art_proto::ProtectedPayload::decode(&payload_bytes[..])?;
        self.decrypted_payload = Some(payload.try_into()?);

        Ok(())
    }

    // pub fn encode_to_vec(&self) -> Vec<u8> {
        

    // }
}

impl TryFrom<zero_art_proto::FrameTbs> for FrameTbs {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::FrameTbs) -> Result<Self, Self::Error> {
        let inner = value.clone();

        let group_id = Uuid::parse_str(&value.group_id).map_err(|_| SDKError::InvalidInput)?;

        let group_operation = if let Some(group_operation) = value.group_operation {
            Some(group_operation.try_into()?)
        } else {
            None
        };

        Ok(FrameTbs {
            group_id,
            epoch: value.epoch,
            nonce: value.nonce,
            group_operation,
            protected_payload: value.protected_payload,
            decrypted_payload: None,
            inner,
        })
    }
}

impl TryFrom<FrameTbs> for zero_art_proto::FrameTbs {
    type Error = SDKError;

    fn try_from(value: FrameTbs) -> Result<Self, Self::Error> {
        let group_id = value.group_id.to_string();
        let group_operation = if let Some(group_operation) = value.group_operation {
            Some(group_operation.try_into()?)
        } else {
            None
        };

        Ok(Self {
            group_id,
            epoch: value.epoch,
            nonce: value.nonce,
            group_operation,
            protected_payload: value.protected_payload,
        })
    }
}

#[derive(Debug, Clone)]
pub enum GroupOperation {
    Init(PublicART<CortadoAffine>),
    AddMember(BranchChanges<CortadoAffine>),
    RemoveMember(BranchChanges<CortadoAffine>),
    KeyUpdate(BranchChanges<CortadoAffine>),
    LeaveGroup,
    DropGroup(Vec<u8>),
}

impl TryFrom<zero_art_proto::GroupOperation> for GroupOperation {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::GroupOperation) -> Result<Self, Self::Error> {
        let group_operation = match value.operation.ok_or(SDKError::InvalidInput)? {
            zero_art_proto::group_operation::Operation::Init(art) => {
                GroupOperation::Init(PublicART::deserialize(&art)?)
            }
            zero_art_proto::group_operation::Operation::AddMember(changes) => {
                GroupOperation::AddMember(BranchChanges::deserialize(&changes)?)
            }
            zero_art_proto::group_operation::Operation::RemoveMember(changes) => {
                GroupOperation::RemoveMember(BranchChanges::deserialize(&changes)?)
            }
            zero_art_proto::group_operation::Operation::KeyUpdate(changes) => {
                GroupOperation::KeyUpdate(BranchChanges::deserialize(&changes)?)
            }
            zero_art_proto::group_operation::Operation::LeaveGroup(_) => GroupOperation::LeaveGroup,
            zero_art_proto::group_operation::Operation::DropGroup(challenge) => {
                GroupOperation::DropGroup(challenge)
            }
        };

        Ok(group_operation)
    }
}

impl TryFrom<GroupOperation> for zero_art_proto::GroupOperation {
    type Error = SDKError;

    fn try_from(value: GroupOperation) -> Result<Self, Self::Error> {
        let operation = match value {
            GroupOperation::Init(art) => {
                zero_art_proto::group_operation::Operation::Init(art.serialize()?)
            }
            GroupOperation::AddMember(changes) => {
                zero_art_proto::group_operation::Operation::AddMember(changes.serialze()?)
            }
            GroupOperation::RemoveMember(changes) => {
                zero_art_proto::group_operation::Operation::RemoveMember(changes.serialze()?)
            }
            GroupOperation::KeyUpdate(changes) => {
                zero_art_proto::group_operation::Operation::KeyUpdate(changes.serialze()?)
            }
            GroupOperation::LeaveGroup => {
                zero_art_proto::group_operation::Operation::LeaveGroup(vec![])
            }
            GroupOperation::DropGroup(challenge) => {
                zero_art_proto::group_operation::Operation::DropGroup(challenge)
            }
        };

        Ok(zero_art_proto::GroupOperation {
            operation: Some(operation),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedPayload {
    pub protected_payload_tbs: ProtectedPayloadTbs,
    pub signature: Vec<u8>,
}

impl TryFrom<zero_art_proto::ProtectedPayload> for ProtectedPayload {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::ProtectedPayload) -> Result<Self, Self::Error> {
        let protected_payload_tbs = value.payload.ok_or(SDKError::InvalidInput)?.try_into()?;
        Ok(Self {
            protected_payload_tbs,
            signature: value.signature,
        })
    }
}

impl From<ProtectedPayload> for zero_art_proto::ProtectedPayload {
    fn from(value: ProtectedPayload) -> Self {
        let payload = value.protected_payload_tbs.into();
        Self {
            payload: Some(payload),
            signature: value.signature,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedPayloadTbs {
    pub seq_num: u64,
    pub created: DateTime<Utc>,
    pub payloads: Vec<Payload>,
    pub sender: Sender,

    inner: zero_art_proto::ProtectedPayloadTbs,
}

impl TryFrom<zero_art_proto::ProtectedPayloadTbs> for ProtectedPayloadTbs {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::ProtectedPayloadTbs) -> Result<Self, Self::Error> {
        let inner = value.clone();

        let timestamp_proto = value.created.ok_or(SDKError::InvalidInput)?;
        let created =
            DateTime::from_timestamp(timestamp_proto.seconds, timestamp_proto.nanos as u32)
                .ok_or(SDKError::InvalidInput)?;
        let sender = value.sender.ok_or(SDKError::InvalidInput)?.into();
        let payloads = value
            .payload
            .into_iter()
            .map(Payload::try_from)
            .collect::<Result<Vec<Payload>, Self::Error>>()?;

        Ok(Self {
            seq_num: value.seq_num,
            created,
            payloads,
            sender,
            inner,
        })
    }
}

impl From<ProtectedPayloadTbs> for zero_art_proto::ProtectedPayloadTbs {
    fn from(value: ProtectedPayloadTbs) -> Self {
        let created = prost_types::Timestamp {
            seconds: value.created.timestamp(),
            nanos: value.created.timestamp_subsec_nanos() as i32,
        };
        let payload = value
            .payloads
            .into_iter()
            .map(zero_art_proto::Payload::from)
            .collect::<Vec<zero_art_proto::Payload>>();
        let sender = value.sender.into();
        Self {
            seq_num: value.seq_num,
            created: Some(created),
            payload,
            sender: Some(sender),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Sender {
    UserId(String),
    LeafId(String),
}

impl From<zero_art_proto::protected_payload_tbs::Sender> for Sender {
    fn from(value: zero_art_proto::protected_payload_tbs::Sender) -> Self {
        match value {
            zero_art_proto::protected_payload_tbs::Sender::UserId(id) => Sender::UserId(id),
            zero_art_proto::protected_payload_tbs::Sender::LeafId(id) => Sender::LeafId(id),
        }
    }
}

impl From<Sender> for zero_art_proto::protected_payload_tbs::Sender {
    fn from(value: Sender) -> Self {
        match value {
            Sender::UserId(id) => zero_art_proto::protected_payload_tbs::Sender::UserId(id),
            Sender::LeafId(id) => zero_art_proto::protected_payload_tbs::Sender::LeafId(id),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Payload {
    Action(GroupActionPayload),
    Crdt(zero_art_proto::crdt_payload::Payload),
    Chat(zero_art_proto::chat_payload::Payload),
}

impl TryFrom<zero_art_proto::Payload> for Payload {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::Payload) -> Result<Self, Self::Error> {
        let payload = match value.content.ok_or(SDKError::InvalidInput)? {
            zero_art_proto::payload::Content::Action(action) => Payload::Action(action.try_into()?),
            zero_art_proto::payload::Content::Crdt(crtd) => {
                Payload::Crdt(crtd.payload.ok_or(SDKError::InvalidInput)?)
            }
            zero_art_proto::payload::Content::Chat(chat) => {
                Payload::Chat(chat.payload.ok_or(SDKError::InvalidInput)?)
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
    Init(metadata::group::GroupInfo),
    InviteMember(metadata::group::GroupInfo),
    RemoveMember(metadata::user::User),
    JoinGroup(metadata::user::User),
    ChangeUser(metadata::user::User),
    ChangeGroup(metadata::group::GroupInfo),
    LeaveGroup(metadata::user::User),
    FinalizeRemoval(metadata::user::User),
}

impl TryFrom<zero_art_proto::GroupActionPayload> for GroupActionPayload {
    type Error = SDKError;

    fn try_from(value: zero_art_proto::GroupActionPayload) -> Result<Self, Self::Error> {
        let group_action_payload = match value.action.ok_or(SDKError::InvalidInput)? {
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
