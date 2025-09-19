use art::types::{BranchChanges, PublicART};
use chrono::{DateTime, Utc};
use cortado::CortadoAffine;
use uuid::Uuid;
use zk::art::ARTProof;

use crate::{group_context::SDKError, metadata, zero_art_proto};

pub struct Frame {
    pub frame_tbs: FrameTbs,
    pub proof: Proof,
}

// impl TryFrom<zero_art_proto::Frame> for Frame {
//     type Error = SDKError;
    
//     fn try_from(value: zero_art_proto::Frame) -> Result<Self, Self::Error> {
        
//     }
// }

pub enum Proof {
    ArtProof(ARTProof),
    SchnorrSignature(Vec<u8>),
}

pub struct FrameTbs {
    pub group_id: Uuid,
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub group_operation: Option<GroupOperation>,

    pub protected_payload: Vec<u8>,
    pub decrypted_payload: Option<ProtectedPayload>,

    inner: zero_art_proto::FrameTbs,
}

impl TryFrom<zero_art_proto::FrameTbs> for FrameTbs {
    type Error = SDKError;
    fn try_from(value: zero_art_proto::FrameTbs) -> Result<Self, Self::Error> {
        unimplemented!();
        let group_id: Uuid = Uuid::parse_str(&value.group_id).map_err(|_| SDKError::InvalidInput)?;
    }
}

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
        unimplemented!();
        match value.operation.ok_or(SDKError::InvalidInput)? {
            zero_art_proto::group_operation::Operation::KeyUpdate(changes) => {},
            zero_art_proto::group_operation::Operation::Init(_) => {},
            zero_art_proto::group_operation::Operation::AddMember(_) => {},
            zero_art_proto::group_operation::Operation::RemoveMember(_) => {},
            zero_art_proto::group_operation::Operation::LeaveGroup(_) => {GroupOperation::LeaveGroup;},
            zero_art_proto::group_operation::Operation::DropGroup(_) => {},
        };
    }
}

pub struct ProtectedPayload {
    pub protected_payload_tbs: ProtectedPayloadTbs,
    pub signature: Vec<u8>,
}

pub struct ProtectedPayloadTbs {
    pub seq_num: u64,
    pub sender: Sender,
    pub created: DateTime<Utc>,
    pub payloads: Vec<Payload>,

    inner: zero_art_proto::ProtectedPayloadTbs,
}

pub enum Sender {
    UserId(String),
    LeafId(String),
}

pub enum Payload {
    Action(GroupActionPayload),
    Crdt(zero_art_proto::crdt_payload::Payload),
    Chat(zero_art_proto::chat_payload::Payload),
}

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
