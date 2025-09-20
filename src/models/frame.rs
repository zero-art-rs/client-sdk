use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use art::types::{BranchChanges, PublicART};
use cortado::CortadoAffine;
use prost::Message;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;
use zk::art::ARTProof;

use crate::{
    models::{errors::Error, protected_payload::ProtectedPayload},
    utils, zero_art_proto,
};

#[derive(Clone, Default)]
pub struct Frame {
    pub frame_tbs: FrameTbs,
    pub proof: Proof,
}

impl Frame {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        let inner: zero_art_proto::Frame = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, Error> {
        zero_art_proto::Frame::decode(&data[..])?.try_into()
    }
}

impl TryFrom<zero_art_proto::Frame> for Frame {
    type Error = Error;

    fn try_from(value: zero_art_proto::Frame) -> Result<Self, Self::Error> {
        let frame_tbs: FrameTbs = value.frame.ok_or(Error::RequiredFieldAbsent)?.try_into()?;

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
    type Error = Error;

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

impl Default for Proof {
    fn default() -> Self {
        Proof::SchnorrSignature(Vec::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FrameTbs {
    pub group_id: Uuid,
    pub epoch: u64,
    pub nonce: Vec<u8>,
    pub group_operation: Option<GroupOperation>,

    pub protected_payload: Vec<u8>,
    pub decrypted_payload: Option<ProtectedPayload>,
}

impl FrameTbs {
    pub fn decrypt(&mut self, stage_key: &[u8; 32]) -> Result<(), Error> {
        // TODO: may be we should store inner
        let mut inner: zero_art_proto::FrameTbs = self.clone().try_into()?;
        std::mem::take(&mut inner.protected_payload);
        let associated_data = Sha3_256::digest(inner.encode_to_vec());

        let payload_bytes = utils::decrypt(stage_key, &self.protected_payload, &associated_data)?;
        let payload = zero_art_proto::ProtectedPayload::decode(&payload_bytes[..])?;
        self.decrypted_payload = Some(payload.try_into()?);

        Ok(())
    }

    pub fn encrypt(&mut self, stage_key: &[u8; 32]) -> Result<(), Error> {
        // TODO: may be we should store inner
        let mut inner: zero_art_proto::FrameTbs = self.clone().try_into()?;
        std::mem::take(&mut inner.protected_payload);
        let associated_data = Sha3_256::digest(inner.encode_to_vec());

        let payload: zero_art_proto::ProtectedPayload = self
            .decrypted_payload
            .clone()
            .ok_or(Error::RequiredFieldAbsent)?
            .into();
        let payload_bytes = payload.encode_to_vec();
        self.protected_payload = utils::encrypt(stage_key, &payload_bytes, &associated_data)?;

        Ok(())
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        let inner: zero_art_proto::FrameTbs = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, Error> {
        zero_art_proto::FrameTbs::decode(&data[..])?.try_into()
    }
}

impl TryFrom<zero_art_proto::FrameTbs> for FrameTbs {
    type Error = Error;

    fn try_from(value: zero_art_proto::FrameTbs) -> Result<Self, Self::Error> {
        let group_id = Uuid::parse_str(&value.group_id).map_err(|_| Error::RequiredFieldAbsent)?;

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
        })
    }
}

impl TryFrom<FrameTbs> for zero_art_proto::FrameTbs {
    type Error = Error;

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

#[derive(Debug, Clone, Default)]
pub enum GroupOperation {
    Init(PublicART<CortadoAffine>),
    AddMember(BranchChanges<CortadoAffine>),
    RemoveMember(BranchChanges<CortadoAffine>),
    KeyUpdate(BranchChanges<CortadoAffine>),
    #[default]
    LeaveGroup,
    DropGroup(Vec<u8>),
}

impl TryFrom<zero_art_proto::GroupOperation> for GroupOperation {
    type Error = Error;

    fn try_from(value: zero_art_proto::GroupOperation) -> Result<Self, Self::Error> {
        let group_operation = match value.operation.ok_or(Error::RequiredFieldAbsent)? {
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
    type Error = Error;

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
