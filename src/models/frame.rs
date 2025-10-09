use std::fmt::Debug;

use ark_ec::{AffineRepr, CurveGroup};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use prost::Message;
use sha3::Digest;
use zrt_art::types::{BranchChanges, NodeIndex, ProverArtefacts, PublicART, VerifierArtefacts};
use zrt_crypto::schnorr;

use uuid::Uuid;
use zrt_zk::art::ARTProof;

use crate::{
    error::{Error, Result},
    proof_system::get_proof_system,
    zero_art_proto,
};

#[derive(Debug, Clone, Default)]
pub struct Frame {
    frame_tbs: FrameTbs,
    proof: Proof,
}

impl Frame {
    pub fn new(frame_tbs: FrameTbs, proof: Proof) -> Self {
        Self { frame_tbs, proof }
    }

    // Getters
    pub fn frame_tbs(&self) -> &FrameTbs {
        &self.frame_tbs
    }

    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    pub fn verify_schnorr<D: Digest>(&self, public_key: CortadoAffine) -> Result<()> {
        match &self.proof {
            Proof::SchnorrSignature(signature) => {
                schnorr::verify(
                    signature,
                    &vec![public_key],
                    &D::digest(self.frame_tbs.encode_to_vec()?),
                )?;
            }
            Proof::ArtProof(_) => return Err(Error::InvalidVerificationMethod),
        }

        Ok(())
    }

    pub fn verify_art<D: Digest>(
        &self,
        verifier_artefacts: VerifierArtefacts<CortadoAffine>,
        public_key: CortadoAffine,
    ) -> Result<()> {
        match &self.proof {
            Proof::SchnorrSignature(_) => return Err(Error::InvalidVerificationMethod),
            Proof::ArtProof(proof) => get_proof_system().verify(
                verifier_artefacts,
                &[public_key],
                &D::digest(self.frame_tbs.encode_to_vec()?),
                proof.clone(),
            )?,
        }

        Ok(())
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let inner: zero_art_proto::Frame = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::Frame::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::Frame> for Frame {
    type Error = Error;

    fn try_from(value: zero_art_proto::Frame) -> Result<Self> {
        let frame_tbs: FrameTbs = value.frame.ok_or(Error::RequiredFieldAbsent)?.try_into()?;

        let proof = if let Some(group_operation) = frame_tbs.group_operation.clone() {
            match group_operation {
                GroupOperation::AddMember(_) => {
                    Proof::ArtProof(crate::utils::deserialize(&value.proof)?)
                }
                GroupOperation::RemoveMember(_) => {
                    Proof::ArtProof(crate::utils::deserialize(&value.proof)?)
                }
                GroupOperation::KeyUpdate(_) => {
                    Proof::ArtProof(crate::utils::deserialize(&value.proof)?)
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

    fn try_from(value: Frame) -> Result<Self> {
        let proof = match value.proof {
            Proof::ArtProof(art_proof) => crate::utils::serialize(art_proof)?,
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

impl Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proof::ArtProof(_) => write!(f, "ArtProof(<opaque>)"),
            Proof::SchnorrSignature(sig) => write!(f, "SchnorrSignature({:?})", sig),
        }
    }
}

impl Default for Proof {
    fn default() -> Self {
        Proof::SchnorrSignature(Vec::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FrameTbs {
    group_id: Uuid,
    epoch: u64,
    nonce: Vec<u8>,
    group_operation: Option<GroupOperation>,
    protected_payload: Vec<u8>,
}

impl FrameTbs {
    pub fn new(
        group_id: Uuid,
        epoch: u64,
        nonce: Vec<u8>,
        group_operation: Option<GroupOperation>,
        protected_payload: Vec<u8>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            nonce,
            group_operation,
            protected_payload,
        }
    }

    // Getters
    pub fn group_id(&self) -> Uuid {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn group_operation(&self) -> Option<&GroupOperation> {
        self.group_operation.as_ref()
    }

    pub fn protected_payload(&self) -> &[u8] {
        &self.protected_payload
    }

    pub fn set_protected_payload(&mut self, protected_payload: Vec<u8>) {
        let _ = std::mem::replace(&mut self.protected_payload, protected_payload);
    }

    // Associated data for authenticate with aes_gcm
    pub fn associated_data<D: Digest>(&self) -> Result<Vec<u8>> {
        let mut inner: zero_art_proto::FrameTbs = self.clone().try_into()?;
        std::mem::take(&mut inner.protected_payload);
        Ok(D::digest(inner.encode_to_vec()).to_vec())
    }

    pub fn prove_schnorr<D: Digest>(self, secret_key: ScalarField) -> Result<Frame> {
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();
        let signature = schnorr::sign(
            &vec![secret_key],
            &vec![public_key],
            &D::digest(self.encode_to_vec()?),
        )?;
        Ok(Frame {
            frame_tbs: self,
            proof: Proof::SchnorrSignature(signature),
        })
    }

    pub fn prove_art<D: Digest>(
        self,
        prover_artefacts: ProverArtefacts<CortadoAffine>,
        secret_key: ScalarField,
    ) -> Result<Frame> {
        let proof = get_proof_system().prove(
            prover_artefacts,
            &[secret_key],
            &D::digest(self.encode_to_vec()?),
        )?;
        Ok(Frame {
            frame_tbs: self,
            proof: Proof::ArtProof(proof),
        })
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let inner: zero_art_proto::FrameTbs = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::FrameTbs::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::FrameTbs> for FrameTbs {
    type Error = Error;

    fn try_from(value: zero_art_proto::FrameTbs) -> Result<Self> {
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
        })
    }
}

impl TryFrom<FrameTbs> for zero_art_proto::FrameTbs {
    type Error = Error;

    fn try_from(value: FrameTbs) -> Result<Self> {
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
    LeaveGroup(NodeIndex),
    DropGroup(Vec<u8>),
}

impl TryFrom<zero_art_proto::GroupOperation> for GroupOperation {
    type Error = Error;

    fn try_from(value: zero_art_proto::GroupOperation) -> Result<Self> {
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
            zero_art_proto::group_operation::Operation::LeaveGroup(node_index) => {
                GroupOperation::LeaveGroup(postcard::from_bytes(&node_index)?)
            }
            zero_art_proto::group_operation::Operation::DropGroup(challenge) => {
                GroupOperation::DropGroup(challenge)
            }
        };

        Ok(group_operation)
    }
}

impl TryFrom<GroupOperation> for zero_art_proto::GroupOperation {
    type Error = Error;

    fn try_from(value: GroupOperation) -> Result<Self> {
        let operation = match value {
            GroupOperation::Init(art) => {
                zero_art_proto::group_operation::Operation::Init(art.serialize()?)
            }
            GroupOperation::AddMember(changes) => {
                zero_art_proto::group_operation::Operation::AddMember(changes.serialize()?)
            }
            GroupOperation::RemoveMember(changes) => {
                zero_art_proto::group_operation::Operation::RemoveMember(changes.serialize()?)
            }
            GroupOperation::KeyUpdate(changes) => {
                zero_art_proto::group_operation::Operation::KeyUpdate(changes.serialize()?)
            }
            GroupOperation::LeaveGroup(node_index) => {
                zero_art_proto::group_operation::Operation::LeaveGroup(postcard::to_allocvec(
                    &node_index,
                )?)
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
