use std::{fmt::Display, hash::Hash};

use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use cortado::CortadoAffine;
use zrt_art::{
    art::art_types::PrivateZeroArt,
    changes::{aggregations::AggregatedChange, branch_change::{ArtOperationOutput, BranchChange}},
};

#[derive(Debug)]
pub enum GroupOperation<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    Init,
    LeaveGroup {
        old_public_key: G,
        new_public_key: G,
    },
    DropGroup,
    AddMember {
        member_public_key: G,
    },
    KeyUpdate {
        old_public_key: G,
        new_public_key: G,
    },
    RemoveMember {
        old_public_key: G,
        new_public_key: G,
    },
}

#[derive(Debug)]
pub struct Proposal<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub change: ArtOperationOutput<CortadoAffine>,
    pub stage_key: StageKey,
    pub aux_secret_key: G::ScalarField,
    pub private_zero_art: PrivateZeroArt<StdRng>,
}

pub type AddMemberProposal = Proposal<CortadoAffine>;
pub type RemoveMemberProposal = Proposal<CortadoAffine>;
pub type UpdateKeyProposal = Proposal<CortadoAffine>;
pub type LeaveGroupProposal = Proposal<CortadoAffine>;
pub type ValidationResult = Option<GroupOperation<CortadoAffine>>;
pub type ValidationWithKeyResult = (ValidationResult, StageKey);

pub type StageKey = [u8; 32];
pub type ChangesID = [u8; 8];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeId([u8; 8]);

impl<T: AsRef<[u8]>> From<T> for ChangeId {
    fn from(value: T) -> Self {
        let slice = value.as_ref();
        let mut bytes = [0u8; 8];
        let len = slice.len().min(8);
        bytes[..len].copy_from_slice(&slice[..len]);
        Self(bytes)
    }
}

impl Display for ChangeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameId([u8; 8]);

impl<T: AsRef<[u8]>> From<T> for FrameId {
    fn from(value: T) -> Self {
        let slice = value.as_ref();
        let mut bytes = [0u8; 8];
        let len = slice.len().min(8);
        bytes[..len].copy_from_slice(&slice[..len]);
        Self(bytes)
    }
}

impl Display for FrameId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub trait Identifiable {
    type Id: Eq + Hash + Clone + std::fmt::Debug;
    fn id(&self) -> Self::Id;
}

impl Identifiable for BranchChange<CortadoAffine> {
    type Id = ChangeId;

    fn id(&self) -> Self::Id {
        blake3::hash(&postcard::to_allocvec(self).expect("Failed to serialize BranchChange"))
            .as_bytes()
            .into()
    }
}

impl Identifiable for AggregatedChange<CortadoAffine> {
    type Id = ChangeId;

    fn id(&self) -> Self::Id {
        blake3::hash(&postcard::to_allocvec(self).expect("Failed to serialize AggregatedChange"))
            .as_bytes()
            .into()
    }
}
