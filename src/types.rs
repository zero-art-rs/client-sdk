use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake3;
use cortado::CortadoAffine;
use serde::{Deserialize, Serialize};
use std::fmt;
use zrt_art::changes::branch_change::{BranchChange, PrivateBranchChange};

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

// #[derive(Debug)]
pub struct Proposal<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub change: PrivateBranchChange<G>,
    pub stage_key: StageKey,
}

pub type AddMemberProposal = Proposal<CortadoAffine>;
pub type RemoveMemberProposal = Proposal<CortadoAffine>;
pub type UpdateKeyProposal = Proposal<CortadoAffine>;
pub type LeaveGroupProposal = Proposal<CortadoAffine>;
pub type ValidationResult = Option<GroupOperation<CortadoAffine>>;
pub type ValidationWithKeyResult = (ValidationResult, StageKey);

pub type StageKey = [u8; 32];

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChangeID([u8; 8]);

impl ChangeID {
    /// Creates a new ChangeID from any byte slice or array.
    /// If the input is shorter than 8 bytes, it will be padded with zeros.
    /// If the input is longer than 8 bytes, it will be truncated.
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let mut id = [0u8; 8];
        let len = bytes.len().min(8);
        id[..len].copy_from_slice(&bytes[..len]);
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 8] {
        self.0
    }
}

impl From<[u8; 8]> for ChangeID {
    fn from(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl From<ChangeID> for [u8; 8] {
    fn from(id: ChangeID) -> Self {
        id.0
    }
}

impl AsRef<[u8]> for ChangeID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ChangeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub trait Identifiable {
    type Id;

    fn id(&self) -> Self::Id;
}

impl<G: AffineRepr + CanonicalSerialize> Identifiable for BranchChange<G> {
    type Id = ChangeID;

    fn id(&self) -> Self::Id {
        let serialized = postcard::to_allocvec(self).unwrap_or_default();
        let hash = blake3::hash(&serialized);
        ChangeID::new(&hash.as_bytes()[..8])
    }
}

impl<G: AffineRepr + CanonicalSerialize> Identifiable for PrivateBranchChange<G> {
    type Id = ChangeID;

    fn id(&self) -> Self::Id {
        self.get_branch_change().id()
    }
}
