use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use cortado::CortadoAffine;
use zrt_art::{
    art::art_types::PrivateZeroArt,
    changes::branch_change::{ArtOperationOutput, BranchChange},
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
