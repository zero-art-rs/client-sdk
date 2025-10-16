use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::CortadoAffine;
use zrt_art::types::{BranchChanges, ProverArtefacts};

#[derive(Debug)]
pub enum GroupOperation<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    Init,
    LeaveGroup {
        member_public_key: G,
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
        member_public_key: G,
    },
}

#[derive(Debug)]
pub struct Proposal<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub changes: BranchChanges<G>,
    pub stage_key: StageKey,
    pub prover_artefacts: ProverArtefacts<G>,
    pub aux_secret_key: G::ScalarField,
}

pub type AddMemberProposal = Proposal<CortadoAffine>;
pub type RemoveMemberProposal = Proposal<CortadoAffine>;
pub type UpdateKeyProposal = Proposal<CortadoAffine>;
pub type ValidationResult = Option<GroupOperation<CortadoAffine>>;
pub type ValidationWithKeyResult = (ValidationResult, StageKey);

pub type StageKey = [u8; 32];
pub type ChangesID = [u8; 8];
