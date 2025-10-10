use crate::{
    core::types::{
        AddMemberProposal, RemoveMemberProposal, UpdateKeyProposal, ValidationResult,
        ValidationWithKeyResult,
    },
    error::Result,
    models::frame::Frame,
};

use cortado::{self, CortadoAffine, Fr as ScalarField};

pub trait Validator {
    fn validate(&mut self, frame: &Frame) -> Result<ValidationResult>;
    fn epoch(&self) -> u64;
}

pub trait KeyedValidator: Validator {
    fn validate_and_derive_key(&mut self, frame: &Frame) -> Result<ValidationWithKeyResult>;
    fn propose_add_member(&self, leaf_secret: ScalarField) -> Result<AddMemberProposal>;
    fn propose_remove_member(&self, leaf: CortadoAffine) -> Result<RemoveMemberProposal>;
    fn propose_update_key(&self, leaf_secret: ScalarField) -> Result<UpdateKeyProposal>;
    fn sign_with_tree_key(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_with_leaf_key();
}

pub trait Parts: Sized {
    type Parts;

    fn to_parts(&self) -> Self::Parts;
    fn into_parts(self) -> Self::Parts;
    fn from_parts(parts: Self::Parts) -> Self;
}
