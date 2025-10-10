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
    fn propose_remove_member(&self, leaf: CortadoAffine, vanishing_secret_key: ScalarField) -> Result<RemoveMemberProposal>;
    // TODO: Migrate to immutable ref
    fn propose_update_key(&mut self) -> Result<UpdateKeyProposal>;
    fn sign_with_tree_key(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_with_leaf_key(&self, message: &[u8]) -> Result<Vec<u8>>;
}

pub trait Decompose {
    type Parts;

    fn decompose(self) -> Self::Parts;
}

pub trait Compose<P> {
    fn compose(parts: P) -> Self;
}

pub trait TryDecompose {
    type Parts;

    fn try_decompose(self) -> Result<Self::Parts>;
}

pub trait TryCompose<P> {
    fn try_compose(parts: P) -> Result<Self>
    where
        Self: Sized;
}
