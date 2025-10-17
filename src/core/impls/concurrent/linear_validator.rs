use cortado::CortadoAffine;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zrt_art::{
    traits::{ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, PublicART},
};

use crate::{
    core::{impls::group_owner_leaf_public_key, traits::Validator},
    errors::{Error, Result},
    models::frame,
    types::{GroupOperation, ValidationResult},
    utils::deserialize,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct LinearValidator {
    base_art: PublicART<CortadoAffine>,
    upstream_art: PublicART<CortadoAffine>,
    changes: Vec<BranchChanges<CortadoAffine>>,
    closed: bool,
    epoch: u64,
}

impl Validator for LinearValidator {
    fn validate(&mut self, frame: &frame::Frame) -> Result<ValidationResult> {
        let frame_epoch = frame.frame_tbs().epoch();

        if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
            return Err(Error::InvalidEpoch);
        }

        let is_next_epoch = frame_epoch == self.epoch + 1;

        // If frame don't have group operation then it is just payload frame that should have current epoch
        if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
            frame.verify_schnorr::<Sha3_256>(self.upstream_art.get_root().get_public_key())?;
            return Ok(None);
        }

        let group_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidEpoch)?;

        match group_operation {
            frame::GroupOperation::AddMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::AddMember {
                    member_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = true;

                Ok(Some(operation))
            }
            frame::GroupOperation::KeyUpdate(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = self
                        .upstream_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = self
                        .base_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            frame::GroupOperation::RemoveMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::RemoveMember {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            frame::GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key)?;
                Ok(Some(GroupOperation::Init))
            }
            frame::GroupOperation::LeaveGroup(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = self
                        .upstream_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = self
                        .base_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            frame::GroupOperation::DropGroup(_) => unimplemented!(),
        }
    }

    fn tree_public_key(&self) -> CortadoAffine {
        self.upstream_art.get_root().get_public_key()
    }

    fn tree(&self) -> &PublicART<CortadoAffine> {
        &self.upstream_art
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl LinearValidator {
    pub fn new(base_art: PublicART<CortadoAffine>, epoch: u64) -> Self {
        Self {
            upstream_art: base_art.clone(),
            base_art,
            changes: vec![],
            closed: true,
            epoch,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }

    #[allow(clippy::useless_vec)]
    fn apply_changes(
        &mut self,
        changes: &BranchChanges<CortadoAffine>,
        is_next_epoch: bool,
    ) -> Result<()> {
        if !is_next_epoch {
            let mut upstream_art = self.base_art.clone();
            upstream_art.merge_all(&vec![self.changes.clone(), vec![changes.clone()]].concat())?;

            self.upstream_art = upstream_art;

            self.changes.push(changes.clone());

            return Ok(());
        }

        let base_art = self.upstream_art.clone();
        let mut upstream_art = self.upstream_art.clone();
        upstream_art.update_public_art(changes)?;

        self.base_art = base_art;
        self.upstream_art = upstream_art;

        self.changes = vec![changes.clone()];

        Ok(())
    }
}
