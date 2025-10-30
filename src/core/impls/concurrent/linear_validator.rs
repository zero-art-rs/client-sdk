use cortado::CortadoAffine;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zrt_art::art::art_types::PublicArt;
use zrt_art::changes::branch_change::MergeBranchChange;
use zrt_art::changes::{ApplicableChange, VerifiableChange};
use zrt_art::{art::art_types::PublicZeroArt, changes::branch_change::BranchChange};
use zrt_zk::EligibilityRequirement;

use crate::{
    core::{impls::group_owner_leaf_public_key, traits::Validator},
    errors::{Error, Result},
    models::frame,
    types::{GroupOperation, ValidationResult},
    utils::deserialize,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct LinearValidator {
    base_art: PublicArt<CortadoAffine>,
    upstream_art: PublicArt<CortadoAffine>,
    changes: Vec<BranchChange<CortadoAffine>>,
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
            frame::GroupOperation::AddMember(change) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                PublicZeroArt::new(&self.upstream_art.clone());

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art = PublicZeroArt::new(self.upstream_art.clone());
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art = PublicZeroArt::new(self.base_art.clone());
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(change, public_zero_art, public_key)?;
                let operation = GroupOperation::AddMember {
                    member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(change, is_next_epoch)?;

                self.closed = true;

                Ok(Some(operation))
            }
            frame::GroupOperation::KeyUpdate(change) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art = PublicZeroArt::new(self.upstream_art.clone());
                    let public_key = self
                        .upstream_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art = PublicZeroArt::new(self.base_art.clone());
                    let public_key = self
                        .base_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(change, public_zero_art, public_key)?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(change, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            frame::GroupOperation::RemoveMember(change) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art = PublicZeroArt::new(self.upstream_art.clone());
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art = PublicZeroArt::new(self.base_art.clone());
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(change, public_zero_art, public_key)?;
                let operation = GroupOperation::RemoveMember {
                    old_public_key: public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(change, is_next_epoch)?;

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
            frame::GroupOperation::LeaveGroup(change) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art = PublicZeroArt::new(self.upstream_art.clone());
                    let public_key = self
                        .upstream_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art = PublicZeroArt::new(self.base_art.clone());
                    let public_key = self
                        .base_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(change, public_zero_art, public_key)?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key: public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                self.apply_changes(change, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            frame::GroupOperation::DropGroup(_) => unimplemented!(),
        }
    }

    fn tree_public_key(&self) -> CortadoAffine {
        self.upstream_art.get_root().get_public_key()
    }

    fn tree(&self) -> &PublicArt<CortadoAffine> {
        &self.upstream_art
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl LinearValidator {
    pub fn new(base_art: PublicArt<CortadoAffine>, epoch: u64) -> Self {
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
        changes: &BranchChange<CortadoAffine>,
        is_next_epoch: bool,
    ) -> Result<()> {
        if !is_next_epoch {
            let mut upstream_art = self.base_art.clone();

            let merge_branch_change = MergeBranchChange::new_for_observer(&vec![self.changes.clone(), vec![changes.clone()]].concat());
            merge_branch_change.update(&mut upstream_art)?;

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
