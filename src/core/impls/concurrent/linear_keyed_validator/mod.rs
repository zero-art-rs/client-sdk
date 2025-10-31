use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use tracing::{Level, debug, instrument, span, trace};
use zrt_art::TreeMethods;
use zrt_art::art::ArtAdvancedOps;
use zrt_art::art::art_node::LeafStatus;
use zrt_art::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use zrt_art::changes::branch_change::BranchChange;
use zrt_art::node_index::NodeIndex;
use zrt_crypto::schnorr;
use zrt_zk::EligibilityRequirement;

use crate::errors;
use crate::{
    bounded_map::BoundedMap,
    core::{
        impls::group_owner_leaf_public_key,
        traits::{KeyedValidator, Validator},
    },
    errors::{Error, Result},
    models::frame,
    types::{
        AddMemberProposal, ChangesID, GroupOperation, LeaveGroupProposal, RemoveMemberProposal,
        StageKey, UpdateKeyProposal, ValidationResult, ValidationWithKeyResult,
    },
    utils::{compute_change_id, derive_leaf_key, derive_stage_key, deserialize},
};
use cortado::{self, CortadoAffine, Fr as ScalarField};

mod merge_strategy;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Participant {
    id: ChangesID,
    branch: BranchChange<CortadoAffine>,
    art: PrivateArt<CortadoAffine>,
}

#[derive(Debug)]
pub struct LinearKeyedValidator {
    base_art: PrivateArt<CortadoAffine>,
    base_stk: StageKey,

    upstream_art: PrivateZeroArt<StdRng>,
    upstream_stk: StageKey,

    changes: HashMap<ChangesID, BranchChange<CortadoAffine>>,

    epoch: u64,

    participant: Option<Participant>,
    participation_leafs: BoundedMap<ChangesID, ScalarField>,
}

impl Validator for LinearKeyedValidator {
    fn validate(&mut self, frame: &frame::Frame) -> Result<ValidationResult> {
        let (result, _) = self.validate_and_derive_key(frame)?;
        Ok(result)
    }

    fn tree(&self) -> &PublicArt<CortadoAffine> {
        &self.upstream_art.get_public_art()
    }

    fn tree_public_key(&self) -> CortadoAffine {
        self.upstream_art.get_root().get_public_key()
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl KeyedValidator for LinearKeyedValidator {
    #[instrument(skip_all, name = "validate", fields(current_epoch = %self.epoch, frame_epoch = %frame.frame_tbs().epoch()))]
    fn validate_and_derive_key(&mut self, frame: &frame::Frame) -> Result<ValidationWithKeyResult> {
        trace!("Frame: {:?}", frame);

        debug!("Validator epoch: {}", self.epoch);
        let frame_epoch = frame.frame_tbs().epoch();
        debug!("Frame epoch: {frame_epoch}");

        if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
            return Err(Error::InvalidEpoch);
        }

        let is_next_epoch = frame_epoch == self.epoch + 1;
        debug!("Is next epoch: {is_next_epoch}");

        // If frame don't have group operation then it is just payload frame that should have current epoch
        trace!("Group operation: {:?}", frame.frame_tbs().group_operation());
        if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
            let span = span!(Level::TRACE, "payload_frame");
            let _enter = span.enter();

            trace!(
                "Upstream root public key: {:?}",
                self.upstream_art.get_root().get_public_key()
            );
            frame.verify_schnorr::<Sha3_256>(self.upstream_art.get_root().get_public_key())?;
            trace!("Upstream stage key: {:?}", self.upstream_stk);
            return Ok((None, self.upstream_stk));
        }

        if matches!(
            frame.frame_tbs().group_operation(),
            Some(frame::GroupOperation::Init(_))
        ) && frame_epoch != 0
        {
            return Err(Error::InvalidEpoch);
        }

        let group_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidEpoch)?;

        match group_operation {
            frame::GroupOperation::AddMember(change) => {
                let span = span!(Level::TRACE, "add_member_frame");
                let _enter = span.enter();

                trace!("Changes: {:?}", change);

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art =
                        PublicZeroArt::new(self.upstream_art.get_public_art().clone());
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art =
                        PublicZeroArt::new(self.base_art.get_public_art().clone());
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    trace!("Base owner leaf key: {:?}", public_key);
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(
                    change.clone(),
                    public_zero_art,
                    zrt_zk::EligibilityRequirement::Previleged((public_key, vec![])),
                )?;
                let operation = GroupOperation::AddMember {
                    member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };
                if !is_next_epoch {
                    return Ok((Some(operation), self.upstream_stk));
                }

                Ok((Some(operation), self.apply_changes(change)?))
            }
            frame::GroupOperation::KeyUpdate(change) => {
                let span = span!(Level::TRACE, "key_update_frame");
                let _enter = span.enter();

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art =
                        PublicZeroArt::new(self.upstream_art.get_public_art().clone());
                    let public_key = self
                        .upstream_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art =
                        PublicZeroArt::new(self.base_art.get_public_art().clone());
                    let public_key = self.base_art.get_node(&change.node_index)?.get_public_key();
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(
                    change.clone(),
                    public_zero_art,
                    zrt_zk::EligibilityRequirement::Member(public_key),
                )?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(change)?
                } else {
                    self.merge_changes(change)?
                };

                Ok((Some(operation), stage_key))
            }
            frame::GroupOperation::RemoveMember(change) => {
                let span = span!(Level::TRACE, "remove_member_frame");
                let _enter = span.enter();

                if *self.upstream_art.get_node_index() == change.node_index {
                    return Err(Error::UserRemovedFromGroup);
                }

                let (public_zero_art, eligibility) = if is_next_epoch {
                    let public_zero_art =
                        PublicZeroArt::new(self.upstream_art.get_public_art().clone());
                    let eligibility = if LeafStatus::Active
                        != self
                            .upstream_art
                            .get_node(&change.node_index)?
                            .get_status()
                            .ok_or(Error::InvalidInput)?
                    {
                        EligibilityRequirement::Member(
                            self.upstream_art.get_root().get_public_key(),
                        )
                    } else {
                        EligibilityRequirement::Previleged((
                            group_owner_leaf_public_key(&self.upstream_art),
                            vec![],
                        ))
                    };
                    (public_zero_art, eligibility)
                } else {
                    let public_zero_art =
                        PublicZeroArt::new(self.base_art.get_public_art().clone());
                    let eligibility = if LeafStatus::Active
                        != self
                            .base_art
                            .get_node(&change.node_index)?
                            .get_status()
                            .ok_or(Error::InvalidInput)?
                    {
                        EligibilityRequirement::Member(self.base_art.get_root().get_public_key())
                    } else {
                        EligibilityRequirement::Previleged((
                            group_owner_leaf_public_key(&self.base_art),
                            vec![],
                        ))
                    };
                    (public_zero_art, eligibility)
                };

                frame.verify_art::<Sha3_256>(change.clone(), public_zero_art, eligibility)?;

                let member_public_key = if is_next_epoch {
                    self.upstream_art
                        .get_node(&change.node_index)?
                        .get_public_key()
                } else {
                    self.base_art.get_node(&change.node_index)?.get_public_key()
                };

                let operation = GroupOperation::RemoveMember {
                    old_public_key: member_public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(change)?
                } else {
                    self.merge_changes(change)?
                };

                Ok((Some(operation), stage_key))
            }
            frame::GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key)?;
                Ok((Some(GroupOperation::Init), self.upstream_stk))
            }
            frame::GroupOperation::LeaveGroup(change) => {
                let span = span!(Level::TRACE, "leave_group_frame");
                let _enter = span.enter();

                let (public_zero_art, public_key) = if is_next_epoch {
                    let public_zero_art =
                        PublicZeroArt::new(self.upstream_art.get_public_art().clone());
                    let public_key = self
                        .upstream_art
                        .get_node(&change.node_index)?
                        .get_public_key();
                    trace!("Upstream member leaf key: {:?}", public_key);
                    (public_zero_art, public_key)
                } else {
                    let public_zero_art =
                        PublicZeroArt::new(self.base_art.get_public_art().clone());
                    let public_key = self.base_art.get_node(&change.node_index)?.get_public_key();
                    trace!("Base member leaf key: {:?}", public_key);
                    (public_zero_art, public_key)
                };

                frame.verify_art::<Sha3_256>(
                    change.clone(),
                    public_zero_art,
                    zrt_zk::EligibilityRequirement::Member(public_key),
                )?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key: public_key,
                    new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(change)?
                } else {
                    self.merge_changes(change)?
                };

                Ok((Some(operation), stage_key))
            }
            frame::GroupOperation::DropGroup(_) => unimplemented!(),
        }
    }

    fn propose_add_member(&self, leaf_secret: ScalarField) -> Result<AddMemberProposal> {
        if self.leaf_public_key() != group_owner_leaf_public_key(&self.upstream_art) {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let change = temporary_art.add_member(leaf_secret)?;
        let root_key = temporary_art.get_root_secret_key();

        Ok(AddMemberProposal {
            change,
            stage_key: derive_stage_key(&self.upstream_stk, root_key)?,
            aux_secret_key: self.upstream_art.get_leaf_secret_key(),
            private_zero_art: temporary_art,
        })
    }

    fn propose_remove_member(
        &self,
        leaf_public_key: CortadoAffine,
        vanishing_secret_key: ScalarField,
    ) -> Result<RemoveMemberProposal> {
        let leaf = self.upstream_art.get_leaf_with(leaf_public_key)?;

        if self.leaf_public_key() != group_owner_leaf_public_key(&self.upstream_art)
            && matches!(leaf.get_status(), Some(LeafStatus::Active))
        {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let change = temporary_art.remove_member(
            &self
                .upstream_art
                .get_path_to_leaf_with(leaf_public_key)?
                .into(),
            vanishing_secret_key,
        )?;
        let root_key = temporary_art.get_root_secret_key();

        let secret_key = if matches!(leaf.get_status(), Some(LeafStatus::Active)) {
            self.upstream_art.get_leaf_secret_key()
        } else {
            self.upstream_art.get_root_secret_key()
        };

        Ok(RemoveMemberProposal {
            change,
            stage_key: derive_stage_key(&self.upstream_stk, root_key)?,
            aux_secret_key: secret_key,
            private_zero_art: temporary_art,
        })
    }

    fn propose_update_key(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key =
            derive_leaf_key(&self.upstream_stk, self.upstream_art.get_leaf_secret_key())?;

        let mut temporary_art = self.upstream_art.clone();
        let change = temporary_art.update_key(secret_key)?;
        let root_key = temporary_art.get_root_secret_key();
        let stage_key = derive_stage_key(&self.upstream_stk, root_key)?;

        let changes_id = compute_change_id(&change.get_branch_change())?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok(UpdateKeyProposal {
            change,
            stage_key,
            aux_secret_key: self.upstream_art.get_leaf_secret_key(),
            private_zero_art: temporary_art,
        })
    }

    fn propose_leave_group(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key =
            derive_leaf_key(&self.upstream_stk, self.upstream_art.get_leaf_secret_key())?;

        let mut temporary_art = self.upstream_art.clone();
        let change = temporary_art.leave_group(secret_key)?;
        let root_key = temporary_art.get_root_secret_key();
        let stage_key = derive_stage_key(&self.upstream_stk, root_key)?;

        let changes_id = compute_change_id(&change.get_branch_change())?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok(LeaveGroupProposal {
            change,
            stage_key,
            aux_secret_key: self.upstream_art.get_leaf_secret_key(),
            private_zero_art: temporary_art,
        })
    }

    fn sign_with_leaf_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.upstream_art.get_leaf_secret_key()],
            &vec![self.upstream_art.get_leaf_public_key()],
            message,
        )?)
    }

    fn sign_with_tree_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.upstream_art.get_root_secret_key()],
            &vec![self.upstream_art.get_root_public_key()],
            message,
        )?)
    }

    fn leaf_public_key(&self) -> CortadoAffine {
        self.upstream_art.get_leaf_public_key()
    }

    fn stage_key(&self) -> StageKey {
        self.upstream_stk
    }

    fn leaf_key(&self) -> ScalarField {
        self.upstream_art.get_leaf_secret_key()
    }

    fn tree_key(&self) -> ScalarField {
        self.upstream_art.get_root_secret_key()
    }
}

impl LinearKeyedValidator {
    pub fn new(base_art: PrivateArt<CortadoAffine>, base_stk: StageKey, epoch: u64) -> Self {
        Self {
            upstream_art: PrivateZeroArt::new(
                base_art.clone(),
                Box::new(StdRng::from_rng(thread_rng()).unwrap()),
            ),
            upstream_stk: base_stk,
            base_art,
            base_stk,
            changes: HashMap::new(),
            epoch,
            participant: None,
            participation_leafs: BoundedMap::with_capacity(8),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        type Parts = (
            PrivateArt<CortadoAffine>,
            StageKey,
            PrivateArt<CortadoAffine>,
            StageKey,
            HashMap<ChangesID, BranchChange<CortadoAffine>>,
            u64,
            Option<Participant>,
            BoundedMap<ChangesID, ScalarField>,
        );

        let parts: Parts = (
            self.upstream_art.get_private_art().clone(),
            self.upstream_stk,
            self.base_art.clone(),
            self.base_stk,
            self.changes.clone(),
            self.epoch,
            self.participant.clone(),
            self.participation_leafs.clone(),
        );
        postcard::to_allocvec(&parts).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        type Parts = (
            PrivateArt<CortadoAffine>,
            StageKey,
            PrivateArt<CortadoAffine>,
            StageKey,
            HashMap<ChangesID, BranchChange<CortadoAffine>>,
            u64,
            Option<Participant>,
            BoundedMap<ChangesID, ScalarField>,
        );
        let parts: Parts = postcard::from_bytes(value).map_err(|_| errors::Error::InvalidInput)?;

        Ok(Self {
            base_art: parts.2,
            base_stk: parts.3,
            upstream_art: PrivateZeroArt::new(
                parts.0,
                Box::new(StdRng::from_rng(thread_rng()).unwrap()),
            ),
            upstream_stk: parts.1,
            changes: parts.4,
            epoch: parts.5,
            participant: parts.6,
            participation_leafs: parts.7,
        })
    }

    pub fn is_participant(&self) -> bool {
        self.participant.is_some()
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.upstream_art.get_node_index()
    }
}

#[cfg(test)]
mod tests;
