use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use tracing::{Level, debug, instrument, span, trace};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafStatus, NodeIndex, PrivateART, PublicART},
};
use zrt_crypto::schnorr;

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
    utils::{compute_changes_id, derive_leaf_key, derive_stage_key, deserialize},
};
use cortado::{self, CortadoAffine, Fr as ScalarField};

mod merge_strategy;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Participant {
    id: ChangesID,
    branch: BranchChanges<CortadoAffine>,
    art: PrivateART<CortadoAffine>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinearKeyedValidator {
    base_art: PrivateART<CortadoAffine>,
    base_stk: StageKey,

    upstream_art: PrivateART<CortadoAffine>,
    upstream_stk: StageKey,

    changes: HashMap<ChangesID, BranchChanges<CortadoAffine>>,

    epoch: u64,

    participant: Option<Participant>,
    participation_leafs: BoundedMap<ChangesID, ScalarField>,
}

impl Validator for LinearKeyedValidator {
    fn validate(&mut self, frame: &frame::Frame) -> Result<ValidationResult> {
        let (result, _) = self.validate_and_derive_key(frame)?;
        Ok(result)
    }

    fn tree(&self) -> &PublicART<CortadoAffine> {
        &self.upstream_art.public_art
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
            frame::GroupOperation::AddMember(changes) => {
                let span = span!(Level::TRACE, "add_member_frame");
                let _enter = span.enter();

                trace!("Changes: {:?}", changes);

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    trace!(
                        "Verifier artefacts based on upstream: {:?}",
                        verifier_artefacts
                    );
                    let public_key = group_owner_leaf_public_key(&self.upstream_art);
                    trace!("Upstream owner leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    trace!("Verifier artefacts based on base: {:?}", verifier_artefacts);
                    let public_key = group_owner_leaf_public_key(&self.base_art);
                    trace!("Base owner leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;

                let operation = GroupOperation::AddMember {
                    member_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };
                if !is_next_epoch {
                    return Ok((Some(operation), self.upstream_stk));
                }

                Ok((Some(operation), self.apply_changes(changes)?))
            }
            frame::GroupOperation::KeyUpdate(changes) => {
                let span = span!(Level::TRACE, "key_update_frame");
                let _enter = span.enter();

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    trace!(
                        "Verifier artefacts based on upstream: {:?}",
                        verifier_artefacts
                    );
                    let public_key = self
                        .upstream_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    trace!("Upstream member leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    trace!("Verifier artefacts based on base: {:?}", verifier_artefacts);
                    let public_key = self
                        .base_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    trace!("Base member leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), stage_key))
            }
            frame::GroupOperation::RemoveMember(changes) => {
                let span = span!(Level::TRACE, "remove_member_frame");
                let _enter = span.enter();

                if self.upstream_art.node_index == changes.node_index {
                    return Err(Error::UserRemovedFromGroup);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = if LeafStatus::Active
                        != self
                            .upstream_art
                            .get_node(&changes.node_index)?
                            .get_status()
                            .ok_or(Error::InvalidInput)?
                    {
                        (CortadoAffine::generator() * self.upstream_art.get_root_key()?.key)
                            .into_affine()
                    } else {
                        group_owner_leaf_public_key(&self.upstream_art)
                    };
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = if LeafStatus::Active
                        != self
                            .base_art
                            .get_node(&changes.node_index)?
                            .get_status()
                            .ok_or(Error::InvalidInput)?
                    {
                        (CortadoAffine::generator() * self.base_art.get_root_key()?.key)
                            .into_affine()
                    } else {
                        group_owner_leaf_public_key(&self.base_art)
                    };
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;

                let member_public_key = if is_next_epoch {
                    self.upstream_art
                        .get_node(&changes.node_index)?
                        .get_public_key()
                } else {
                    self.base_art
                        .get_node(&changes.node_index)?
                        .get_public_key()
                };

                let operation = GroupOperation::RemoveMember { member_public_key };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
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
            frame::GroupOperation::LeaveGroup(changes) => {
                let span = span!(Level::TRACE, "leave_group_frame");
                let _enter = span.enter();

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    trace!(
                        "Verifier artefacts based on upstream: {:?}",
                        verifier_artefacts
                    );
                    let public_key = self
                        .upstream_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    trace!("Upstream member leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    trace!("Verifier artefacts based on base: {:?}", verifier_artefacts);
                    let public_key = self
                        .base_art
                        .get_node(&changes.node_index)?
                        .get_public_key();
                    trace!("Base member leaf key: {:?}", public_key);
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
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
        let (tree_key, changes, prover_artefacts) =
            temporary_art.append_or_replace_node(&leaf_secret)?;

        Ok(AddMemberProposal {
            changes,
            stage_key: derive_stage_key(&self.upstream_stk, tree_key.key)?,
            prover_artefacts,
            aux_secret_key: self.upstream_art.secret_key,
        })
    }

    fn propose_remove_member(
        &self,
        leaf_public_key: CortadoAffine,
        vanishing_secret_key: ScalarField,
    ) -> Result<RemoveMemberProposal> {
        let leaf = self.upstream_art.get_leaf_with(&leaf_public_key)?;

        if self.leaf_public_key() != group_owner_leaf_public_key(&self.upstream_art)
            && leaf.is_active()
        {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.make_blank(
            &self.upstream_art.get_path_to_leaf(&leaf_public_key)?,
            &vanishing_secret_key,
        )?;

        let secret_key = if leaf.is_active() {
            self.upstream_art.secret_key
        } else {
            self.upstream_art.get_root_key()?.key
        };

        Ok(RemoveMemberProposal {
            changes,
            stage_key: derive_stage_key(&self.upstream_stk, tree_key.key)?,
            prover_artefacts,
            aux_secret_key: secret_key,
        })
    }

    fn propose_update_key(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.upstream_art.secret_key)?;

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
        let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok(UpdateKeyProposal {
            changes,
            stage_key,
            prover_artefacts,
            aux_secret_key: self.upstream_art.secret_key,
        })
    }

    fn propose_leave_group(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.upstream_art.secret_key)?;

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.leave(secret_key)?;
        let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok(LeaveGroupProposal {
            changes,
            stage_key,
            prover_artefacts,
            aux_secret_key: self.upstream_art.secret_key,
        })
    }

    fn sign_with_leaf_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.upstream_art.secret_key],
            &vec![(CortadoAffine::generator() * self.upstream_art.secret_key).into_affine()],
            message,
        )?)
    }

    fn sign_with_tree_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        let tree_key = self.upstream_art.get_root_key()?;
        Ok(schnorr::sign(
            &vec![tree_key.key],
            &vec![(tree_key.generator * tree_key.key).into_affine()],
            message,
        )?)
    }

    fn leaf_public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.upstream_art.secret_key).into_affine()
    }

    fn stage_key(&self) -> StageKey {
        self.upstream_stk
    }

    fn leaf_key(&self) -> ScalarField {
        self.upstream_art.secret_key
    }

    fn tree_key(&self) -> ScalarField {
        self.upstream_art
            .get_root_key()
            .expect("Something very BAD happened")
            .key
    }
}

impl LinearKeyedValidator {
    pub fn new(base_art: PrivateART<CortadoAffine>, base_stk: StageKey, epoch: u64) -> Self {
        Self {
            upstream_art: base_art.clone(),
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
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }

    pub fn is_participant(&self) -> bool {
        self.participant.is_some()
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.upstream_art.node_index
    }
}

#[cfg(test)]
mod tests;
