use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafStatus, PrivateART, PublicART},
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
        AddMemberProposal, ChangesID, GroupOperation, RemoveMemberProposal, StageKey,
        UpdateKeyProposal, ValidationResult, ValidationWithKeyResult,
    },
    utils::{compute_changes_id, derive_leaf_key, derive_stage_key, deserialize},
};
use cortado::{self, CortadoAffine, Fr as ScalarField};

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
    fn validate_and_derive_key(&mut self, frame: &frame::Frame) -> Result<ValidationWithKeyResult> {
        let frame_epoch = frame.frame_tbs().epoch();

        if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
            return Err(Error::InvalidEpoch);
        }

        let is_next_epoch = frame_epoch == self.epoch + 1;

        // If frame don't have group operation then it is just payload frame that should have current epoch
        if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
            frame.verify_schnorr::<Sha3_256>(self.upstream_art.get_root().get_public_key())?;
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
                println!("IsNextEpoch: {}", is_next_epoch);

                if !is_next_epoch {
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

                Ok((Some(operation), self.apply_changes(changes)?))
            }
            frame::GroupOperation::KeyUpdate(changes) => {
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

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), stage_key))
            }
            frame::GroupOperation::RemoveMember(changes) => {
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
                let operation = GroupOperation::RemoveMember {
                    member_public_key: public_key,
                };

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
            frame::GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.upstream_art.get_node(node_index)?.get_public_key();
                frame.verify_schnorr::<Sha3_256>(public_key)?;
                Ok((Some(GroupOperation::LeaveGroup), self.upstream_stk))
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

        Ok(RemoveMemberProposal {
            changes,
            stage_key: derive_stage_key(&self.upstream_stk, tree_key.key)?,
            prover_artefacts,
            aux_secret_key: self.upstream_art.secret_key,
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

    fn merge_changes_and_participate(
        &mut self,
        changes_id: ChangesID,
        changes: BranchChanges<CortadoAffine>,
        secret_key: ScalarField,
    ) -> Result<StageKey> {
        let mut upstream_art = self.base_art.clone();
        let (tree_key, _, _) = upstream_art.update_key(&secret_key)?;
        let branch_stk = derive_stage_key(&self.base_stk, tree_key.key)?;

        let participant = Participant {
            id: changes_id,
            branch: changes.clone(),
            art: upstream_art.clone(),
        };

        upstream_art.merge_for_participant(
            changes.clone(),
            &self
                .changes
                .values()
                .cloned()
                .collect::<Vec<BranchChanges<CortadoAffine>>>(),
            self.base_art.clone(),
        )?;
        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;

        self.upstream_art = upstream_art;
        self.upstream_stk = upstream_stk;

        self.participant = Some(participant);
        self.changes.insert(changes_id, changes);

        Ok(branch_stk)
    }

    fn merge_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
            .try_into()
            .unwrap();

        if self.changes.contains_key(&changes_id) {
            return Err(Error::ChangesAlreadyApplied);
        }

        if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            return self.merge_changes_and_participate(changes_id, changes.clone(), secret_key);
        }

        // Derive branch stk to decrypt payload
        let mut branch_art = self.base_art.clone();
        branch_art.update_private_art(changes)?;
        let branch_stk = derive_stage_key(&self.base_stk, branch_art.get_root_key()?.key)?;

        let upstream_art = if let Some(participant) = &self.participant {
            // Derive upstream art and stk to advance epoch and encrypt new payloads
            let mut upstream_art = participant.art.clone();
            let target_changes = self
                .changes
                .iter()
                .filter(|&(&id, _)| (id != participant.id))
                .map(|(_, c)| c.clone())
                .chain(std::iter::once(changes.clone()))
                .collect::<Vec<_>>();

            upstream_art.merge_for_participant(
                participant.branch.clone(),
                &target_changes,
                self.base_art.clone(),
            )?;

            upstream_art
        } else {
            let mut upstream_art = self.base_art.clone();
            upstream_art
                .merge_for_observer(&self.changes.clone().into_values().collect::<Vec<_>>())?;

            upstream_art
        };

        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;

        self.upstream_art = upstream_art;
        self.upstream_stk = upstream_stk;

        self.changes.insert(changes_id, changes.clone());

        Ok(branch_stk)
    }

    fn apply_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
            .try_into()
            .unwrap();

        if self.changes.contains_key(&changes_id) {
            return Err(Error::ChangesAlreadyApplied);
        }

        // Derive current stk and art
        let mut upstream_art = self.upstream_art.clone();

        let participant = if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            upstream_art.update_key(&secret_key)?;

            let participant = Participant {
                id: changes_id,
                branch: changes.clone(),
                art: upstream_art.clone(),
            };
            Some(participant)
        } else {
            upstream_art.update_private_art(changes)?;
            None
        };

        let upstream_stk = derive_stage_key(&self.upstream_stk, upstream_art.get_root_key()?.key)?;

        // Advance base
        self.base_art = self.upstream_art.clone();
        self.base_stk = self.upstream_stk;

        // Advance current
        self.upstream_art = upstream_art;
        self.upstream_stk = upstream_stk;

        self.participant = participant;
        self.changes = HashMap::new();
        self.changes.insert(changes_id, changes.clone());
        self.epoch += 1;

        Ok(self.upstream_stk)
    }

    pub fn is_participant(&self) -> bool {
        self.participant.is_some()
    }
}

#[cfg(test)]
mod tests;
