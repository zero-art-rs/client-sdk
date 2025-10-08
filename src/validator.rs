use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use std::collections::HashMap;
use zrt_zk::art::ARTProof;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPrivateView, ARTPublicAPI, ARTPublicView},
    types::{ARTNode, BranchChanges, LeafIter, LeafStatus, PrivateART, PublicART},
};

use crate::{
    bounded_map::BoundedMap,
    error::{Error, Result},
    models::frame::{Frame, GroupOperation},
    proof_system::get_proof_system,
    utils::{
        ChangesID, StageKey, compute_changes_id, decrypt, derive_leaf_key, derive_stage_key,
        deserialize, serialize,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Validator {
    base_art: PublicART<CortadoAffine>,
    upstream_art: PublicART<CortadoAffine>,
    changes: Vec<BranchChanges<CortadoAffine>>,
    closed: bool,
    epoch: u64,
}

impl Validator {
    pub fn new(base_art: PublicART<CortadoAffine>, epoch: u64) -> Self {
        Self {
            upstream_art: base_art.clone(),
            base_art,
            changes: vec![],
            closed: true,
            epoch,
        }
    }

    pub fn validate(&mut self, frame: &Frame) -> Result<Option<ARTOperation>> {
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
            GroupOperation::AddMember(changes) => {
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
                let operation = ARTOperation::AddMember {
                    member_public_key: changes
                        .public_keys
                        .last()
                        .ok_or(Error::InvalidInput)?
                        .clone(),
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = true;

                Ok(Some(operation))
            }
            GroupOperation::KeyUpdate(changes) => {
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
                let operation = ARTOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: changes
                        .public_keys
                        .last()
                        .ok_or(Error::InvalidInput)?
                        .clone(),
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            GroupOperation::RemoveMember(changes) => {
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
                let operation = ARTOperation::RemoveMember {
                    member_public_key: public_key,
                };

                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(Some(operation))
            }
            GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key);
                Ok(Some(ARTOperation::Init))
            }
            GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.upstream_art.get_node(node_index)?.get_public_key();
                frame.verify_schnorr::<Sha3_256>(public_key);
                Ok(Some(ARTOperation::LeaveGroup))
            }
            GroupOperation::DropGroup(_) => unimplemented!(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }

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

fn group_owner_leaf_public_key<A: ARTPublicView<CortadoAffine>>(art: &A) -> CortadoAffine {
    LeafIter::new(art.get_root())
        .next()
        .expect("ART can't be empty")
        .get_public_key()
}

#[derive(Debug)]
pub enum ARTOperation {
    Init,
    LeaveGroup,
    DropGroup,
    AddMember {
        member_public_key: CortadoAffine,
    },
    KeyUpdate {
        old_public_key: CortadoAffine,
        new_public_key: CortadoAffine,
    },
    RemoveMember {
        member_public_key: CortadoAffine,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Participant {
    id: ChangesID,
    branch: BranchChanges<CortadoAffine>,
    art: PrivateART<CortadoAffine>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyedValidator {
    base_art: PrivateART<CortadoAffine>,
    base_stk: StageKey,

    upstream_art: PrivateART<CortadoAffine>,
    upstream_stk: StageKey,

    changes: HashMap<ChangesID, BranchChanges<CortadoAffine>>,

    epoch: u64,

    participant: Option<Participant>,
    participation_leafs: BoundedMap<ChangesID, ScalarField>,
}

impl KeyedValidator {
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

    pub fn validate(&mut self, frame: &Frame) -> Result<(Option<ARTOperation>, StageKey)> {
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

        let group_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidEpoch)?;

        match group_operation {
            GroupOperation::AddMember(changes) => {
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
                let operation = ARTOperation::AddMember {
                    member_public_key: changes
                        .public_keys
                        .last()
                        .ok_or(Error::InvalidInput)?
                        .clone(),
                };

                Ok((Some(operation), self.apply_changes(changes)?))
            }
            GroupOperation::KeyUpdate(changes) => {
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
                let operation = ARTOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: changes
                        .public_keys
                        .last()
                        .ok_or(Error::InvalidInput)?
                        .clone(),
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), stage_key))
            }
            GroupOperation::RemoveMember(changes) => {
                if self.upstream_art.node_index == changes.node_index {
                    return Err(Error::UserRemovedFromGroup);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    let verifier_artefacts = self
                        .upstream_art
                        .compute_artefacts_for_verification(changes)?;
                    let public_key = if LeafStatus::Active != self
                        .upstream_art
                        .get_node(&changes.node_index)?
                        .get_status().ok_or(Error::InvalidInput)?
                    {
                        (CortadoAffine::generator() * self.upstream_art.get_root_key()?.key).into_affine()
                    } else {
                        group_owner_leaf_public_key(&self.upstream_art)
                    };
                    (verifier_artefacts, public_key)
                } else {
                    let verifier_artefacts =
                        self.base_art.compute_artefacts_for_verification(changes)?;
                    let public_key = if LeafStatus::Active != self
                        .base_art
                        .get_node(&changes.node_index)?
                        .get_status().ok_or(Error::InvalidInput)?
                    {
                        (CortadoAffine::generator() * self.base_art.get_root_key()?.key).into_affine()
                    } else {
                        group_owner_leaf_public_key(&self.base_art)
                    };
                    (verifier_artefacts, public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                let operation = ARTOperation::RemoveMember {
                    member_public_key: public_key,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), stage_key))
            }
            GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key)?;
                Ok((Some(ARTOperation::Init), self.upstream_stk))
            }
            GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.upstream_art.get_node(node_index)?.get_public_key();
                frame.verify_schnorr::<Sha3_256>(public_key)?;
                Ok((Some(ARTOperation::LeaveGroup), self.upstream_stk))
            }
            GroupOperation::DropGroup(_) => unimplemented!(),
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
                .iter()
                .map(|(_, c)| c.clone())
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
            return Err(Error::InvalidInput);
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
                .filter_map(|(&id, c)| (id != participant.id).then(|| c.clone()))
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
            upstream_art.merge_for_observer(
                &self
                    .changes
                    .clone()
                    .into_iter()
                    .map(|(_, changes)| changes)
                    .collect::<Vec<_>>(),
            )?;

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
            return Err(Error::InvalidInput);
        }

        // Derive current stk and art
        let mut upstream_art = self.upstream_art.clone();

        if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            upstream_art.update_key(&secret_key)?;

            let participant = Participant {
                id: changes_id,
                branch: changes.clone(),
                art: upstream_art.clone(),
            };

            let upstream_stk =
                derive_stage_key(&self.upstream_stk, upstream_art.get_root_key()?.key)?;

            // Advance base
            self.base_art = self.upstream_art.clone();
            self.base_stk = self.upstream_stk;

            // Advance upstream
            self.upstream_art = upstream_art;
            self.upstream_stk = upstream_stk;

            self.participant = Some(participant);
            self.changes.insert(changes_id, changes.clone());

            return Ok(upstream_stk);
        }

        upstream_art.update_private_art(changes)?;
        let upstream_stk = derive_stage_key(&self.upstream_stk, upstream_art.get_root_key()?.key)?;

        // Advance base
        self.base_art = self.upstream_art.clone();
        self.base_stk = self.upstream_stk;

        // Advance current
        self.upstream_art = upstream_art;
        self.upstream_stk = upstream_stk;

        self.participant = None;
        self.changes = HashMap::new();
        self.changes.insert(changes_id, changes.clone());

        Ok(self.upstream_stk)
    }

    pub fn add_member(
        &self,
        secret_key: ScalarField,
    ) -> Result<(
        impl FnOnce(&[u8]) -> Result<ARTProof>,
        BranchChanges<CortadoAffine>,
        StageKey,
    )> {
        if self.public_key() != group_owner_leaf_public_key(&self.upstream_art) {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) =
            temporary_art.append_or_replace_node(&secret_key)?;
        let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(prover_artefacts, &vec![current_secret_key], associated_data)
                .map_err(|e| e.into())
        };

        Ok((prove, changes, stk))
    }

    pub fn remove_member(
        &self,
        public_key: &CortadoAffine,
        vanishing_secret_key: ScalarField,
    ) -> Result<(
        impl FnOnce(&[u8]) -> Result<ARTProof>,
        BranchChanges<CortadoAffine>,
        StageKey,
    )> {
        if self.public_key() != group_owner_leaf_public_key(&self.upstream_art) {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.make_blank(
            &self.upstream_art.get_path_to_leaf(public_key)?,
            &vanishing_secret_key,
        )?;
        let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(prover_artefacts, &vec![current_secret_key], associated_data)
                .map_err(|e| e.into())
        };

        Ok((prove, changes, stk))
    }

    pub fn update_key(
        &mut self,
    ) -> Result<(
        impl FnOnce(&[u8]) -> Result<ARTProof>,
        BranchChanges<CortadoAffine>,
        StageKey,
    )> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.upstream_art.secret_key)?;

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
        let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(prover_artefacts, &vec![current_secret_key], associated_data)
                .map_err(|e| e.into())
        };

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok((prove, changes, stk))
    }

    pub fn update_key_with(
        &mut self,
        secret_key: ScalarField,
    ) -> Result<(
        impl FnOnce(&[u8]) -> Result<ARTProof>,
        BranchChanges<CortadoAffine>,
        StageKey,
    )> {
        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
        let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(prover_artefacts, &vec![current_secret_key], associated_data)
                .map_err(|e| e.into())
        };

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok((prove, changes, stk))
    }

    pub fn public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.upstream_art.secret_key).into_affine()
    }
}
