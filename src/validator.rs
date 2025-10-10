use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use std::{collections::HashMap, sync::Mutex};
use tracing::{Level, instrument, span, trace};
use zrt_crypto::schnorr;
use zrt_zk::art::ARTProof;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafIter, LeafStatus, PrivateART},
};

use crate::{
    bounded_map::BoundedMap,
    core::types::{self, ChangesID, StageKey},
    error::{Error, Result},
    models::{
        frame::{Frame, FrameTbs, GroupOperation, Proof},
        group_info::{GroupInfo, Role, User, public_key_to_id},
        invite::{Invite, InviteTbs, Invitee, ProtectedInviteData},
        payload::{GroupActionPayload, Payload},
        protected_payload::{ProtectedPayload, ProtectedPayloadTbs, Sender},
    },
    proof_system::get_proof_system,
    utils::{
        compute_changes_id, decrypt, derive_invite_key, derive_leaf_key, derive_stage_key,
        deserialize, encrypt, serialize,
    },
};
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

fn decrypt_factory(stage_key: StageKey) -> impl Fn(&[u8], &[u8]) -> Result<Vec<u8>> {
    move |ciphertext: &[u8], associated_data: &[u8]| {
        decrypt(&stage_key, ciphertext, associated_data)
    }
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

    #[instrument(skip_all)]
    pub fn validate(
        &mut self,
        frame: &Frame,
    ) -> Result<(
        Option<types::GroupOperation<CortadoAffine>>,
        impl Fn(&[u8], &[u8]) -> Result<Vec<u8>> + 'static,
    )> {
        trace!("Frame: {:?}", frame);

        trace!("Validator epoch: {}", self.epoch);
        let frame_epoch = frame.frame_tbs().epoch();
        trace!("Frame epoch: {frame_epoch}");

        if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
            return Err(Error::InvalidEpoch);
        }

        let is_next_epoch = frame_epoch == self.epoch + 1;
        trace!("Is next epoch: {is_next_epoch}");

        // If frame don't have group operation then it is just payload frame that should have current epoch
        trace!("Group operation: {:?}", frame.frame_tbs().group_operation());
        if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
            let span = span!(Level::TRACE, "Payload frame");
            let _enter = span.enter();

            trace!(
                "Upstream root public key: {:?}",
                self.upstream_art.get_root().get_public_key()
            );
            frame.verify_schnorr::<Sha3_256>(self.upstream_art.get_root().get_public_key())?;
            trace!("Upstream stage key: {:?}", self.upstream_stk);
            return Ok((None, decrypt_factory(self.upstream_stk)));
        }

        if matches!(
            frame.frame_tbs().group_operation(),
            Some(GroupOperation::Init(_))
        ) && frame_epoch != 0
        {
            return Err(Error::InvalidEpoch);
        }

        let group_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidEpoch)?;

        match group_operation {
            GroupOperation::AddMember(changes) => {
                let span = span!(Level::TRACE, "Add member frame");
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
                
                let operation = types::GroupOperation::AddMember {
                    member_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };
                if !is_next_epoch {
                    return Ok((Some(operation), decrypt_factory(self.upstream_stk)));
                }

                Ok((
                    Some(operation),
                    decrypt_factory(self.apply_changes(changes)?),
                ))
            }
            GroupOperation::KeyUpdate(changes) => {
                let span = span!(Level::TRACE, "Key update frame");
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
                let operation = types::GroupOperation::KeyUpdate {
                    old_public_key: public_key,
                    new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), decrypt_factory(stage_key)))
            }
            GroupOperation::RemoveMember(changes) => {
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
                let operation = types::GroupOperation::RemoveMember {
                    member_public_key: public_key,
                };

                let stage_key = if is_next_epoch {
                    self.apply_changes(changes)?
                } else {
                    self.merge_changes(changes)?
                };

                Ok((Some(operation), decrypt_factory(stage_key)))
            }
            GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key)?;
                Ok((
                    Some(types::GroupOperation::Init),
                    decrypt_factory(self.upstream_stk),
                ))
            }
            GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.upstream_art.get_node(node_index)?.get_public_key();
                frame.verify_schnorr::<Sha3_256>(public_key)?;
                Ok((
                    Some(types::GroupOperation::LeaveGroup),
                    decrypt_factory(self.upstream_stk),
                ))
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

    #[instrument(skip_all)]
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

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        trace!("Resulted epoch: {}", self.epoch);

        Ok(branch_stk)
    }

    #[instrument(skip_all)]
    fn merge_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        trace!("Changes: {:?}", changes);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
            .try_into()
            .unwrap();

        trace!("ChangesID: {:?}", changes_id);

        if self.changes.contains_key(&changes_id) {
            trace!("Changes already applied");
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

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        trace!("Resulted epoch: {}", self.epoch);

        Ok(branch_stk)
    }

    #[instrument(skip_all)]
    fn apply_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        trace!("Changes: {:?}", changes);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
            .try_into()
            .unwrap();

        trace!("ChangesID: {:?}", changes_id);

        if self.changes.contains_key(&changes_id) {
            trace!("Changes already applied");
            return Err(Error::ChangesAlreadyApplied);
        }

        // Derive current stk and art
        let mut upstream_art = self.upstream_art.clone();

        let participant = if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            trace!("We initiate new epoch");
            trace!("New leaf secret: {:?}", secret_key);
            upstream_art.update_key(&secret_key)?;

            let participant = Participant {
                id: changes_id,
                branch: changes.clone(),
                art: upstream_art.clone(),
            };
            Some(participant)
        } else {
            trace!("Epoch initiated by another member");
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

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        trace!("Resulted epoch: {}", self.epoch);

        Ok(self.upstream_stk)
    }

    pub fn add_member(
        &self,
        secret_key: ScalarField,
    ) -> Result<(
        BranchChanges<CortadoAffine>,
        StageKey,
        impl Fn(&[u8]) -> Result<ARTProof> + 'static,
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
                .prove(
                    prover_artefacts.clone(),
                    &[current_secret_key],
                    associated_data,
                )
                .map_err(|e| e.into())
        };

        Ok((changes, stk, prove))
    }

    pub fn remove_member(
        &self,
        public_key: &CortadoAffine,
        vanishing_secret_key: ScalarField,
    ) -> Result<(
        BranchChanges<CortadoAffine>,
        StageKey,
        impl Fn(&[u8]) -> Result<ARTProof> + 'static,
    )> {
        if self.public_key() != group_owner_leaf_public_key(&self.upstream_art) {
            return Err(Error::Forbidden);
        }

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.make_blank(
            &self.upstream_art.get_path_to_leaf(public_key)?,
            &vanishing_secret_key,
        )?;
        let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(
                    prover_artefacts.clone(),
                    &[current_secret_key],
                    associated_data,
                )
                .map_err(|e| e.into())
        };

        Ok((changes, stage_key, prove))
    }

    pub fn update_key(
        &mut self,
    ) -> Result<(
        BranchChanges<CortadoAffine>,
        StageKey,
        impl Fn(&[u8]) -> Result<ARTProof> + 'static,
    )> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.upstream_art.secret_key)?;

        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
        let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(
                    prover_artefacts.clone(),
                    &[current_secret_key],
                    associated_data,
                )
                .map_err(|e| e.into())
        };

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok((changes, stage_key, prove))
    }

    pub fn update_key_with(
        &mut self,
        secret_key: ScalarField,
    ) -> Result<(
        BranchChanges<CortadoAffine>,
        impl Fn(&[u8], &[u8]) -> Result<Vec<u8>> + 'static,
        impl Fn(&[u8]) -> Result<ARTProof> + 'static,
    )> {
        let mut temporary_art = self.upstream_art.clone();
        let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
        let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

        let current_secret_key = self.upstream_art.secret_key;
        let prove = move |associated_data: &[u8]| {
            get_proof_system()
                .prove(
                    prover_artefacts.clone(),
                    &[current_secret_key],
                    associated_data,
                )
                .map_err(|e| e.into())
        };

        let encrypt = move |plaintext: &[u8], associated_data: &[u8]| {
            encrypt(&stk, plaintext, associated_data)
        };

        let changes_id = compute_changes_id(&changes)?;
        self.participation_leafs.insert(changes_id, secret_key);

        Ok((changes, encrypt, prove))
    }

    pub fn public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.upstream_art.secret_key).into_affine()
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        encrypt(&self.upstream_stk, plaintext, associated_data)
    }

    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        decrypt(&self.upstream_stk, ciphertext, associated_data)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_participant(&self) -> bool {
        self.participant.is_some()
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(u64);

impl Nonce {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn next(&mut self) -> Vec<u8> {
        let nonce = self.0.to_le_bytes().to_vec();
        self.0 += 1;
        nonce
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub struct GroupContext {
    identity_secret_key: ScalarField,
    validator: Mutex<KeyedValidator>,
    group_info: GroupInfo,
    seq_num: u64,
    nonce: Nonce,
}

impl GroupContext {
    pub fn new(
        identity_secret_key: ScalarField,
        user: User,
        mut group_info: GroupInfo,
    ) -> Result<(Self, Frame)> {
        let leaf_secret = ScalarField::rand(&mut thread_rng());
        let (base_art, tree_key) =
            PrivateART::new_art_from_secrets(&vec![leaf_secret], &CortadoAffine::generator())?;
        let base_stk = derive_stage_key(&[0u8; 32], tree_key.key)?;

        group_info
            .members_mut()
            .insert((CortadoAffine::generator() * leaf_secret).into(), user);

        let frame = FrameTbs::new(
            group_info.id(),
            0,
            serialize((CortadoAffine::generator() * identity_secret_key).into_affine())?,
            Some(GroupOperation::Init(base_art.clone().into())),
            vec![],
        )
        .prove_schnorr::<Sha3_256>(identity_secret_key)?;

        Ok((
            Self {
                identity_secret_key,
                validator: Mutex::new(KeyedValidator::new(base_art, base_stk, 0)),
                group_info,
                seq_num: 0,
                nonce: Nonce(0),
            },
            frame,
        ))
    }

    pub fn into_parts(self) -> (ScalarField, KeyedValidator, GroupInfo, u64, Nonce) {
        (
            self.identity_secret_key,
            self.validator.into_inner().unwrap(),
            self.group_info,
            self.seq_num,
            self.nonce,
        )
    }

    pub fn to_parts(&self) -> (ScalarField, KeyedValidator, GroupInfo, u64, Nonce) {
        (
            self.identity_secret_key,
            self.validator.lock().unwrap().clone(),
            self.group_info.clone(),
            self.seq_num,
            self.nonce,
        )
    }

    pub fn from_parts(
        identity_secret_key: ScalarField,
        validator: KeyedValidator,
        group_info: GroupInfo,
        seq_num: u64,
        nonce: Nonce,
    ) -> Self {
        Self {
            identity_secret_key,
            validator: Mutex::new(validator),
            group_info,
            seq_num,
            nonce,
        }
    }

    pub fn process_frame(&mut self, frame: Frame) -> Result<Vec<Payload>> {
        let mut validator = self.validator.lock().unwrap();
        let (operation, decrypt) = validator.validate(&frame)?;

        let protected_payload = ProtectedPayload::decode(&decrypt(
            frame.frame_tbs().protected_payload(),
            &frame.frame_tbs().associated_data::<Sha3_256>()?,
        )?)?;

        let Some(operation) = operation else {
            return Ok(protected_payload
                .protected_payload_tbs()
                .payloads()
                .to_vec());
        };

        match operation {
            types::GroupOperation::AddMember { member_public_key } => {
                trace!("GroupMembers count: {}", self.group_info.members().len());
                if self.group_info.members().is_empty() {
                    let group_info = protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .iter()
                        .find_map(|payload| match payload {
                            Payload::Action(GroupActionPayload::InviteMember(group_info)) => {
                                Some(group_info.to_owned())
                            }
                            _ => None,
                        });

                    if let Some(group_info) = group_info {
                        self.group_info = group_info;
                    }
                }

                let sender_public_key = match protected_payload.protected_payload_tbs().sender() {
                    Sender::UserId(user_id) => self
                        .group_info
                        .members()
                        .get(user_id)
                        .ok_or(Error::SenderNotInGroup)?
                        .public_key(),
                    Sender::LeafId(_) => unimplemented!(),
                };
                protected_payload.verify::<Sha3_256>(sender_public_key)?;

                let member = User::new_with_id(
                    public_key_to_id(member_public_key),
                    String::from("Invited"),
                    CortadoAffine::identity(),
                    serialize(member_public_key)?,
                    Role::Write,
                );
                self.group_info
                    .members_mut()
                    .insert(member_public_key, member);
            }
            types::GroupOperation::KeyUpdate {
                old_public_key,
                new_public_key,
            } => {
                let sender_public_key = match protected_payload.protected_payload_tbs().sender() {
                    Sender::UserId(user_id) => self
                        .group_info
                        .members()
                        .get(user_id)
                        .ok_or(Error::SenderNotInGroup)?
                        .public_key(),
                    Sender::LeafId(_) => {
                        // TODO: Map for leafs
                        old_public_key
                    }
                };
                protected_payload.verify::<Sha3_256>(sender_public_key)?;

                let leaf_id = public_key_to_id(old_public_key);

                if self.group_info.members().get(&leaf_id).is_some() {
                    let user = protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .iter()
                        .find_map(|payload| match payload {
                            Payload::Action(GroupActionPayload::JoinGroup(user)) => {
                                Some(user.to_owned())
                            }
                            _ => None,
                        });

                    if let Some(user) = user {
                        self.group_info
                            .members_mut()
                            .update_user(old_public_key, user);
                    }
                }

                self.group_info
                    .members_mut()
                    .update_leaf(old_public_key, new_public_key);
            }
            types::GroupOperation::RemoveMember { member_public_key } => {
                let sender_public_key = match protected_payload.protected_payload_tbs().sender() {
                    Sender::UserId(user_id) => self
                        .group_info
                        .members()
                        .get(user_id)
                        .ok_or(Error::SenderNotInGroup)?
                        .public_key(),
                    Sender::LeafId(_) => unimplemented!(),
                };
                protected_payload.verify::<Sha3_256>(sender_public_key)?;

                self.group_info
                    .members_mut()
                    .remove_by_leaf(&member_public_key);
            }
            _ => {}
        }

        Ok(protected_payload
            .protected_payload_tbs()
            .payloads()
            .to_vec())
    }

    pub fn add_member(
        &mut self,
        invitee: Invitee,
        mut payloads: Vec<Payload>,
    ) -> Result<(Frame, Invite)> {
        let validator = self.validator.lock().unwrap();
        // Future epoch
        let epoch = validator.epoch() + 1;

        // 1. Generate ephemeral secret key
        let ephemeral_secret_key = ScalarField::rand(&mut thread_rng());
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        let leaf_secret = self.compute_leaf_secret_for_invitee(invitee, ephemeral_secret_key)?;

        // Predict add member changes
        let (changes, stage_key, prove) = validator.add_member(leaf_secret)?;

        payloads.push(Payload::Action(GroupActionPayload::InviteMember(
            self.group_info.clone(),
        )));

        // Frame construction
        let protected_payload_tbs = ProtectedPayloadTbs::new(
            self.seq_num,
            Utc::now(),
            payloads,
            Sender::UserId(public_key_to_id(self.identity_public_key())),
        );

        let protected_payload = protected_payload_tbs.sign::<Sha3_256>(self.identity_secret_key)?;
        let mut frame_tbs = FrameTbs::new(
            self.group_info.id(),
            epoch,
            self.nonce.next(),
            Some(GroupOperation::AddMember(changes)),
            vec![],
        );

        // Encryption
        let encrypted_protected_payload = encrypt(
            &stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        // Proving
        let proof = Proof::ArtProof(prove(&Sha3_256::digest(frame_tbs.encode_to_vec()?))?);
        let frame = Frame::new(frame_tbs, proof);

        // Invite construction
        let protected_invite_data =
            ProtectedInviteData::new(epoch, stage_key, self.group_info.id());

        let encrypted_invite_data = encrypt(
            &derive_invite_key(leaf_secret)?,
            &protected_invite_data.encode_to_vec()?,
            &[],
        )?;

        let invite_tbs = InviteTbs::new(
            invitee,
            self.identity_public_key(),
            ephemeral_public_key,
            encrypted_invite_data,
        );

        let invite = invite_tbs.sign::<Sha3_256>(self.identity_secret_key)?;

        Ok((frame, invite))
    }

    pub fn remove_member(&mut self, user_id: &str, mut payloads: Vec<Payload>) -> Result<Frame> {
        let validator = self.validator.lock().unwrap();

        // Future epoch
        let epoch = validator.epoch() + 1;

        let vanishing_leaf_secret: ark_ff::Fp<ark_ff::MontBackend<cortado::FrConfig, 4>, 4> =
            ScalarField::rand(&mut thread_rng());

        let leaf = self
            .group_info
            .members()
            .get_leaf(user_id)
            .ok_or(Error::SenderNotInGroup)?;

        // Predict add member changes
        let (changes, stage_key, prove) = validator.remove_member(leaf, vanishing_leaf_secret)?;

        payloads.push(Payload::Action(GroupActionPayload::RemoveMember(
            self.group_info
                .members()
                .get(user_id)
                .ok_or(Error::SenderNotInGroup)?
                .to_owned(),
        )));

        // Frame construction
        let protected_payload_tbs = ProtectedPayloadTbs::new(
            self.seq_num,
            Utc::now(),
            payloads,
            Sender::UserId(public_key_to_id(self.identity_public_key())),
        );

        let protected_payload = protected_payload_tbs.sign::<Sha3_256>(self.identity_secret_key)?;
        let mut frame_tbs = FrameTbs::new(
            self.group_info.id(),
            epoch,
            self.nonce.next(),
            Some(GroupOperation::RemoveMember(changes)),
            vec![],
        );

        // Encryption
        let encrypted_protected_payload = encrypt(
            &stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        // Proving
        let proof = Proof::ArtProof(prove(&Sha3_256::digest(frame_tbs.encode_to_vec()?))?);
        let frame = Frame::new(frame_tbs, proof);

        Ok(frame)
    }

    pub fn create_frame(&mut self, payloads: Vec<Payload>) -> Result<Frame> {
        let mut validator = self.validator.lock().unwrap();

        let protected_payload_tbs = ProtectedPayloadTbs::new(
            self.seq_num,
            Utc::now(),
            payloads,
            Sender::UserId(public_key_to_id(self.identity_public_key())),
        );

        let protected_payload = protected_payload_tbs.sign::<Sha3_256>(self.identity_secret_key)?;

        // Predict add member changes
        let frame = if validator.is_participant() {
            let mut frame_tbs = FrameTbs::new(
                self.group_info.id(),
                validator.epoch(),
                self.nonce.next(),
                None,
                vec![],
            );

            let encrypted_protected_payload = validator.encrypt(
                &protected_payload.encode_to_vec(),
                &frame_tbs.associated_data::<Sha3_256>()?,
            )?;
            frame_tbs.set_protected_payload(encrypted_protected_payload);

            frame_tbs.prove_schnorr::<Sha3_256>(validator.upstream_art.get_root_key()?.key)?
        } else {
            let (changes, stage_key, prove) = validator.update_key()?;

            let mut frame_tbs = FrameTbs::new(
                self.group_info.id(),
                validator.epoch() + 1,
                self.nonce.next(),
                Some(GroupOperation::KeyUpdate(changes)),
                vec![],
            );

            let encrypted_protected_payload = encrypt(
                &stage_key,
                &protected_payload.encode_to_vec(),
                &frame_tbs.associated_data::<Sha3_256>()?,
            )?;
            frame_tbs.set_protected_payload(encrypted_protected_payload);

            let proof = Proof::ArtProof(prove(&Sha3_256::digest(frame_tbs.encode_to_vec()?))?);
            Frame::new(frame_tbs, proof)
        };

        Ok(frame)
    }

    pub fn join_group_as(&mut self, user: User) -> Result<Frame> {
        let mut validator = self.validator.lock().unwrap();

        // Future epoch
        let epoch = validator.epoch() + 1;

        let protected_payload_tbs = ProtectedPayloadTbs::new(
            self.seq_num,
            Utc::now(),
            vec![Payload::Action(GroupActionPayload::JoinGroup(user))],
            Sender::LeafId(public_key_to_id(
                (CortadoAffine::generator() * validator.upstream_art.secret_key).into_affine(),
            )),
        );

        let protected_payload =
            protected_payload_tbs.sign::<Sha3_256>(validator.upstream_art.secret_key)?;

        let (changes, stage_key, prove) = validator.update_key()?;

        let mut frame_tbs = FrameTbs::new(
            self.group_info.id(),
            epoch,
            self.nonce.next(),
            Some(GroupOperation::KeyUpdate(changes)),
            vec![],
        );

        let encrypted_protected_payload = encrypt(
            &stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        let proof = Proof::ArtProof(prove(&Sha3_256::digest(frame_tbs.encode_to_vec()?))?);
        Ok(Frame::new(frame_tbs, proof))
    }

    fn compute_leaf_secret_for_invitee(
        &self,
        invitee: Invitee,
        ephemeral_secret_key: ScalarField,
    ) -> Result<ScalarField> {
        match invitee {
            Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => crate::utils::compute_leaf_secret_a(
                self.identity_secret_key,
                ephemeral_secret_key,
                identity_public_key,
                spk_public_key.unwrap_or(identity_public_key),
            )
            .map_err(|_| Error::InvalidInput),
            Invitee::Unidentified(secret_key) => {
                let public_key = (CortadoAffine::generator() * secret_key).into_affine();
                crate::utils::compute_leaf_secret_a(
                    self.identity_secret_key,
                    ephemeral_secret_key,
                    public_key,
                    public_key,
                )
                .map_err(|_| Error::InvalidInput)
            }
        }
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn epoch(&self) -> u64 {
        self.validator.lock().unwrap().epoch()
    }

    pub fn identity_public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.identity_secret_key).into_affine()
    }

    pub fn sign_with_tk(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let tk = self.validator.lock().unwrap().upstream_art.get_root_key()?;
        let tk_public_key = (CortadoAffine::generator() * tk.key).into_affine();
        Ok(schnorr::sign(&vec![tk.key], &vec![tk_public_key], msg)?)
    }
}

fn group_owner_leaf_public_key<A: ARTPublicView<CortadoAffine>>(art: &A) -> CortadoAffine {
    LeafIter::new(art.get_root())
        .next()
        .expect("ART can't be empty")
        .get_public_key()
}

#[cfg(test)]
mod tests {
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    use uuid::Uuid;

    use crate::models::frame::Proof;

    use super::*;

    #[derive(Debug, Default)]
    struct Nonce(u64);

    impl Nonce {
        fn new(value: u64) -> Self {
            Self(value)
        }

        fn next(&mut self) -> Vec<u8> {
            let nonce = self.0.to_le_bytes().to_vec();
            self.0 += 1;
            nonce
        }
    }

    #[test]
    fn test_create_validator() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut nonce = Nonce::new(0);
        let group_id = Uuid::new_v4();

        let leaf_secret_0_0 = ScalarField::rand(&mut rng);

        let (base_art, tree_key) =
            PrivateART::new_art_from_secrets(&vec![leaf_secret_0_0], &CortadoAffine::generator())
                .expect("Failed to create art from secret");
        let base_stk = derive_stage_key(&StageKey::default(), tree_key.key)
            .expect("Failed to derive base stage key");

        let mut keyed_validator_0 = KeyedValidator::new(base_art, base_stk, 0);

        // Member 1
        let leaf_secret_1_0 = ScalarField::rand(&mut rng);

        let (changes, stage_key, prove) = keyed_validator_0
            .add_member(leaf_secret_1_0)
            .expect("Failed to predict add member");

        // Frame construction
        let frame_0_tbs = FrameTbs::new(
            group_id,
            1,
            nonce.next(),
            Some(GroupOperation::AddMember(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_0_aad = Sha3_256::digest(
            frame_0_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_0 = Frame::new(
            frame_0_tbs,
            Proof::ArtProof(prove(&frame_0_aad).expect("Failed to prove frame 0")),
        );

        // Frame validation
        let _ = keyed_validator_0
            .validate(&frame_0)
            .expect("Failed to validate frame 0");

        let upstream_art: PrivateART<CortadoAffine> = PrivateART::from_public_art_and_secret(
            keyed_validator_0.upstream_art.clone(),
            leaf_secret_1_0,
        )
        .expect("Failed to create base/upstream art for another member");
        let mut keyed_validator_1 = KeyedValidator::new(
            upstream_art,
            keyed_validator_0.upstream_stk,
            keyed_validator_0.epoch,
        );

        // Member 2
        let leaf_secret_2_0 = ScalarField::rand(&mut rng);

        let (changes, stage_key, prove) = keyed_validator_0
            .add_member(leaf_secret_2_0)
            .expect("Failed to predict add member");

        // Frame construction
        let frame_1_tbs = FrameTbs::new(
            group_id,
            2,
            nonce.next(),
            Some(GroupOperation::AddMember(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_1_aad = Sha3_256::digest(
            frame_1_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_1 = Frame::new(
            frame_1_tbs,
            Proof::ArtProof(prove(&frame_1_aad).expect("Failed to prove frame 0")),
        );

        // Frame validation
        let _ = keyed_validator_0
            .validate(&frame_1)
            .expect("Failed to validate frame 1 for validator 0");
        let _ = keyed_validator_1
            .validate(&frame_1)
            .expect("Failed to validate frame 1 for validator 1");

        assert_eq!(
            keyed_validator_0.epoch(),
            keyed_validator_1.epoch(),
            "Validator epoch mismatch"
        );
        assert_eq!(
            keyed_validator_0.base_stk, keyed_validator_1.base_stk,
            "Validator upstream base stk mismatch"
        );
        assert_eq!(
            keyed_validator_0.upstream_stk, keyed_validator_1.upstream_stk,
            "Validator upstream stk mismatch"
        );

        let (changes, stage_key, prove) = keyed_validator_0
            .update_key()
            .expect("Failed to predict update key");

        // Frame construction
        let frame_2_tbs = FrameTbs::new(
            group_id,
            3,
            nonce.next(),
            Some(GroupOperation::KeyUpdate(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_2_aad = Sha3_256::digest(
            frame_2_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_2 = Frame::new(
            frame_2_tbs,
            Proof::ArtProof(prove(&frame_2_aad).expect("Failed to prove frame 0")),
        );

        let _ = keyed_validator_0
            .validate(&frame_2)
            .expect("Failed to validate frame 1 for validator 0");
        let _ = keyed_validator_1
            .validate(&frame_2)
            .expect("Failed to validate frame 1 for validator 1");

        assert_eq!(
            keyed_validator_0.epoch(),
            keyed_validator_1.epoch(),
            "Validator epoch mismatch"
        );
        assert_eq!(
            keyed_validator_0.base_stk, keyed_validator_1.base_stk,
            "Validator upstream base stk mismatch"
        );
        assert_eq!(
            keyed_validator_0.upstream_stk, keyed_validator_1.upstream_stk,
            "Validator upstream stk mismatch"
        );
        assert!(
            keyed_validator_0.participant.is_some(),
            "Validator 0 should participate in epoch"
        );
        assert!(
            keyed_validator_1.participant.is_none(),
            "Validator 1 should not participate in epoch"
        );
        assert_eq!(
            keyed_validator_0.participation_leafs.len(),
            1,
            "Validator 0 should have participation leafs"
        );

        let (changes, stage_key, prove) = keyed_validator_0
            .update_key()
            .expect("Failed to predict update key");

        // Frame construction
        let frame_3_tbs = FrameTbs::new(
            group_id,
            4,
            nonce.next(),
            Some(GroupOperation::KeyUpdate(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_3_aad = Sha3_256::digest(
            frame_3_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_3 = Frame::new(
            frame_3_tbs,
            Proof::ArtProof(prove(&frame_3_aad).expect("Failed to prove frame 0")),
        );

        let (changes, stage_key, prove) = keyed_validator_1
            .update_key()
            .expect("Failed to predict update key");

        // Frame construction
        let frame_4_tbs = FrameTbs::new(
            group_id,
            4,
            nonce.next(),
            Some(GroupOperation::KeyUpdate(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_4_aad = Sha3_256::digest(
            frame_4_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_4 = Frame::new(
            frame_4_tbs,
            Proof::ArtProof(prove(&frame_4_aad).expect("Failed to prove frame 0")),
        );

        let _ = keyed_validator_0
            .validate(&frame_3)
            .expect("Failed to validate frame 3 for validator 0");
        let _ = keyed_validator_1
            .validate(&frame_3)
            .expect("Failed to validate frame 3 for validator 1");

        let _ = keyed_validator_0
            .validate(&frame_4)
            .expect("Failed to validate frame 4 for validator 0");
        let _ = keyed_validator_1
            .validate(&frame_4)
            .expect("Failed to validate frame 4 for validator 1");

        assert_eq!(
            keyed_validator_0.epoch(),
            keyed_validator_1.epoch(),
            "Validator epoch mismatch"
        );
        assert_eq!(
            keyed_validator_0.base_stk, keyed_validator_1.base_stk,
            "Validator upstream base stk mismatch"
        );
        assert_eq!(
            keyed_validator_0.upstream_stk, keyed_validator_1.upstream_stk,
            "Validator upstream stk mismatch"
        );
        assert!(
            keyed_validator_0.participant.is_some(),
            "Validator 0 should participate in epoch"
        );
        assert!(
            keyed_validator_1.participant.is_some(),
            "Validator 1 should participate in epoch"
        );
        assert_eq!(
            keyed_validator_0.participation_leafs.len(),
            2,
            "Validator 0 should have participation leafs"
        );
        assert_eq!(
            keyed_validator_1.participation_leafs.len(),
            1,
            "Validator 1 should have participation leafs"
        );

        let (changes, stage_key, prove) = keyed_validator_1
            .update_key()
            .expect("Failed to predict update key");

        // Frame construction
        let frame_5_tbs = FrameTbs::new(
            group_id,
            5,
            nonce.next(),
            Some(GroupOperation::KeyUpdate(changes)),
            encrypt(&stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
        );
        let frame_5_aad = Sha3_256::digest(
            frame_5_tbs
                .encode_to_vec()
                .expect("Failed to encode frame 0 tbs"),
        );
        let frame_5 = Frame::new(
            frame_5_tbs,
            Proof::ArtProof(prove(&frame_5_aad).expect("Failed to prove frame 0")),
        );

        let _ = keyed_validator_0
            .validate(&frame_5)
            .expect("Failed to validate frame 5 for validator 0");
        let _ = keyed_validator_1
            .validate(&frame_5)
            .expect("Failed to validate frame 5 for validator 1");

        assert_eq!(keyed_validator_0.epoch(), 5);
        assert_eq!(
            keyed_validator_0.epoch(),
            keyed_validator_1.epoch(),
            "Validator epoch mismatch"
        );
        assert_eq!(
            keyed_validator_0.base_stk, keyed_validator_1.base_stk,
            "Validator upstream base stk mismatch"
        );
        assert_eq!(
            keyed_validator_0.upstream_stk, keyed_validator_1.upstream_stk,
            "Validator upstream stk mismatch"
        );
        assert!(
            keyed_validator_0.participant.is_none(),
            "Validator 0 should not participate in epoch"
        );
        assert!(
            keyed_validator_1.participant.is_some(),
            "Validator 1 should participate in epoch"
        );
        assert_eq!(
            keyed_validator_0.participation_leafs.len(),
            2,
            "Validator 0 should have participation leafs"
        );
        assert_eq!(
            keyed_validator_1.participation_leafs.len(),
            2,
            "Validator 1 should have participation leafs"
        );
    }
}
