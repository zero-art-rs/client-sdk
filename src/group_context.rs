use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::traits::ARTPublicView;
use art::types::{LeafIter, ProverArtefacts, PublicART};
use art::{
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::{BranchChanges, PrivateART},
};
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::schnorr;

use sha3::Sha3_256;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::models::frame::{Frame, GroupOperation};
use crate::models::group_info::{GroupInfo, GroupMembers, User};
use crate::models::invite::Invite;
use crate::models::payload::{GroupActionPayload, Payload};
use crate::proof_system::ProofSystem;
use crate::utils::derive_stage_key;
use crate::{models, proof_system};
use ark_std::rand::thread_rng;

pub mod operations;
#[cfg(test)]
mod tests;

pub struct KeyPair {
    secret_key: ScalarField,
    public_key: CortadoAffine,
}

impl KeyPair {
    pub fn from_secret_key(secret_key: ScalarField) -> Self {
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();

        Self {
            public_key,
            secret_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupState {
    art: PrivateART<CortadoAffine>,
    stk: [u8; 32],
    epoch: u64,
    group_info: GroupInfo,
    is_last_sender: bool,
}

impl GroupState {
    pub fn into_parts(
        self,
    ) -> (
        ScalarField,
        PublicART<CortadoAffine>,
        [u8; 32],
        u64,
        models::group_info::GroupInfo,
    ) {
        (
            self.art.secret_key,
            PublicART {
                root: self.art.root.clone(),
                generator: CortadoAffine::generator(),
            },
            self.stk,
            self.epoch,
            self.group_info,
        )
    }

    pub fn to_parts(
        &self,
    ) -> (
        ScalarField,
        PublicART<CortadoAffine>,
        [u8; 32],
        u64,
        models::group_info::GroupInfo,
        bool,
    ) {
        (
            self.art.secret_key,
            PublicART {
                root: self.art.root.clone(),
                generator: CortadoAffine::generator(),
            },
            self.stk,
            self.epoch,
            self.group_info.clone(),
            self.is_last_sender,
        )
    }

    pub fn from_parts(
        leaf_secret: ScalarField,
        art: PublicART<CortadoAffine>,
        stk: [u8; 32],
        epoch: u64,
        group_info: models::group_info::GroupInfo,
        is_last_sender: bool,
    ) -> Result<Self> {
        Ok(Self {
            art: PrivateART::from_public_art(art, leaf_secret)?,
            stk,
            epoch,
            group_info,
            is_last_sender,
        })
    }

    fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        crate::utils::encrypt(&self.stk, plaintext, associated_data)
    }

    fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        crate::utils::decrypt(&self.stk, ciphertext, associated_data)
    }

    fn update_art(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<()> {
        self.art.update_private_art(changes)?;
        self.advance_epoch()?;
        Ok(())
    }

    fn append_leaf(
        &mut self,
        leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.append_or_replace_node(leaf_secret)?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    fn update_key(
        &mut self,
        leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.update_key(leaf_secret)?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    fn make_blank(
        &mut self,
        leaf_public_key: &CortadoAffine,
        temporary_leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.make_blank(
            &self.art.get_path_to_leaf(leaf_public_key)?,
            temporary_leaf_secret,
        )?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    fn advance_epoch(&mut self) -> Result<()> {
        let tk = self.art.get_root_key()?;
        // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
        let stk = crate::utils::derive_stage_key(&self.stk, tk.key)?;
        self.stk = stk;

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }
}

pub struct GroupContext {
    state: GroupState,
    pending_state: GroupState,

    proof_system: ProofSystem,
    rng: StdRng,
    identity_key_pair: KeyPair,
}

impl GroupContext {
    pub fn new(identity_secret_key: ScalarField, group_info: GroupInfo) -> Result<(Self, Frame)> {
        let mut context_rng = StdRng::from_rng(thread_rng()).unwrap();

        let leaf_secret = ScalarField::rand(&mut context_rng);
        let (art, tk) =
            PrivateART::new_art_from_secrets(&vec![leaf_secret], &CortadoAffine::generator())?;

        let state = GroupState {
            art,
            stk: derive_stage_key(&[0u8; 32], tk.key)?,
            epoch: 0,
            group_info,
            is_last_sender: true,
        };

        let group_context = Self {
            pending_state: state.clone(),
            state,
            proof_system: ProofSystem::default(),
            rng: context_rng,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
        };

        let frame = group_context
            .create_frame_tbs(
                &group_context.state,
                vec![],
                Some(GroupOperation::Init(PublicART {
                    root: group_context.state.art.root.clone(),
                    generator: CortadoAffine::generator(),
                })),
            )?
            .prove_schnorr::<Sha3_256>(identity_secret_key)?;

        Ok((group_context, frame))
    }

    pub fn new_with_rng(
        _identity_secret_key: ScalarField,
        _group_info: GroupInfo,
        _context_rng: StdRng,
        _proof_system_rng: StdRng,
    ) -> Result<(Self, Frame)> {
        unimplemented!()
    }

    pub fn set_rng(&mut self, rng: StdRng) {
        self.rng = rng;
    }

    pub fn set_proof_system(&mut self, proof_system: ProofSystem) {
        self.proof_system = proof_system;
    }

    pub fn sign_with_tk(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let tk = self.state.art.get_root_key()?;
        let tk_public_key = (CortadoAffine::generator() * tk.key).into_affine();
        Ok(schnorr::sign(&vec![tk.key], &vec![tk_public_key], msg)?)
    }

    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    pub fn pending_epoch(&self) -> u64 {
        self.pending_state.epoch
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.state.group_info
    }

    pub fn pending_group_info(&self) -> &GroupInfo {
        &self.pending_state.group_info
    }

    // Parts
    pub fn into_state(self) -> GroupState {
        self.state
    }

    pub fn to_state(&self) -> GroupState {
        self.state.clone()
    }

    pub fn from_state(identity_secret_key: ScalarField, state: GroupState) -> Result<Self> {
        let context_rng = StdRng::from_rng(thread_rng()).unwrap();
        let proof_system = proof_system::ProofSystem::default();

        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        Ok(GroupContext {
            pending_state: state.clone(),
            state,
            identity_key_pair,
            proof_system,
            rng: context_rng,
        })
    }

    pub fn process_frame(
        &mut self,
        frame: models::frame::Frame,
    ) -> Result<Vec<models::payload::Payload>> {
        // Validate that frame belong to this group
        let group_id = frame.frame_tbs().group_id();
        if group_id != self.group_info().id() {
            return Err(Error::InvalidGroup);
        }

        let epoch = frame.frame_tbs().epoch();
        if frame.frame_tbs().group_operation().is_none() {
            if self.group_info().members().len() == 0 {
                return Err(Error::InvalidInput);
            }

            if self.epoch() != epoch {
                return Err(Error::InvalidEpoch);
            }

            let tk = self.state.art.get_root_key()?;
            let tree_public_key = (tk.generator * tk.key).into_affine();

            frame.verify_schnorr::<Sha3_256>(tree_public_key)?;

            let protected_payload =
                models::protected_payload::ProtectedPayload::decode(&crate::utils::decrypt(
                    &self.state.stk,
                    frame.frame_tbs().protected_payload(),
                    &frame.frame_tbs().associated_data::<Sha3_256>()?,
                )?)?;

            let sender = match protected_payload.protected_payload_tbs().sender() {
                models::protected_payload::Sender::UserId(id) => self
                    .state
                    .group_info
                    .members()
                    .get(id)
                    .ok_or(Error::InvalidSender)?,
                _ => unimplemented!(),
            };

            protected_payload.verify::<Sha3_256>(sender.public_key())?;

            if sender.public_key() == self.identity_key_pair.public_key {
                println!("Own frame");
                return Ok(vec![]);
            }

            return Ok(protected_payload
                .protected_payload_tbs()
                .payloads()
                .to_vec());
        }

        match frame.frame_tbs().group_operation().unwrap() {
            models::frame::GroupOperation::Init(_) => {
                return Ok(vec![]);
            }
            models::frame::GroupOperation::AddMember(changes) => {
                if self.state.group_info.members().len() == 0 {
                    let protected_payload = models::protected_payload::ProtectedPayload::decode(
                        &crate::utils::decrypt(
                            &self.state.stk,
                            frame.frame_tbs().protected_payload(),
                            &frame.frame_tbs().associated_data::<Sha3_256>()?,
                        )?,
                    )?;

                    let group_infos = protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .iter()
                        .filter_map(|payload| match payload {
                            Payload::Action(GroupActionPayload::InviteMember(group_info)) => {
                                Some(group_info.clone())
                            }
                            _ => None,
                        })
                        .collect::<Vec<GroupInfo>>();

                    if group_infos.is_empty() {
                        return Err(Error::InvalidInput);
                    }

                    self.state.group_info = group_infos[0].clone();
                    return Ok(protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .to_vec());
                }

                if self.state.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.state.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self
                    .state
                    .art
                    .compute_artefacts_for_verification(&changes)?;
                let owner_leaf_public_key = self.group_owner_leaf_public_key()?;

                frame.verify_art::<Sha3_256>(
                    &self.proof_system,
                    verifier_artefacts,
                    owner_leaf_public_key,
                )?;

                self.state.update_art(&changes)?;
                self.state.advance_epoch()?;

                // TODO: Implement rollback mechanism, because after tree update there can be unrecoverable errors
                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => self
                        .group_info()
                        .members()
                        .get(id)
                        .ok_or(Error::InvalidInput)?,
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            models::frame::GroupOperation::KeyUpdate(changes) => {
                if self.state.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.state.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self
                    .state
                    .art
                    .compute_artefacts_for_verification(&changes)?;

                let old_leaf_public_key = self.state.art.get_node(&changes.node_index)?.public_key;
                frame.verify_art::<Sha3_256>(
                    &self.proof_system,
                    verifier_artefacts,
                    old_leaf_public_key,
                )?;

                self.state.update_art(&changes)?;
                self.state.advance_epoch()?;

                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let new_users: Vec<models::group_info::User> = protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .iter()
                    .filter_map(|payload| match payload {
                        models::payload::Payload::Action(
                            models::payload::GroupActionPayload::JoinGroup(user),
                        ) => Some(user.clone()),
                        _ => None,
                    })
                    .collect();

                let mut group_info = self.group_info().clone();
                for user in new_users {
                    group_info.members_mut().insert_user(user);
                }

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => {
                        group_info.members().get(&id).ok_or(Error::InvalidInput)?
                    }
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;

                self.state.group_info = group_info;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            _ => unimplemented!(),
        }
    }

    // create_frame should:
    // 1. Parse provided payloads
    // (?: here can be problem that linked to situation
    // when somebody will use this library with custom
    // payloads and will returned error because only
    // repo proto payloads can be parsed)
    // 2. Build and sign (with identity key) general payload
    // 3. Build FrameTBS and encrypt general payload with FrameTBS as associated data
    // 4. Build and sign (with tree key) frame
    // Return Frame
    // TODO: KeyUpdate when last frame not from us
    pub fn create_frame(
        &mut self,
        payloads: Vec<models::payload::Payload>,
    ) -> Result<models::frame::Frame> {
        if !self.state.is_last_sender {
            let leaf_secret = ScalarField::rand(&mut self.rng);
            return self.key_update(leaf_secret, payloads);
        }

        let tk = self.state.art.get_root_key()?;
        let frame = self
            .create_frame_tbs(&self.state, payloads, None)?
            .prove_schnorr::<Sha3_256>(tk.key)?;
        Ok(frame)
    }

    pub fn commit_state(&mut self) {
        self.state = self.pending_state.clone()
    }

    fn group_owner_leaf_public_key(&self) -> Result<CortadoAffine> {
        Ok(LeafIter::new(self.state.art.get_root())
            .next()
            .ok_or(Error::InvalidInput)?
            .get_public_key())
    }

    fn create_invite(
        &self,
        state: &GroupState,
        invitee: models::invite::Invitee,
        leaf_secret: ScalarField,
        ephemeral_secret_key: ScalarField,
    ) -> Result<models::invite::Invite> {
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        let protected_invite_data =
            models::invite::ProtectedInviteData::new(state.epoch, state.stk, state.group_info.id());

        let invite_encryption_key = crate::utils::hkdf(
            Some(b"invite-key-derivation"),
            &crate::utils::serialize(leaf_secret)?,
        )?;

        let encrypted_invite_data = crate::utils::encrypt(
            &invite_encryption_key,
            &protected_invite_data.encode_to_vec()?,
            &[],
        )?;

        let invite_tbs = models::invite::InviteTbs::new(
            invitee,
            self.identity_key_pair.public_key,
            ephemeral_public_key,
            encrypted_invite_data,
        );

        let invite = invite_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        Ok(invite)
    }

    fn compute_leaf_secret_for_invitee(
        &self,
        invitee: models::invite::Invitee,
        ephemeral_secret_key: ScalarField,
    ) -> Result<ScalarField> {
        match invitee {
            models::invite::Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => crate::utils::compute_leaf_secret_a(
                self.identity_key_pair.secret_key,
                ephemeral_secret_key,
                identity_public_key,
                spk_public_key.unwrap_or(identity_public_key),
            )
            .map_err(|_| Error::InvalidInput),
            models::invite::Invitee::Unidentified(secret_key) => {
                let public_key = (CortadoAffine::generator() * secret_key).into_affine();
                crate::utils::compute_leaf_secret_a(
                    self.identity_key_pair.secret_key,
                    ephemeral_secret_key,
                    public_key,
                    public_key,
                )
                .map_err(|_| Error::InvalidInput)
            }
        }
    }

    fn create_frame_tbs(
        &self,
        state: &GroupState,
        payloads: Vec<models::payload::Payload>,
        group_operation: Option<models::frame::GroupOperation>,
    ) -> Result<models::frame::FrameTbs> {
        let protected_payload_tbs = models::protected_payload::ProtectedPayloadTbs::new(
            0,
            Utc::now(),
            payloads,
            models::protected_payload::Sender::UserId(
                state
                    .group_info
                    .members()
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(Error::InvalidInput)?
                    .id()
                    .to_string(),
            ),
        );
        let protected_payload =
            protected_payload_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        let mut frame_tbs = models::frame::FrameTbs::new(
            state.group_info.id(),
            state.epoch,
            vec![],
            group_operation,
            vec![],
        );
        let protected_payload = state.encrypt(
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(protected_payload);

        Ok(frame_tbs)
    }

    fn map_leafs_to_users(&self) -> HashMap<CortadoAffine, String> {
        LeafIter::new(self.state.art.get_root())
            .filter(|node| !node.is_blank)
            .enumerate()
            .map(|(i, node)| {
                let member = self
                    .group_info()
                    .members()
                    .get_by_index(i)
                    .expect("Inconsistent group info");
                (node.public_key, member.0.to_string())
            })
            .collect::<HashMap<CortadoAffine, String>>()
    }

    fn map_uids_to_indexes_by_leafs(
        &self,
        values: HashMap<CortadoAffine, String>,
    ) -> HashMap<String, usize> {
        LeafIter::new(self.state.art.get_root())
            .filter(|node| !node.is_blank)
            .enumerate()
            .map(|(i, node)| (values.get(&node.public_key).expect("").to_string(), i))
            .collect::<HashMap<String, usize>>()
    }
}

fn compute_invite_leaf_secret(
    invitee: models::invite::Invitee,
    identity_secret_key: ScalarField,
    spk_secret_key: Option<ScalarField>,
    inviter_public_key: CortadoAffine,
    ephemeral_public_key: CortadoAffine,
) -> Result<ScalarField> {
    let owned_identity_public_key =
        (CortadoAffine::generator() * identity_secret_key).into_affine();
    let owned_spk_public_key =
        spk_secret_key.map(|sk| (CortadoAffine::generator() * sk).into_affine());

    match invitee {
        models::invite::Invitee::Identified {
            identity_public_key,
            spk_public_key,
        } => {
            if identity_public_key != owned_identity_public_key {
                return Err(Error::InvalidInput);
            }
            if spk_public_key != owned_spk_public_key {
                return Err(Error::InvalidInput);
            }

            crate::utils::compute_leaf_secret_b(
                identity_secret_key,
                spk_secret_key.unwrap_or(identity_secret_key),
                inviter_public_key,
                ephemeral_public_key,
            )
        }
        models::invite::Invitee::Unidentified(secret_key) => crate::utils::compute_leaf_secret_b(
            secret_key,
            secret_key,
            inviter_public_key,
            ephemeral_public_key,
        ),
    }
}

pub struct PendingGroupContext(GroupContext);

impl PendingGroupContext {
    pub fn process_frame(&mut self, frame: Frame) -> Result<Vec<Payload>> {
        self.0.process_frame(frame)
    }

    pub fn join_group_as(&mut self, user: User) -> Result<Frame> {
        let leaf_secret = ScalarField::rand(&mut thread_rng());

        let group_action_payload =
            models::payload::Payload::Action(models::payload::GroupActionPayload::JoinGroup(user));

        let frame = self.0.key_update(leaf_secret, vec![group_action_payload])?;

        Ok(frame)
    }

    pub fn upgrade(mut self) -> GroupContext {
        self.0.commit_state();
        self.0
    }
}

pub struct InviteContext {
    identity_key_pair: KeyPair,
    leaf_secret: ScalarField,
    stk: [u8; 32],
    epoch: u64,
    group_id: Uuid,
}

impl InviteContext {
    pub fn new(
        identity_secret_key: ScalarField,
        spk_secret_key: Option<ScalarField>,
        invite: Invite,
    ) -> Result<Self> {
        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        invite.verify::<Sha3_256>(invite.invite_tbs().inviter_public_key())?;

        let inviter_public_key = invite.invite_tbs().inviter_public_key();
        let ephemeral_public_key = invite.invite_tbs().ephemeral_public_key();

        let leaf_secret = compute_invite_leaf_secret(
            invite.invite_tbs().invitee(),
            identity_secret_key,
            spk_secret_key,
            inviter_public_key,
            ephemeral_public_key,
        )?;

        let invite_encryption_key = crate::utils::hkdf(
            Some(b"invite-key-derivation"),
            &crate::utils::serialize(leaf_secret)?,
        )?;

        let protected_invite_data =
            models::invite::ProtectedInviteData::decode(&crate::utils::decrypt(
                &invite_encryption_key,
                invite.invite_tbs().protected_invite_data(),
                &[],
            )?)?;

        Ok(Self {
            identity_key_pair,
            leaf_secret,
            stk: protected_invite_data.stage_key(),
            epoch: protected_invite_data.epoch(),
            group_id: protected_invite_data.group_id(),
        })
    }

    pub fn sign_as_identity(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            msg,
        )?)
    }

    pub fn sign_as_leaf(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let public_key = (CortadoAffine::generator() * self.leaf_secret).into_affine();
        Ok(schnorr::sign(
            &vec![self.leaf_secret],
            &vec![public_key],
            msg,
        )?)
    }

    pub fn upgrade(self, art: PublicART<CortadoAffine>) -> Result<PendingGroupContext> {
        let state = GroupState {
            art: PrivateART::from_public_art(art, self.leaf_secret)?,
            stk: self.stk,
            epoch: self.epoch,
            group_info: GroupInfo::new(
                self.group_id,
                String::new(),
                Utc::now(),
                vec![],
                GroupMembers::default(),
            ),
            is_last_sender: false,
        };

        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        Ok(PendingGroupContext(GroupContext {
            pending_state: state.clone(),
            state,
            proof_system: proof_system::ProofSystem::default(),
            rng: context_rng,
            identity_key_pair: self.identity_key_pair,
        }))
    }
}
