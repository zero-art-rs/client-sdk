use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use std::sync::Mutex;
use tracing::{instrument, trace};
use zrt_crypto::schnorr;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zrt_art::types::{PrivateART, PublicART};

use crate::{
    bounded_map::BoundedMap, core::{
        impls::concurrent::linear_keyed_validator::LinearKeyedValidator,
        traits::{KeyedValidator, Validator},
    }, errors::{Error, Result}, models::{
        frame::{Frame, FrameTbs, GroupOperation, Proof},
        group_info::{public_key_to_id, GroupInfo, Role, User},
        invite::{Invite, InviteTbs, Invitee, ProtectedInviteData},
        payload::{GroupActionPayload, Payload},
        protected_payload::{ProtectedPayload, ProtectedPayloadTbs, Sender},
    }, proof_system::get_proof_system, types, utils::{decrypt, derive_invite_key, derive_stage_key, encrypt, serialize}
};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(u64);

impl Nonce {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn advance(&mut self) -> Vec<u8> {
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
    validator: Mutex<LinearKeyedValidator>,
    group_info: GroupInfo,
    seq_num: u64,
    nonce: Nonce,
    is_last_sender: bool,
    sended_frames: BoundedMap<[u8; 32], ()>
}

impl GroupContext {
    pub fn new(
        identity_secret_key: ScalarField,
        mut user: User,
        mut group_info: GroupInfo,
    ) -> Result<(Self, Frame)> {
        let leaf_secret = ScalarField::rand(&mut thread_rng());
        let (base_art, tree_key) =
            PrivateART::new_art_from_secrets(&vec![leaf_secret], &CortadoAffine::generator())?;
        let base_stk = derive_stage_key(&[0u8; 32], tree_key.key)?;

        *user.role_mut() = Role::Ownership;

        group_info
            .members_mut()
            .insert((CortadoAffine::generator() * leaf_secret).into(), user);

        let mut frame_tbs = FrameTbs::new(
            group_info.id(),
            0,
            serialize((CortadoAffine::generator() * identity_secret_key).into_affine())?,
            Some(GroupOperation::Init(base_art.clone().into())),
            vec![],
        );
        let protected_payload = encrypt(
            &base_stk,
            &ProtectedPayload::default().encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(protected_payload);

        let frame = frame_tbs.prove_schnorr::<Sha3_256>(identity_secret_key)?;

        Ok((
            Self {
                identity_secret_key,
                validator: Mutex::new(LinearKeyedValidator::new(base_art, base_stk, 0)),
                group_info,
                seq_num: 0,
                nonce: Nonce(0),
                is_last_sender: false,
                sended_frames: BoundedMap::with_capacity(8)
            },
            frame,
        ))
    }

    pub fn into_parts(self) -> (ScalarField, LinearKeyedValidator, GroupInfo, u64, Nonce) {
        (
            self.identity_secret_key,
            self.validator.into_inner().unwrap(),
            self.group_info,
            self.seq_num,
            self.nonce,
        )
    }

    pub fn to_parts(&self) -> (ScalarField, LinearKeyedValidator, GroupInfo, u64, Nonce) {
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
        validator: LinearKeyedValidator,
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
            is_last_sender: false,
            sended_frames: BoundedMap::with_capacity(8)
        }
    }

    #[instrument(skip_all)]
    pub fn process_frame(&mut self, frame: Frame) -> Result<Vec<Payload>> {
        let mut validator = self.validator.lock().unwrap();
        let (operation, stage_key) = validator.validate_and_derive_key(&frame)?;

        self.is_last_sender =  self.sended_frames.contains_key(&Sha3_256::digest(frame.encode_to_vec()?).into());

        let protected_payload = ProtectedPayload::decode(&decrypt(
            &stage_key,
            frame.frame_tbs().protected_payload(),
            &frame.frame_tbs().associated_data::<Sha3_256>()?,
        )?)?;

        let Some(operation) = operation else {
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
            
            if self.identity_public_key() == sender_public_key {
                return Ok(vec![])
            }

            return Ok(protected_payload
                .protected_payload_tbs()
                .payloads()
                .to_vec());
        };

        let sender_public_key = match operation {
            types::GroupOperation::AddMember { member_public_key } => {
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

                trace!("Sender public key: {:?}", sender_public_key);
                trace!("Signature: {:?}", protected_payload.signature());
                trace!("Payload: {:?}", protected_payload);
                protected_payload.verify::<Sha3_256>(sender_public_key)?;
                trace!("Verified");

                let member = User::new_with_id(
                    public_key_to_id(member_public_key),
                    String::from("Invited"),
                    CortadoAffine::identity(),
                    serialize(member_public_key)?,
                );
                self.group_info
                    .members_mut()
                    .insert(member_public_key, member);

                sender_public_key
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

                sender_public_key
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

                sender_public_key
            }
            _ => CortadoAffine::identity()
        };

        if self.identity_public_key() == sender_public_key {
            return Ok(vec![])
        }


        Ok(protected_payload
            .protected_payload_tbs()
            .payloads()
            .to_vec())
    }

    #[instrument(skip_all)]
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
        let proposal = validator.propose_add_member(leaf_secret)?;

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
            self.nonce.advance(),
            Some(GroupOperation::AddMember(proposal.changes)),
            vec![],
        );

        protected_payload
            .verify::<Sha3_256>(self.identity_public_key())
            .unwrap();
        trace!("Valid with: {:?}", self.identity_public_key());
        trace!("Signature: {:?}", protected_payload.signature());
        trace!("Payload: {:?}", protected_payload);

        // Encryption
        let encrypted_protected_payload = encrypt(
            &proposal.stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        // Proving
        let proof = Proof::ArtProof(get_proof_system().prove(
            proposal.prover_artefacts,
            &[proposal.aux_secret_key],
            &Sha3_256::digest(frame_tbs.encode_to_vec()?),
        )?);
        let frame = Frame::new(frame_tbs, proof);

        // Invite construction
        let protected_invite_data =
            ProtectedInviteData::new(epoch, proposal.stage_key, self.group_info.id());

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

        self.sended_frames.insert(Sha3_256::digest(frame.encode_to_vec()?).into(), ());

        Ok((frame, invite))
    }

    #[instrument(skip_all)]
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
        let proposal = validator.propose_remove_member(*leaf, vanishing_leaf_secret)?;

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
            self.nonce.advance(),
            Some(GroupOperation::RemoveMember(proposal.changes)),
            vec![],
        );

        // Encryption
        let encrypted_protected_payload = encrypt(
            &proposal.stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        // Proving
        let proof = Proof::ArtProof(get_proof_system().prove(
            proposal.prover_artefacts,
            &[proposal.aux_secret_key],
            &Sha3_256::digest(frame_tbs.encode_to_vec()?),
        )?);
        let frame = Frame::new(frame_tbs, proof);

        self.sended_frames.insert(Sha3_256::digest(frame.encode_to_vec()?).into(), ());

        Ok(frame)
    }

    #[instrument(skip_all)]
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
        let frame = if self.is_last_sender {
            let mut frame_tbs = FrameTbs::new(
                self.group_info.id(),
                validator.epoch(),
                self.nonce.advance(),
                None,
                vec![],
            );

            let stage_key = validator.stage_key();

            let encrypted_protected_payload = encrypt(
                &stage_key,
                &protected_payload.encode_to_vec(),
                &frame_tbs.associated_data::<Sha3_256>()?,
            )?;
            frame_tbs.set_protected_payload(encrypted_protected_payload);

            frame_tbs.prove_schnorr::<Sha3_256>(validator.tree_key())?
        } else {
            let proposal = validator.propose_update_key()?;

            let mut frame_tbs = FrameTbs::new(
                self.group_info.id(),
                validator.epoch() + 1,
                self.nonce.advance(),
                Some(GroupOperation::KeyUpdate(proposal.changes)),
                vec![],
            );

            let encrypted_protected_payload = encrypt(
                &proposal.stage_key,
                &protected_payload.encode_to_vec(),
                &frame_tbs.associated_data::<Sha3_256>()?,
            )?;
            frame_tbs.set_protected_payload(encrypted_protected_payload);

            let proof = Proof::ArtProof(get_proof_system().prove(
                proposal.prover_artefacts,
                &[proposal.aux_secret_key],
                &Sha3_256::digest(frame_tbs.encode_to_vec()?),
            )?);
            Frame::new(frame_tbs, proof)
        };

        self.sended_frames.insert(Sha3_256::digest(frame.encode_to_vec()?).into(), ());

        Ok(frame)
    }

    #[instrument(skip_all)]
    pub fn join_group_as(&mut self, user: User) -> Result<Frame> {
        let mut validator = self.validator.lock().unwrap();

        // Future epoch
        let epoch = validator.epoch() + 1;

        let protected_payload_tbs = ProtectedPayloadTbs::new(
            self.seq_num,
            Utc::now(),
            vec![Payload::Action(GroupActionPayload::JoinGroup(user))],
            Sender::LeafId(public_key_to_id(validator.leaf_public_key())),
        );

        let protected_payload = protected_payload_tbs.sign::<Sha3_256>(validator.leaf_key())?;

        let proposal = validator.propose_update_key()?;

        let mut frame_tbs = FrameTbs::new(
            self.group_info.id(),
            epoch,
            self.nonce.advance(),
            Some(GroupOperation::KeyUpdate(proposal.changes)),
            vec![],
        );

        let encrypted_protected_payload = encrypt(
            &proposal.stage_key,
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(encrypted_protected_payload);

        let proof = Proof::ArtProof(get_proof_system().prove(
            proposal.prover_artefacts,
            &[proposal.aux_secret_key],
            &Sha3_256::digest(frame_tbs.encode_to_vec()?),
        )?);

        let frame = Frame::new(frame_tbs, proof);

        self.sended_frames.insert(Sha3_256::digest(frame.encode_to_vec()?).into(), ());

        Ok(frame)
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
        let validator = self.validator.lock().unwrap();
        Ok(schnorr::sign(
            &vec![validator.tree_key()],
            &vec![validator.tree_public_key()],
            msg,
        )?)
    }

    pub fn tree(&self) -> PublicART<CortadoAffine> {
        self.validator.lock().unwrap().tree().clone()
    }
}
