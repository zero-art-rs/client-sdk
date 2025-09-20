use std::{collections::HashMap, marker::PhantomData, vec};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, inv};
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use ark_std::{UniformRand, rand::Rng};
use art::traits::ARTPublicView;
use art::types::{LeafIter, NodeIter, PublicART};
use art::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, PrivateART, ProverArtefacts},
};
use bulletproofs::r1cs::R1CSError;
use chrono::{DateTime, Utc};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::{CryptoError, schnorr, x3dh::x3dh_a, x3dh::x3dh_b};

use curve25519_dalek::Scalar;
use hkdf::Hkdf;
use prost::{DecodeError, Message};
use prost_types::Timestamp;
use rand::seq::IndexedRandom;
use sha3::{Digest, Sha3_256};
use static_assertions::assert_impl_all;
use zk::art::{ARTProof, art_prove};

use crate::error::{Error, Result};
use crate::group_context::utils::{decrypt, derive_stage_key, encrypt};
use crate::models::group_info::GroupInfo;
use crate::{
    builders,
    proof_system::ProofSystem,
    zero_art_proto::{
        self, GroupOperation, Invite, group_operation::Operation, protected_payload_tbs,
    },
};
use crate::{invite, models, proof_system};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, SerializationError, serialize_to_vec,
};
use ark_std::rand::thread_rng;

use aes_gcm::{
    AeadCore, KeySizeUser,
    aead::{Aead, KeyInit, Nonce, OsRng, Payload},
};
use aes_gcm::{Aes256Gcm, Key};
// use rand::rngs::OsRng;
// use rand::RngCore;
use thiserror::Error;

pub mod builder;
pub mod utils;

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

pub struct GroupContext {
    art: PrivateART<CortadoAffine>,
    // ?: i realy don't know why Box
    stk: Box<[u8; 32]>,
    epoch: u64,
    proof_system: ProofSystem,

    seq_num: u64,

    rng: StdRng,

    identity_key_pair: KeyPair,

    group_info: models::group_info::GroupInfo,
}

impl GroupContext {
    pub fn sign_with_tk(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let tk = self.art.get_root_key()?;
        let tk_public_key = (CortadoAffine::generator() * tk.key).into_affine();
        Ok(schnorr::sign(&vec![tk.key], &vec![tk_public_key], msg)?)
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn get_group_info(&self) -> &GroupInfo {
        &self.group_info
    }

    pub fn into_parts(self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u64, Vec<u8>)> {
        let group_info: zero_art_proto::GroupInfo = self.group_info.into();

        let mut leaf_secret = Vec::new();
        self.art
            .secret_key
            .serialize_uncompressed(&mut leaf_secret)?;
        let art = self.art.serialize()?;
        let stk = self.stk.to_vec();
        Ok((
            leaf_secret,
            art,
            stk,
            self.epoch,
            group_info.encode_to_vec(),
        ))
    }

    pub fn from_parts(
        identity_secret_key: ScalarField,
        leaf_secret: ScalarField,
        art: &[u8],
        stk: [u8; 32],
        epoch: u64,
        seq_num: u64,
        group_info: models::group_info::GroupInfo,
    ) -> Result<Self> {
        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(art, &leaf_secret)?;

        // 1. Init PRNGs
        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        let proof_system = proof_system::ProofSystem::default();

        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        Ok(GroupContext {
            art,
            stk: Box::new(stk),
            identity_key_pair,
            seq_num,
            epoch,
            group_info,
            proof_system,
            rng: context_rng,
        })
    }

    pub fn from_invite(
        identity_secret_key: ScalarField,
        spk_secret_key: Option<ScalarField>,
        art: Vec<u8>,
        invite: models::invite::Invite,
        mut user: models::group_info::User,
    ) -> Result<(Self, models::frame::Frame)> {
        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        invite.verify::<Sha3_256>(invite.invite_tbs().inviter_public_key())?;

        let inviter_public_key = invite.invite_tbs().inviter_public_key();
        let ephemeral_public_key = invite.invite_tbs().ephemeral_public_key();

        let invite_leaf_secret = match invite.invite_tbs().invitee() {
            models::invite::Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => {
                let owned_identity_public_key =
                    (CortadoAffine::generator() * identity_secret_key).into_affine();
                if identity_public_key != owned_identity_public_key {
                    return Err(Error::InvalidInput);
                }

                let owned_spk_public_key = if let Some(spk_secret_key) = spk_secret_key {
                    Some((CortadoAffine::generator() * spk_secret_key).into_affine())
                } else {
                    None
                };
                if spk_public_key != owned_spk_public_key {
                    return Err(Error::InvalidInput);
                }

                crate::utils::compute_leaf_secret_b(
                    identity_secret_key,
                    spk_secret_key.unwrap_or(identity_secret_key),
                    inviter_public_key,
                    ephemeral_public_key,
                )?
            }
            models::invite::Invitee::Unidentified(secret_key) => {
                crate::utils::compute_leaf_secret_b(
                    secret_key,
                    secret_key,
                    inviter_public_key,
                    ephemeral_public_key,
                )?
            }
        };

        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(&art, &invite_leaf_secret)?;

        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        *user.public_key_mut() = identity_key_pair.public_key;

        let mut invite_leaf_secret_stk = [0u8; 32];
        invite_leaf_secret.serialize_uncompressed(&mut invite_leaf_secret_stk[..])?;

        let protected_invite_data =
            models::invite::ProtectedInviteData::decode(&crate::utils::decrypt(
                &invite_leaf_secret_stk,
                invite.invite_tbs().protected_invite_data(),
                &[],
            )?)?;
        let mut group_info = protected_invite_data.group_info().clone();

        group_info.members_mut().add_user(user.clone());

        let mut group_context = Self {
            art,
            stk: Box::new(protected_invite_data.stage_key()),
            epoch: protected_invite_data.epoch(),
            seq_num: 0,
            proof_system: proof_system::ProofSystem::default(),
            rng: context_rng,
            group_info: group_info,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
        };

        let leaf_secret = ScalarField::rand(&mut group_context.rng);

        let group_action_payload =
            models::payload::Payload::Action(models::payload::GroupActionPayload::JoinGroup(user));

        let frame = group_context.update_key(leaf_secret, vec![group_action_payload])?;

        Ok((group_context, frame))
    }

    pub fn process_frame(
        &mut self,
        sp_frame: zero_art_proto::SpFrame,
    ) -> Result<Vec<models::payload::Payload>> {
        let frame = sp_frame.frame.ok_or(Error::InvalidInput)?;
        let frame = models::frame::Frame::try_from(frame)?;
        // Validate that frame belong to this group
        let group_id = frame.frame_tbs().group_id();
        if group_id != self.group_info.id() {
            return Err(Error::InvalidInput);
        }

        let epoch = frame.frame_tbs().epoch();
        if frame.frame_tbs().group_operation().is_none() {
            if self.epoch != epoch {
                return Err(Error::InvalidEpoch);
            }

            let tk = self.art.get_root_key()?;
            let tree_public_key = (tk.generator * tk.key).into_affine();

            frame.verify_schnorr::<Sha3_256>(tree_public_key)?;

            let protected_payload =
                models::protected_payload::ProtectedPayload::decode(&self.decrypt(
                    frame.frame_tbs().protected_payload(),
                    &frame.frame_tbs().associated_data::<Sha3_256>()?,
                )?)?;

            let sender = match protected_payload.protected_payload_tbs().sender() {
                models::protected_payload::Sender::UserId(id) => self
                    .group_info
                    .members()
                    .get_by_id(id)
                    .ok_or(Error::InvalidInput)?,
                _ => unimplemented!(),
            };

            protected_payload.verify::<Sha3_256>(sender.public_key())?;

            if sender.public_key() == self.identity_key_pair.public_key {
                return Ok(vec![]);
            }

            return Ok(protected_payload
                .protected_payload_tbs()
                .payloads()
                .to_vec());
        }

        match frame.frame_tbs().group_operation().unwrap() {
            models::frame::GroupOperation::Init(_) => {
                if frame.frame_tbs().epoch() != 0 {
                    return Ok(vec![]);
                }

                let owner_public_key =
                    CortadoAffine::deserialize_uncompressed(frame.frame_tbs().nonce())?;

                frame.verify_schnorr::<Sha3_256>(owner_public_key)?;

                if owner_public_key == self.identity_key_pair.public_key {
                    return Ok(vec![]);
                }

                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                protected_payload.verify::<Sha3_256>(owner_public_key)?;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            models::frame::GroupOperation::AddMember(changes) => {
                if self.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self.art.compute_artefacts_for_verification(&changes)?;
                let owner_leaf_public_key = self.group_owner_leaf_public_key()?;

                frame.verify_art::<Sha3_256>(
                    &self.proof_system,
                    verifier_artefacts,
                    owner_leaf_public_key,
                )?;

                self.art.update_private_art(&changes)?;
                self.advance_epoch()?;

                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => self
                        .group_info
                        .members()
                        .get_by_id(id)
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
                if self.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self.art.compute_artefacts_for_verification(&changes)?;

                let old_leaf_public_key = self.art.get_node(&changes.node_index)?.public_key;
                frame.verify_art::<Sha3_256>(
                    &self.proof_system,
                    verifier_artefacts,
                    old_leaf_public_key,
                )?;

                println!();
                println!();
                println!("Process frame before ART: {:?}", self.art.get_root());
                println!("Process frame before TK: {:?}", self.art.get_root_key());
                println!("Process frame before STK: {:?}", self.stk);
                self.art.update_private_art(&changes)?;
                self.advance_epoch()?;

                println!();
                println!("Changes: {:?}", changes);
                println!("Process frame after ART: {:?}", self.art.get_root());
                println!("Process frame after TK: {:?}", self.art.get_root_key());
                println!("Process frame after STK: {:?}", self.stk);
                println!();
                println!();
                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let new_users: Vec<models::group_info::User> = protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .iter()
                    .filter_map(|payload| match payload {
                        models::payload::Payload::Action(action) => match action {
                            models::payload::GroupActionPayload::JoinGroup(user) => {
                                Some(user.clone())
                            }
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect();

                let mut group_info = self.group_info.clone();
                for user in new_users {
                    group_info.members_mut().add_user(user);
                }

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => group_info
                        .members()
                        .get_by_id(&id)
                        .ok_or(Error::InvalidInput)?,
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;

                self.group_info = group_info;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            _ => unimplemented!(),
        }

        unreachable!()
    }

    pub fn add_member(
        &mut self,
        invitee: models::invite::Invitee,
        mut payloads: Vec<models::payload::Payload>,
    ) -> Result<(models::frame::Frame, models::invite::Invite)> {
        // 1. Generate ephemeral secret key
        let ephemeral_secret_key = ScalarField::rand(&mut self.rng);
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        // 2. Compute new member's leaf secret
        let leaf_secret = match invitee {
            models::invite::Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => crate::utils::compute_leaf_secret_a(
                self.identity_key_pair.secret_key,
                ephemeral_secret_key,
                identity_public_key,
                spk_public_key.unwrap_or(identity_public_key),
            )
            .map_err(|_| Error::InvalidInput)?,
            models::invite::Invitee::Unidentified(secret_key) => {
                let public_key = (CortadoAffine::generator() * secret_key).into_affine();
                crate::utils::compute_leaf_secret_a(
                    self.identity_key_pair.secret_key,
                    ephemeral_secret_key,
                    public_key,
                    public_key,
                )
                .map_err(|_| Error::InvalidInput)?
            }
        };

        // 3. Add node to ART and advance epoch
        let (_, changes, prover_artefacts) = self.art.append_or_replace_node(&leaf_secret)?;
        self.advance_epoch()?;

        // 4. Add payload with group info
        payloads.push(models::payload::Payload::Action(
            models::payload::GroupActionPayload::InviteMember(self.group_info.clone()),
        ));

        // 5. Construct payload
        // let mut payload = models::protected_payload::ProtectedPayload {
        //     protected_payload_tbs: models::protected_payload::ProtectedPayloadTbs {
        //         seq_num: 0,
        //         created: Utc::now(),
        //         payloads: payloads,
        //         sender: models::protected_payload::Sender::UserId(
        //             self.group_info
        //                 .members
        //                 .get_by_public_key(&self.identity_key_pair.public_key)
        //                 .ok_or(Error::InvalidInput)?
        //                 .id
        //                 .clone(),
        //         ),
        //     },
        //     signature: Vec::new(),
        // };

        let protected_payload_tbs = models::protected_payload::ProtectedPayloadTbs::new(
            0,
            Utc::now(),
            payloads,
            models::protected_payload::Sender::UserId(
                self.group_info
                    .members()
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(Error::InvalidInput)?
                    .id(),
            ),
        );
        let protected_payload =
            protected_payload_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        let mut frame_tbs = models::frame::FrameTbs::new(
            self.group_info.id(),
            self.epoch,
            vec![],
            Some(models::frame::GroupOperation::AddMember(changes)),
            vec![],
        );
        let protected_payload = self.encrypt(
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(protected_payload);

        let frame = frame_tbs.prove_art::<Sha3_256>(
            &mut self.proof_system,
            prover_artefacts,
            self.art.secret_key,
        )?;

        let protected_invite_data = models::invite::ProtectedInviteData::new(
            self.epoch,
            *self.stk,
            self.group_info.clone(),
        );
        let mut leaf_secret_stk = [0u8; 32];
        leaf_secret.serialize_uncompressed(&mut leaf_secret_stk[..])?;
        let protected_invite_data = crate::utils::encrypt(
            &leaf_secret_stk,
            &protected_invite_data.encode_to_vec()?,
            &[],
        )?;

        let invite_tbs = models::invite::InviteTbs::new(
            invitee,
            self.identity_key_pair.public_key,
            ephemeral_public_key,
            protected_invite_data,
        );

        let invite = invite_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        Ok((frame, invite))
    }

    // remove_member should:
    // 1. Generate temporary leaf secret
    // 2. Make node blank in ART and recompute STK
    // 3. Create frame without encrypted payload
    // 4. Encrypt provided payload and attach to frame
    // 5. Generate proof for ART change with SHA3-256(frame) in associated data
    // Return Frame(serialized?)
    pub fn remove_member(
        &mut self,
        // TOOD: We also should take new leaf secret key
        // maybe it should be another function to add ability
        // to user generate secrets on its own
        // public_key -> actor_id
        public_key: CortadoAffine,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Generate temporary leaf secret
        let temporary_leaf_secret: ark_ff::Fp<ark_ff::MontBackend<cortado::FrConfig, 4>, 4> =
            ScalarField::rand(&mut self.rng);

        // 2. Make node blank in ART and recompute STK
        let (_, changes, artefacts) = self.art.make_blank(
            &self.art.get_path_to_leaf(&public_key).unwrap(),
            &temporary_leaf_secret,
        )?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::AddMember(changes.serialze()?))
            .build();
        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_info.id().to_string())
            .group_operation(group_operation)
            .build();

        // 4. Encrypt provided payload and attach to frame
        let protected_payload = self.encrypt(payload, &frame_tbs.encode_to_vec())?;
        frame_tbs.protected_payload = protected_payload;

        let mut frame = builders::FrameBuilder::new().frame(frame_tbs).build();

        // 5. Generate proof for ART change with SHA3-256(frame) in associated data

        // Calculate SHA3-256 digest of frame
        let frame_digest = Sha3_256::digest(frame.encode_to_vec());

        // Prove changes
        let proof =
            self.proof_system
                .prove(artefacts, &vec![self.art.secret_key], &frame_digest)?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes)?;

        frame.proof = proof_bytes;

        Ok(frame.encode_to_vec())
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
        payloads: Vec<zero_art_proto::Payload>,
    ) -> Result<zero_art_proto::Frame> {
        let mut unproved_frame = self.create_frame_unproved(payloads)?;

        // 4. Build and sign (with tree key) frame
        let tk = self.art.get_root_key()?;
        let proof = schnorr::sign(
            &vec![tk.key],
            &vec![(tk.generator * tk.key).into_affine()],
            &Sha3_256::digest(unproved_frame.frame.as_ref().unwrap().encode_to_vec()),
        )?;

        unproved_frame.proof = proof;
        Ok(unproved_frame)
    }

    pub fn create_frame_unproved(
        &mut self,
        payloads: Vec<zero_art_proto::Payload>,
    ) -> Result<zero_art_proto::Frame> {
        // 1. Parse provided payloads

        // 2. Build and sign (with identity key) general payload
        let timestamp = Utc::now();
        let payload_tbs = builders::ProtectedPayloadTbsBuilder::new()
            .payload(payloads)
            .created(Timestamp {
                seconds: timestamp.timestamp(),
                nanos: timestamp.timestamp_subsec_nanos() as i32,
            })
            // TODO: Replace with seq_num
            // ?: If this is global counter then there can be collisions
            .seq_num(0)
            .sender(zero_art_proto::protected_payload_tbs::Sender::UserId(
                self.group_info
                    .members()
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(Error::InvalidInput)?
                    .id()
                    .to_string(),
            ))
            .build();

        let signature = schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            &Sha3_256::digest(payload_tbs.encode_to_vec()),
        )?;

        let payload = builders::ProtectedPayloadBuilder::new()
            .payload(payload_tbs)
            .signature(signature)
            .build();

        // 3. Build FrameTBS and encrypt general payload with FrameTBS as associated data
        // ?: Maybe in the future nonce should increments
        // sequentialy like in Ethereum transactions
        let mut nonce = [0u8; 16];
        self.rng.fill(&mut nonce);
        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_info.id().to_string())
            .nonce(nonce.into())
            .build();

        let protected_payload = self.encrypt(
            &payload.encode_to_vec(),
            &Sha3_256::digest(frame_tbs.encode_to_vec()),
        )?;
        frame_tbs.protected_payload = protected_payload;

        // 4. Build and sign (with tree key) frame
        let frame = builders::FrameBuilder::new().frame(frame_tbs).build();
        Ok(frame)
    }

    pub fn create_init_frame_unproved(
        &mut self,
        payloads: Vec<zero_art_proto::Payload>,
    ) -> Result<zero_art_proto::Frame> {
        // 1. Parse provided payloads

        // 2. Build and sign (with identity key) general payload
        let timestamp = Utc::now();
        let payload_tbs = builders::ProtectedPayloadTbsBuilder::new()
            .payload(payloads)
            .created(Timestamp {
                seconds: timestamp.timestamp(),
                nanos: timestamp.timestamp_subsec_nanos() as i32,
            })
            // TODO: Replace with seq_num
            // ?: If this is global counter then there can be collisions
            .seq_num(0)
            .sender(zero_art_proto::protected_payload_tbs::Sender::UserId(
                self.group_info
                    .members()
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(Error::InvalidInput)?
                    .id()
                    .to_string(),
            ))
            .build();

        let signature = schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            &Sha3_256::digest(payload_tbs.encode_to_vec()),
        )?;

        let payload = builders::ProtectedPayloadBuilder::new()
            .payload(payload_tbs)
            .signature(signature)
            .build();

        // 3. Build FrameTBS and encrypt general payload with FrameTBS as associated data
        // ?: Maybe in the future nonce should increments
        // sequentialy like in Ethereum transactions
        let mut identity_public_key_bytes = Vec::new();
        self.identity_key_pair
            .public_key
            .serialize_uncompressed(&mut identity_public_key_bytes)?;

        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_info.id().to_string())
            .nonce(identity_public_key_bytes)
            .group_operation(zero_art_proto::GroupOperation {
                operation: Some(zero_art_proto::group_operation::Operation::Init(
                    self.art.serialize()?,
                )),
            })
            .build();

        let protected_payload = self.encrypt(
            &payload.encode_to_vec(),
            &Sha3_256::digest(frame_tbs.encode_to_vec()),
        )?;
        frame_tbs.protected_payload = protected_payload;

        // 4. Build and sign (with tree key) frame
        let frame = builders::FrameBuilder::new().frame(frame_tbs).build();
        Ok(frame)
    }

    // update_key should:
    // 1. Update own leaf with provided secret and recompute STK
    // 2. Create frame without encrypted payload
    // 3. Encrypt provided payload and attach to frame
    // 4. Generate proof for ART change with SHA3-256(frame) in associated data
    // Return Frame(serialized?)
    pub fn update_key(
        &mut self,
        leaf_secret: ScalarField,
        payloads: Vec<models::payload::Payload>,
    ) -> Result<models::frame::Frame> {
        // 1. Update own leaf with provided secret and recompute STK
        let old_secret = self.art.secret_key;

        println!();
        println!();
        println!("Key update before ART: {:?}", self.art.get_root());
        println!("Key update before TK: {:?}", self.art.get_root_key());
        println!("Key update before STK: {:?}", self.stk);
        let (_, changes, prover_artefacts) = self.art.update_key(&leaf_secret)?;
        self.advance_epoch()?;
        println!();
        println!("Changes: {:?}", changes);
        println!("Key update after ART: {:?}", self.art.get_root());
        println!("Key update after TK: {:?}", self.art.get_root_key());
        println!("Key update after STK: {:?}", self.stk);
        println!();
        println!();

        let protected_payload_tbs = models::protected_payload::ProtectedPayloadTbs::new(
            0,
            Utc::now(),
            payloads,
            models::protected_payload::Sender::UserId(
                self.group_info
                    .members()
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(Error::InvalidInput)?
                    .id(),
            ),
        );
        let protected_payload =
            protected_payload_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        let mut frame_tbs = models::frame::FrameTbs::new(
            self.group_info.id(),
            self.epoch,
            vec![],
            Some(models::frame::GroupOperation::KeyUpdate(changes)),
            vec![],
        );
        let protected_payload = self.encrypt(
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(protected_payload);

        Ok(
            frame_tbs.prove_art::<Sha3_256>(
                &mut self.proof_system,
                prover_artefacts,
                old_secret,
            )?,
        )
    }

    fn group_owner_leaf_public_key(&self) -> Result<CortadoAffine> {
        Ok(LeafIter::new(self.art.get_root())
            .next()
            .ok_or(Error::InvalidInput)?
            .get_public_key())
    }

    fn simulate_art_change_with_stk(
        &self,
        changes: &BranchChanges<CortadoAffine>,
    ) -> Result<[u8; 32]> {
        let mut eph_art = self.art.clone();
        eph_art.update_private_art(changes)?;

        derive_stage_key(&self.stk, eph_art.get_root_key()?.key)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{group_context, models::group_info::GroupInfo, secrets_factory};

    use super::*;

    #[test]
    fn test_create_new_group() {
        // Use determined seed for reproducability
        let mut rng = StdRng::seed_from_u64(0);

        let mut secrets_factory_seed = [0u8; 32];
        rng.fill(&mut secrets_factory_seed);

        let mut secrets_factory = secrets_factory::SecretsFactory::new(secrets_factory_seed);

        // Predefined key pairs
        let mut key_pairs = Vec::new();
        for _ in 0..20 {
            key_pairs.push(secrets_factory.generate_secret_with_public_key());
        }

        let owner_user = models::group_info::User::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440001").unwrap(),
            String::from("owner"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::default(),
        );
        let group_info = models::group_info::GroupInfo::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
            String::from("group_1"),
            Utc::now(),
            vec![],
            models::group_info::GroupMembers::default(),
        );

        let mut context_seed = [0u8; 32];
        rng.fill(&mut context_seed);

        let mut proof_system_seed = [0u8; 32];
        rng.fill(&mut proof_system_seed);

        let result = group_context::builder::GroupContextBuilder::new(key_pairs[0].1)
            .context_prng_seed(context_seed)
            .proof_system_prng_seed(proof_system_seed)
            .create(owner_user, group_info)
            .identified_members_keys(vec![
                (key_pairs[1].0, Some(key_pairs[2].0)),
                (key_pairs[3].0, None),
            ])
            .unidentified_members_count(3)
            .payloads(vec![])
            .build();

        assert!(result.is_ok(), "Failed to create group context");

        let (mut group_context, init_frame, identified_invites, unidentified_invites) =
            result.unwrap();

        assert_eq!(
            identified_invites.len(),
            2,
            "Group created with 2 identified invites"
        );
        assert_eq!(
            unidentified_invites.len(),
            3,
            "Group created with 3 unidentified invites"
        );

        // Check if identified invite is invited users
        let mut public_key_1_bytes = Vec::new();
        key_pairs[1]
            .0
            .serialize_uncompressed(&mut public_key_1_bytes)
            .unwrap();
        let mut public_key_3_bytes = Vec::new();
        key_pairs[3]
            .0
            .serialize_uncompressed(&mut public_key_3_bytes)
            .unwrap();

        identified_invites.get(&public_key_1_bytes).unwrap();
        identified_invites.get(&public_key_3_bytes).unwrap();

        assert_eq!(
            group_context.art.get_root().weight,
            6,
            "ART should have 6 leafs (owner + 2 identified + 3 unidentified)"
        );

        let public_art_bytes = group_context.art.serialize().unwrap();

        let user_1 = models::group_info::User::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440002").unwrap(),
            String::from("user"),
            CortadoAffine::generator(),
            vec![],
            zero_art_proto::Role::default(),
        );
        let invite = identified_invites.get(&public_key_1_bytes).unwrap().clone();

        let (identity_public_key_1, identity_secret_key_1) = key_pairs[1];
        let (spk_public_key_2, spk_secret_key_2) = key_pairs[2];

        // let (mut secondary_group_context, join_group_frame) = GroupContext::from_invite(
        //     identity_secret_key_1,
        //     Some(spk_secret_key_2),
        //     public_art_bytes.clone(),
        //     invite,
        //     user_1,
        // )
        // .unwrap();

        let (identity_public_key_4, identity_secret_key_4) = key_pairs[4];
        let (spk_public_key_5, spk_secret_key_5) = key_pairs[5];

        let (frame, invite) = group_context
            .add_member(
                models::invite::Invitee::Identified {
                    identity_public_key: identity_public_key_4,
                    spk_public_key: Some(spk_public_key_5),
                },
                vec![],
            )
            .unwrap();

        let public_art_bytes = group_context.art.serialize().unwrap();

        let user_1 = models::group_info::User::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440003").unwrap(),
            String::from("user"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::default(),
        );
        let (mut secondary_group_context, join_group_frame) = GroupContext::from_invite(
            identity_secret_key_4,
            Some(spk_secret_key_5),
            public_art_bytes,
            invite,
            user_1,
        )
        .unwrap();

        let (leaf_secret, art, stk, epoch, group_info) = group_context.into_parts().unwrap();
        let leaf_secret = ScalarField::deserialize_uncompressed(&leaf_secret[..]).unwrap();
        let group_info = zero_art_proto::GroupInfo::decode(&group_info[..]).unwrap();
        let mut group_context = GroupContext::from_parts(
            key_pairs[0].1,
            leaf_secret,
            &art,
            stk.try_into().unwrap(),
            epoch,
            0,
            group_info.try_into().unwrap(),
        )
        .unwrap();

        group_context
            .process_frame(zero_art_proto::SpFrame {
                seq_num: 0,
                created: None,
                frame: Some(join_group_frame.try_into().unwrap()),
            })
            .unwrap();

        // let payloads = secondary_group_context
        //     .process_frame(zero_art_proto::SpFrame {
        //         seq_num: 0,
        //         created: None,
        //         frame: Some(join_group_frame),
        //     })
        //     .unwrap();
        // assert_eq!(payloads.len(), 0);
    }

    #[test]
    fn test_create_new_group_2() {
        // Use determined seed for reproducability
        let mut rng = StdRng::seed_from_u64(0);

        let mut secrets_factory_seed = [0u8; 32];
        rng.fill(&mut secrets_factory_seed);

        let mut secrets_factory = secrets_factory::SecretsFactory::new(secrets_factory_seed);

        // Predefined key pairs
        let mut key_pairs = Vec::new();
        for _ in 0..20 {
            key_pairs.push(secrets_factory.generate_secret_with_public_key());
        }

        let owner_user = models::group_info::User::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440001").unwrap(),
            String::from("owner"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::default(),
        );
        let group_info = models::group_info::GroupInfo::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
            String::from("group_1"),
            Utc::now(),
            vec![],
            models::group_info::GroupMembers::default(),
        );

        let mut context_seed = [0u8; 32];
        rng.fill(&mut context_seed);

        let mut proof_system_seed = [0u8; 32];
        rng.fill(&mut proof_system_seed);

        let result = group_context::builder::GroupContextBuilder::new(key_pairs[0].1)
            .context_prng_seed(context_seed)
            .proof_system_prng_seed(proof_system_seed)
            .create(owner_user, group_info)
            .unidentified_members_count(1)
            .payloads(vec![])
            .build();
        assert!(result.is_ok(), "Failed to create group context");

        let (mut group_context, init_frame, identified_invites, unidentified_invites) =
            result.unwrap();

        let (invite_public_key_1, invite_secret_key_1) = key_pairs[1];

        // Invite unidentified member
        // let (frame, invite) = group_context
        //     .add_member(invite::Invitee::Unidentified(invite_secret_key_1), vec![])
        //     .unwrap();

        // let (frame, invite) = group_context
        //     .add_member(
        //         invite::Invitee::Identified {
        //             identity_public_key: key_pairs[0].0,
        //             spk_public_key: None,
        //         },
        //         vec![],
        //     )
        //     .unwrap();

        let (frame, invite) = group_context
            .add_member(
                models::invite::Invitee::Identified {
                    identity_public_key: key_pairs[1].0,
                    spk_public_key: None,
                },
                vec![],
            )
            .unwrap();

        let public_art_bytes = group_context.art.serialize().unwrap();

        let user_1 = models::group_info::User::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440002").unwrap(),
            String::from("user"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::default(),
        );
        let (mut secondary_group_context, join_group_frame) =
            GroupContext::from_invite(key_pairs[1].1, None, public_art_bytes, invite, user_1)
                .unwrap();

        println!("Frame epocch: {}", join_group_frame.frame_tbs().epoch());

        println!("Epoch: {}", group_context.epoch);
        let paylaods = group_context
            .process_frame(zero_art_proto::SpFrame {
                seq_num: 0,
                created: None,
                frame: Some(join_group_frame.try_into().unwrap()),
            })
            .unwrap();

        println!("Epoch: {}", group_context.epoch);
        assert!(paylaods.len() != 0);

        // let (leaf_secret, art, stk, epoch, group_info) = group_context.into_parts().unwrap();
        // let leaf_secret = ScalarField::deserialize_uncompressed(&leaf_secret[..]).unwrap();
        // let group_info = zero_art_proto::GroupInfo::decode(&group_info[..]).unwrap();
        // let mut group_context = GroupContext::from_parts(
        //     key_pairs[0].1,
        //     leaf_secret,
        //     &art,
        //     stk.try_into().unwrap(),
        //     epoch,
        //     0,
        //     group_info.try_into().unwrap(),
        // )
        // .unwrap();

        // group_context
        //     .process_frame(zero_art_proto::SpFrame {
        //         seq_num: 0,
        //         created: None,
        //         frame: Some(join_group_frame.try_into().unwrap()),
        //     })
        //     .unwrap();

        // let payloads = secondary_group_context
        //     .process_frame(zero_art_proto::SpFrame {
        //         seq_num: 0,
        //         created: None,
        //         frame: Some(join_group_frame),
        //     })
        //     .unwrap();
        // assert_eq!(payloads.len(), 0);
    }

    #[test]
    fn test_context_from_tree_secret() {
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = ScalarField::rand(&mut rng);
        // let secret_key_1 = ScalarField::rand(&mut rng);

        let (mut private_art_0, _) =
            PrivateART::new_art_from_secrets(&vec![secret_key_0], &CortadoAffine::generator())
                .unwrap();

        let secret_key_2 = ScalarField::rand(&mut rng);
        private_art_0.append_or_replace_node(&secret_key_2).unwrap();

        let public_art_bytes = private_art_0.serialize().unwrap();

        let mut private_art_1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_2).unwrap();
        let secret_key_3 = ScalarField::rand(&mut rng);

        let (tk, changes, _) = private_art_1.update_key(&secret_key_3).unwrap();
        println!("tk_1: {:?}", private_art_1.get_root_key());
        println!();
        println!("art_1: {}", private_art_1.get_root());

        println!();
        private_art_0.update_private_art(&changes).unwrap();
        println!("tk_0: {:?}", private_art_0.get_root_key());
        println!();
        println!("art_0: {}", private_art_0.get_root());
        println!();

        assert_eq!(private_art_0.get_root(), private_art_1.get_root());
        // assert_eq!(
        //     private_art_1.get_root_key().unwrap(),
        //     private_art_0.get_root_key().unwrap()
        // );
    }

    #[test]
    fn test_context_from_invite() {}

    #[test]
    fn test_add_member() {}

    #[test]
    fn test_remove_member() {}

    #[test]
    fn test_update_key() {}

    #[test]
    fn test_process_frame() {}

    #[test]
    fn test_() {}
}
