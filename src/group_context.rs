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

use crate::group_context::utils::{decrypt, derive_stage_key, encrypt};
use crate::{
    builders, metadata,
    proof_system::ProofSystem,
    zero_art_proto::{
        self, GroupOperation, Invite, group_operation::Operation, protected_payload_tbs,
    },
};
use crate::{frame, invite, proof_system};
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

#[derive(Error, Debug)]
pub enum SDKError {
    #[error("ART error")]
    ArtError(#[from] ARTError),
    #[error("Serialization error")]
    SerializationError(#[from] SerializationError),
    #[error("Cryptography error")]
    CryptoError(#[from] CryptoError),
    #[error("Decode error")]
    DecodeError(#[from] DecodeError),
    #[error("HKDF error")]
    HKDFError(#[from] hkdf::InvalidLength),
    #[error("R1CS error")]
    R1CSError(#[from] R1CSError),
    #[error("Metadata error")]
    MetadataError(#[from] metadata::error::Error),

    #[error("AES encryption error")]
    AesError,

    #[error("ART logic error")]
    ARTLogicError,
    #[error("Invalid input provided")]
    InvalidInput,
    // #[error("Postcard error: {0}")]
    // Postcard(#[from] postcard::Error),
    // #[error("Serde JSON error: {0}")]
    // SerdeJson(#[from] serde_json::Error),
    // #[error("Node error: {0}")]
    // Node(#[from] ARTNodeError),
    #[error("Can't find path to given node.")]
    PathNotExists,
    #[error("Can't remove the node. It isn't close enough")]
    RemoveError,
    #[error("Failed to convert &[u8] into &[u8;32]: {0}")]
    ConversionError(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point")]
    XCoordinateError,
    #[error("No changes provided in given BranchChanges structure")]
    NoChanges,

    #[error("Invalid epoch")]
    InvalidEpoch,
}

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

#[derive(Debug)]
struct IdentifiedPublicKeys {
    identity_public_key: CortadoAffine,
    invitation_public_key: CortadoAffine,
}

impl IdentifiedPublicKeys {
    fn new(
        identity_public_key: CortadoAffine,
        invitation_public_key: Option<CortadoAffine>,
    ) -> Self {
        if invitation_public_key.is_some() {
            return Self {
                identity_public_key,
                invitation_public_key: invitation_public_key.unwrap(),
            };
        }

        Self {
            identity_public_key: identity_public_key.clone(),
            invitation_public_key: identity_public_key,
        }
    }
}

// TODO: Add serialization
#[derive(Clone, Copy)]
pub enum InvitationKeys {
    Identified {
        identity_public_key: CortadoAffine,
        spk_public_key: Option<CortadoAffine>,
    },
    Unidentified {
        invitation_secret_key: ScalarField,
    },
}

// fn derive_stage_key(stage_key: &[u8; 32], art: PrivateART<CortadoAffine>, group_operation: zero_art_proto::group_operation::Operation) {

// }

pub struct GroupContext {
    art: PrivateART<CortadoAffine>,
    // ?: i realy don't know why Box
    stk: Box<[u8; 32]>,
    epoch: u64,
    proof_system: ProofSystem,

    seq_num: u64,

    rng: StdRng,

    identity_key_pair: KeyPair,

    group_info: metadata::group::GroupInfo,
}

impl GroupContext {
    pub fn sign_with_tk(&self, msg: &[u8]) -> Result<Vec<u8>, SDKError> {
        let tk = self.art.get_root_key()?;
        let tk_public_key = (CortadoAffine::generator() * tk.key).into_affine();
        Ok(schnorr::sign(&vec![tk.key], &vec![tk_public_key], msg)?)
    }

    pub fn get_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn into_parts(self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u64, Vec<u8>), SDKError> {
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
        group_info: metadata::group::GroupInfo,
    ) -> Result<Self, SDKError> {
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
        invite: zero_art_proto::Invite,
        mut user: metadata::user::User,
    ) -> Result<(Self, frame::Frame), SDKError> {
        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        let (mut invite, invite_leaf_secret) =
            invite::Invite::try_from(invite, Some((identity_secret_key, spk_secret_key)))?;
        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(&art, &invite_leaf_secret)?;
        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        user.public_key = identity_key_pair.public_key;
        invite.group_info.members.add_user(user.clone());

        let mut group_context = Self {
            art,
            stk: Box::new(invite.stage_key),
            epoch: invite.epoch,
            seq_num: 0,
            proof_system: proof_system::ProofSystem::default(),
            rng: context_rng,
            group_info: invite.group_info,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
        };

        let leaf_secret = ScalarField::rand(&mut group_context.rng);

        let group_action_payload =
            frame::Payload::Action(frame::GroupActionPayload::JoinGroup(user));

        let frame = group_context.update_key(leaf_secret, vec![group_action_payload])?;

        Ok((group_context, frame))
    }

    // process_frame should:
    // 1. Deserialize SP frame
    // 2. Validate epoch correctness
    // 3. Verify frame proof/signature
    // 4.
    //
    pub fn process_frame(
        &mut self,
        sp_frame: zero_art_proto::SpFrame,
    ) -> Result<Vec<frame::Payload>, SDKError> {
        let frame = sp_frame.frame.ok_or(SDKError::InvalidInput)?;
        let mut frame = frame::Frame::try_from(frame)?;
        // Validate that frame belong to this group
        let group_id = frame.frame_tbs.group_id;
        if group_id != self.group_info.id {
            return Err(SDKError::InvalidInput);
        }

        let epoch = frame.frame_tbs.epoch;
        if frame.frame_tbs.group_operation.is_none() {
            if self.epoch == epoch {
                return Err(SDKError::InvalidInput);
            }

            let tk = self.art.get_root_key()?;
            let tree_public_key = (tk.generator * tk.key).into_affine();

            match frame.proof {
                frame::Proof::SchnorrSignature(signature) => {
                    schnorr::verify(
                        &signature,
                        &vec![tree_public_key],
                        &Sha3_256::digest(frame.frame_tbs.encode_to_vec()?),
                    )?;
                }
                _ => unreachable!(),
            }

            frame.frame_tbs.decrypt(&self.stk)?;

            let payload = &frame
                .frame_tbs
                .decrypted_payload
                .ok_or(SDKError::InvalidInput)?;

            let sender = match payload.protected_payload_tbs.sender.clone() {
                frame::Sender::UserId(id) => self
                    .group_info
                    .members
                    .get_by_id(&id)
                    .ok_or(SDKError::InvalidInput)?,
                _ => unimplemented!(),
            };

            schnorr::verify(
                &payload.signature,
                &vec![sender.public_key],
                &Sha3_256::digest(payload.protected_payload_tbs.encode_to_vec()),
            )?;

            if sender.public_key == self.identity_key_pair.public_key {
                return Ok(vec![]);
            }

            return Ok(payload.protected_payload_tbs.payloads.clone());
        }

        match frame.frame_tbs.group_operation.clone().unwrap() {
            frame::GroupOperation::Init(_) => {
                if frame.frame_tbs.epoch != 0 {
                    return Ok(vec![]);
                }

                let owner_public_key =
                    CortadoAffine::deserialize_uncompressed(&frame.frame_tbs.nonce[..])?;

                match frame.proof {
                    frame::Proof::SchnorrSignature(signature) => {
                        schnorr::verify(
                            &signature,
                            &vec![owner_public_key],
                            &Sha3_256::digest(frame.frame_tbs.encode_to_vec()?),
                        )?;
                    }
                    _ => unreachable!(),
                }

                if owner_public_key == self.identity_key_pair.public_key {
                    return Ok(vec![]);
                }

                frame.frame_tbs.decrypt(&self.stk)?;

                let payload = &frame
                    .frame_tbs
                    .decrypted_payload
                    .ok_or(SDKError::InvalidInput)?;
                schnorr::verify(
                    &payload.signature,
                    &vec![owner_public_key],
                    &Sha3_256::digest(payload.protected_payload_tbs.encode_to_vec()),
                )?;

                return Ok(payload.protected_payload_tbs.payloads.clone());
            }
            frame::GroupOperation::AddMember(changes) => {
                if self.epoch == frame.frame_tbs.epoch {
                    return Ok(vec![]);
                }
                if self.epoch + 1 != frame.frame_tbs.epoch {
                    return Err(SDKError::InvalidInput);
                }

                let verification_artefacts =
                    self.art.compute_artefacts_for_verification(&changes)?;
                let owner_leaf_public_key = self.group_owner_leaf_public_key()?;
                match frame.proof {
                    frame::Proof::ArtProof(art_proof) => {
                        self.proof_system.verify(
                            verification_artefacts,
                            &vec![owner_leaf_public_key],
                            &Sha3_256::digest(frame.frame_tbs.encode_to_vec()?),
                            art_proof,
                        )?;
                    }
                    _ => unreachable!(),
                };

                self.art.update_private_art(&changes)?;
                self.advance_epoch()?;

                frame.frame_tbs.decrypt(&self.stk)?;

                let payload = &frame
                    .frame_tbs
                    .decrypted_payload
                    .ok_or(SDKError::InvalidInput)?;

                let sender = match payload.protected_payload_tbs.sender.clone() {
                    frame::Sender::UserId(id) => self
                        .group_info
                        .members
                        .get_by_id(&id)
                        .ok_or(SDKError::InvalidInput)?,
                    _ => unimplemented!(),
                };

                schnorr::verify(
                    &payload.signature,
                    &vec![sender.public_key],
                    &Sha3_256::digest(payload.protected_payload_tbs.encode_to_vec()),
                )?;

                return Ok(payload.protected_payload_tbs.payloads.clone());
            }
            frame::GroupOperation::KeyUpdate(changes) => {
                if self.epoch == frame.frame_tbs.epoch {
                    return Ok(vec![]);
                }
                if self.epoch + 1 != frame.frame_tbs.epoch {
                    return Err(SDKError::InvalidInput);
                }

                let verification_artefacts =
                    self.art.compute_artefacts_for_verification(&changes)?;

                let old_leaf_public_key = self.art.get_node(&changes.node_index)?.public_key;
                match frame.proof {
                    frame::Proof::ArtProof(art_proof) => {
                        self.proof_system.verify(
                            verification_artefacts,
                            &vec![old_leaf_public_key],
                            &Sha3_256::digest(frame.frame_tbs.encode_to_vec()?),
                            art_proof,
                        )?;
                    }
                    _ => unreachable!(),
                };

                println!("Process, Before STK: {:?}", self.stk);
                println!("Process, Before TK: {:?}", self.art.get_root_key());
                println!("Process, Changes: {:?}", changes);
                self.art.update_public_art(&changes)?;
                self.advance_epoch()?;
                println!("Process, After STK: {:?}", self.stk);
                println!("Process, After TK: {:?}", self.art.get_root_key());

                frame.frame_tbs.decrypt(&self.stk)?;

                let payload = &frame
                    .frame_tbs
                    .decrypted_payload
                    .ok_or(SDKError::InvalidInput)?;

                let new_users: Vec<metadata::user::User> = payload
                    .protected_payload_tbs
                    .payloads
                    .iter()
                    .filter_map(|payload| match payload {
                        frame::Payload::Action(action) => match action {
                            frame::GroupActionPayload::JoinGroup(user) => Some(user.clone()),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect();

                let mut group_info = self.group_info.clone();
                for user in new_users {
                    group_info.members.add_user(user);
                }

                let sender = match payload.protected_payload_tbs.sender.clone() {
                    frame::Sender::UserId(id) => group_info
                        .members
                        .get_by_id(&id)
                        .ok_or(SDKError::InvalidInput)?,
                    _ => unimplemented!(),
                };

                schnorr::verify(
                    &payload.signature,
                    &vec![sender.public_key],
                    &Sha3_256::digest(payload.protected_payload_tbs.encode_to_vec()),
                )?;

                self.group_info = group_info;

                return Ok(payload.protected_payload_tbs.payloads.clone());
            }
            _ => unimplemented!(),
        }

        unreachable!()
    }

    // add_member should:
    // 1. Compute new member's leaf secret
    // 2. Add node to ART and recompute STK
    // 3. Create frame without encrypted payload
    // 4. Encrypt provided payload and attach to frame
    // 5. Generate proof for ART change with SHA3-256(frame) in associated data
    // 6. Create and Sign invite
    // Return Frame(serialized?), Invite(serialized?)
    // invitation_keys -> User
    pub fn add_member(
        &mut self,
        invitee: invite::Invitee,
        mut payloads: Vec<zero_art_proto::Payload>,
    ) -> Result<(zero_art_proto::Frame, zero_art_proto::Invite), SDKError> {
        let ephemeral_secret_key = ScalarField::rand(&mut self.rng);
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        // 1. Compute new member's leaf secret
        let leaf_secret = self.compute_member_leaf_secret(ephemeral_secret_key, invitee)?;

        // 2. Add node to ART and recompute STK
        let (_, changes, artefacts) = self.art.append_or_replace_node(&leaf_secret)?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::AddMember(changes.serialze()?))
            .build();

        // 4. Build GroupActionPayload
        let group_action_payload = zero_art_proto::Payload {
            content: Some(zero_art_proto::payload::Content::Action(
                zero_art_proto::GroupActionPayload {
                    action: Some(zero_art_proto::group_action_payload::Action::InviteMember(
                        self.group_info.clone().into(),
                    )),
                },
            )),
        };
        payloads.push(group_action_payload);

        // 5. Build and sign (with identity key) general payload
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
                    .members
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(SDKError::InvalidInput)?
                    .id
                    .clone(),
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

        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_info.id.to_string())
            .group_operation(group_operation)
            .build();

        // 4. Encrypt provided payload and attach to frame
        let protected_payload = self.encrypt(
            &payload.encode_to_vec(),
            &Sha3_256::digest(frame_tbs.encode_to_vec()),
        )?;
        frame_tbs.protected_payload = protected_payload;

        // 5. Generate proof for ART change with SHA3-256(frame) in associated data

        // Calculate SHA3-256 digest of frame
        let frame_digest = Sha3_256::digest(frame_tbs.encode_to_vec());

        // Prove changes
        let proof = self
            .proof_system
            // review this
            .prove(artefacts, &vec![self.art.secret_key], &frame_digest)?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes)?;

        let frame = builders::FrameBuilder::new()
            .frame(frame_tbs)
            .proof(proof_bytes)
            .build();

        // 6. Create and Sign invite
        let invite = invite::Invite {
            invitee: invitee,
            inviter_public_key: CortadoAffine::default(),
            ephemeral_public_key: CortadoAffine::default(),
            epoch: self.epoch,
            stage_key: *self.stk,
            group_info: self.group_info.clone(),
        }
        .try_into(self.identity_key_pair.secret_key, ephemeral_secret_key)?;

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
    ) -> Result<Vec<u8>, SDKError> {
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
            .group_id(self.group_info.id.to_string())
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
    ) -> Result<zero_art_proto::Frame, SDKError> {
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
    ) -> Result<zero_art_proto::Frame, SDKError> {
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
                    .members
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(SDKError::InvalidInput)?
                    .id
                    .clone(),
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
            .group_id(self.group_info.id.to_string())
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
    ) -> Result<zero_art_proto::Frame, SDKError> {
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
                    .members
                    .get_by_public_key(&self.identity_key_pair.public_key)
                    .ok_or(SDKError::InvalidInput)?
                    .id
                    .clone(),
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
            .group_id(self.group_info.id.to_string())
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
        payloads: Vec<frame::Payload>,
    ) -> Result<frame::Frame, SDKError> {
        // 1. Update own leaf with provided secret and recompute STK
        let old_secret = self.art.secret_key;

        println!("Generate, Before STK: {:?}", self.stk);
        println!("Generate, Before TK: {:?}", self.art.get_root_key());
        let (_, changes, artefacts) = self.art.update_key(&leaf_secret)?;
        println!("Generate, Changes: {:?}", changes);
        self.advance_epoch()?;
        println!("Generate, After STK: {:?}", self.stk);
        println!("Generate, After TK: {:?}", self.art.get_root_key());

        let mut payload = frame::ProtectedPayload {
            protected_payload_tbs: frame::ProtectedPayloadTbs {
                seq_num: 0,
                created: Utc::now(),
                payloads: payloads,
                sender: frame::Sender::UserId(
                    self.group_info
                        .members
                        .get_by_public_key(&self.identity_key_pair.public_key)
                        .ok_or(SDKError::InvalidInput)?
                        .id
                        .clone(),
                ),
            },
            signature: Vec::new(),
        };

        let signature = schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            &Sha3_256::digest(payload.protected_payload_tbs.encode_to_vec()),
        )?;
        payload.signature = signature;

        let mut frame = frame::Frame {
            frame_tbs: frame::FrameTbs {
                group_id: self.group_info.id.clone(),
                epoch: self.epoch,
                nonce: vec![],
                group_operation: Some(frame::GroupOperation::KeyUpdate(changes)),
                protected_payload: Vec::new(),
                decrypted_payload: Some(payload),
            },
            proof: frame::Proof::default(),
        };
        frame.frame_tbs.encrypt(&self.stk)?;

        // Prove changes
        let proof = self.proof_system.prove(
            artefacts,
            &vec![old_secret],
            &Sha3_256::digest(frame.frame_tbs.encode_to_vec()?),
        )?;
        frame.proof = frame::Proof::ArtProof(proof);

        Ok(frame)
    }

    fn apply_changes(&mut self, changes: &[u8]) -> Result<(), SDKError> {
        self.art
            .update_private_art(&BranchChanges::deserialize(changes)?)?;
        let tk = self.art.get_root_key()?;

        // Derive new stage key
        // TODO: Concat with stk
        // self.stk = Key::<Aes256Gcm>::from(hkdf(Some(b"stage-key-derivation"), &serialize_to_vec![tk.key]?)?);

        // Increment epoch
        self.epoch += 1;
        Ok(())
    }

    fn group_owner_leaf_public_key(&self) -> Result<CortadoAffine, SDKError> {
        Ok(LeafIter::new(self.art.get_root())
            .next()
            .ok_or(SDKError::InvalidInput)?
            .get_public_key())
    }

    fn simulate_art_change_with_stk(
        &self,
        changes: &BranchChanges<CortadoAffine>,
    ) -> Result<[u8; 32], SDKError> {
        let mut eph_art = self.art.clone();
        eph_art.update_private_art(changes)?;

        derive_stage_key(&self.stk, eph_art.get_root_key()?.key)
    }
}

// pub fn invite_to_challenge() ->

// pub fn verify_invite(invite: zero_art_proto::Invite) {
//     if invite;

//     let signature = invite.signature;

// }

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{group_context, secrets_factory};

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

        let owner_user =
            metadata::user::User::new(String::from("owner_id_1"), String::from("owner"), vec![]);
        let group_info = metadata::group::GroupInfo::new(
            Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
            String::from("group_1"),
            vec![],
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

        let user_1 =
            metadata::user::User::new(String::from("user_id_1"), String::from("user"), vec![]);
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
                invite::Invitee::Identified {
                    identity_public_key: identity_public_key_4,
                    spk_public_key: Some(spk_public_key_5),
                },
                vec![],
            )
            .unwrap();

        let public_art_bytes = group_context.art.serialize().unwrap();

        let user_1 =
            metadata::user::User::new(String::from("user_id_2"), String::from("user"), vec![]);
        let (mut secondary_group_context, join_group_frame) = GroupContext::from_invite(
            identity_secret_key_4,
            Some(spk_secret_key_5),
            public_art_bytes,
            invite,
            user_1,
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

    // #[test]
    // fn test_new_context() {
    //     let mut secrets_factory = secrets_factory::SecretsFactory::default();
    //     let (identity_public_key, identity_secret_key) =
    //         secrets_factory.generate_secret_with_public_key();
    //     // let leaf_secret = secrets_factory.generate_secret();

    //     let user = metadata::user::User {
    //         id: String::from("id"),
    //         name: String::from("id"),
    //         metadata: vec![],
    //         public_key: identity_public_key,
    //         role: zero_art_proto::Role::default(),
    //     };

    //     let group_info = metadata::group::GroupInfo {
    //         id: String::from("id"),
    //         name: String::from("id"),
    //         metadata: vec![],
    //         created: Utc::now(),
    //         members: metadata::group::GroupMembers::default(),
    //     };

    //     // let (identified_public_key_1, identified_secret_key_1) =
    //     //     secrets_factory.generate_secret_with_public_key();
    //     // let (identified_public_key_2, identified_secret_key_2) =
    //     //     secrets_factory.generate_secret_with_public_key();
    //     // let (identified_public_key_3, identified_secret_key_3) =
    //     //     secrets_factory.generate_secret_with_public_key();
    //     // let (spk_public_key_1, spk_secret_key_1) =
    //     //     secrets_factory.generate_secret_with_public_key();
    //     // let (spk_public_key_2, spk_secret_key_2) =
    //     //     secrets_factory.generate_secret_with_public_key();
    //     // let (spk_public_key_3, spk_secret_key_3) =
    //     //     secrets_factory.generate_secret_with_public_key();

    //     let (mut group_context, frame, identified_invites, unidentified_invites) =
    //         builder::GroupContextBuilder::new(identity_secret_key)
    //             .create(user, group_info)
    //             .unidentified_members_count(1)
    //             // .identified_members_keys(vec![(identified_public_key_1, Some(spk_public_key_1))])
    //             .build()
    //             .unwrap();

    //     // println!("serialized art: {:?}", group_context.art.root);

    //     let (public_key, secret_key) = secrets_factory.generate_secret_with_public_key();

    //     let (_, invite) = group_context
    //         .add_member(invite::Invitee::Unidentified(secret_key), vec![])
    //         .unwrap();

    //     let (invite, leaf_secret) = invite::Invite::try_from(invite, None).unwrap();
    //     // println!("Invite: {:?}", leaf_secret);
    //     let leaf_public_key = (CortadoAffine::generator() * leaf_secret).into_affine();

    //     let mut public_key_is_wrong = true;
    //     for node in LeafIter::new(group_context.art.get_root()) {
    //         if node.public_key == leaf_public_key {
    //             public_key_is_wrong = false;
    //         }
    //     }

    //     let (invite_public_key, invite_secret_key) =
    //         secrets_factory.generate_secret_with_public_key();

    //     let (inviter_public_key, inviter_secret_key) =
    //         secrets_factory.generate_secret_with_public_key();

    //     let (ephemeral_public_key, ephemeral_secret_key) =
    //         secrets_factory.generate_secret_with_public_key();

    //     let leaf_a = ScalarField::from_le_bytes_mod_order(
    //         &x3dh_a::<CortadoAffine>(
    //             inviter_secret_key,
    //             ephemeral_secret_key,
    //             invite_public_key,
    //             invite_public_key,
    //         )
    //         .unwrap(),
    //     );

    //     let leaf_b = ScalarField::from_le_bytes_mod_order(
    //         &x3dh_b::<CortadoAffine>(
    //             invite_secret_key,
    //             invite_secret_key,
    //             inviter_public_key,
    //             ephemeral_public_key,
    //         )
    //         .unwrap(),
    //     );

    //     // let frame = group_context.create_frame(vec![]).unwrap();
    //     // let res = group_context
    //     //     .add_member(
    //     //         InvitationKeys::Unidentified {
    //     //             invitation_secret_key: identified_secret_key_2,
    //     //         },
    //     //         vec![],
    //     //     )
    //     //     .unwrap();
    //     // println!("frame: {:?}", frame.encode_to_vec())
    //     // group_context
    //     //     .process_frame(zero_art_proto::SpFrame {
    //     //         seq_num: 0,
    //     //         created: None,
    //     //         frame: Some(frame),
    //     //     })
    //     //     .unwrap();
    // }

    // #[test]
    // fn test_create_group() {
    //     let frame_bytes = vec![
    //         10, 134, 1, 10, 2, 105, 100, 26, 16, 177, 119, 38, 153, 44, 247, 120, 146, 151, 166,
    //         146, 50, 14, 9, 221, 241, 50, 110, 104, 209, 123, 20, 52, 151, 120, 11, 229, 215, 99,
    //         125, 145, 235, 5, 104, 104, 252, 215, 144, 44, 231, 192, 8, 144, 96, 197, 102, 166,
    //         205, 192, 190, 205, 253, 230, 54, 1, 219, 221, 17, 234, 101, 49, 75, 237, 79, 41, 119,
    //         161, 73, 95, 156, 51, 189, 242, 146, 33, 76, 67, 100, 250, 31, 143, 161, 184, 242, 137,
    //         194, 144, 10, 56, 65, 104, 196, 43, 64, 130, 243, 166, 101, 110, 106, 90, 99, 35, 22,
    //         252, 199, 151, 78, 161, 206, 49, 46, 5, 128, 31, 134, 132, 223, 96, 168, 227, 220, 219,
    //         130, 173, 24, 139, 110, 74, 72, 207, 75, 127, 168, 180, 145, 188, 212, 152, 250, 126,
    //         94, 254, 236, 194, 144, 207, 255, 40, 251, 25, 126, 227, 58, 128, 95, 51, 165, 5, 59,
    //         206, 2, 1, 0, 0, 0, 0, 0, 0, 0, 178, 131, 88, 147, 161, 129, 31, 8, 112, 76, 214, 42,
    //         4, 129, 124, 223, 141, 10, 217, 200, 244, 62, 39, 158, 187, 220, 59, 185, 230, 198, 99,
    //         7,
    //     ];
    //     let frame = zero_art_proto::Frame::decode(&frame_bytes[..]).unwrap();

    //     // let frame = frame.frame.unwrap();
    //     // frame.group_operation.unwrap();
    // }

    #[test]
    fn test_context_from_tree_secret() {}

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
