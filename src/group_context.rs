use std::{collections::HashMap, marker::PhantomData, vec};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, inv};
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use ark_std::{UniformRand, rand::Rng};
use art::types::PublicART;
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
use sha3::{Digest, Sha3_256};
use static_assertions::assert_impl_all;
use zk::art::art_prove;

use crate::group_context::utils::{decrypt, derive_stage_key};
use crate::proof_system;
use crate::{
    builders, metadata,
    proof_system::ProofSystem,
    zero_art_proto::{
        self, GroupOperation, Invite, group_operation::Operation, protected_payload_tbs,
    },
};
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
mod utils;

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

    rng: StdRng,

    identity_key_pair: KeyPair,

    this_id: String,
    metadata: metadata::group::GroupInfo,
}

impl GroupContext {
    pub fn into_parts(self) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u64, Vec<u8>), SDKError> {
        let mut leaf_secret = Vec::new();
        self.art.secret_key.serialize_uncompressed(&mut leaf_secret)?;
        let art = self.art.serialize()?;
        let stk = self.stk.to_vec();
        let metadata = self.metadata.to_proto_bytes();
        Ok((leaf_secret, art, stk, self.epoch, metadata))
    }

    pub fn from_parts(identity_secret_key: ScalarField, leaf_secret: ScalarField, art: &[u8], stk: [u8; 32], epoch: u64, group_info: metadata::group::GroupInfo) -> Result<Self, SDKError> {
        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(art, &leaf_secret)?;

        // 1. Init PRNGs
        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        let proof_system = proof_system::ProofSystem::default();

        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        let this_id = group_info
            .members
            .iter()
            .filter(|(_, user)| user.public_key == identity_key_pair.public_key)
            .take(1)
            .map(|(id, _)| id.clone())
            .collect();

        Ok(GroupContext {
            art,
            stk: Box::new(stk),
            identity_key_pair,
            epoch,
            metadata: group_info,
            proof_system,
            rng: context_rng,
            this_id,
        })
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
    ) -> Result<Vec<zero_art_proto::Payload>, SDKError> {
        let frame = sp_frame.frame.ok_or(SDKError::InvalidInput)?;

        // Frame
        let mut frame_tbs = frame.frame.ok_or(SDKError::InvalidInput)?;
        let frame_tbs_digest = Sha3_256::digest(frame_tbs.encode_to_vec());
        let proof = frame.proof;

        // FrameTbs
        let protected_payload = std::mem::take(&mut frame_tbs.protected_payload);
        let associated_data = Sha3_256::digest(frame_tbs.encode_to_vec());

        // Validate that frame belong to this group
        let group_id = frame_tbs.group_id;
        if group_id != self.metadata.id {
            return Err(SDKError::InvalidInput);
        }

        // 2. Validate epoch correctness
        let epoch = frame_tbs.epoch;
        if self.epoch != epoch && self.epoch != epoch + 1 {
            return Err(SDKError::InvalidEpoch);
        }

        let group_operation = frame_tbs.group_operation.clone();

        // Get stage key that will be used to decrypt protected payload to know if user is eligible for such actions

        let (stage_key, branch_changes) = if let Some(group_operation) = group_operation.clone() {
            let branch_changes = match group_operation.operation.ok_or(SDKError::InvalidInput)? {
                Operation::AddMember(changes) => Some(BranchChanges::deserialize(&changes)?),
                Operation::RemoveMember(changes) => Some(BranchChanges::deserialize(&changes)?),
                Operation::KeyUpdate(changes) => Some(BranchChanges::deserialize(&changes)?),
                _ => None,
            };

            if let Some(branch_changes) = branch_changes {
                let mut art_clone = self.art.clone();
                art_clone.update_private_art(&branch_changes)?;
                let tree_key = art_clone.get_root_key()?;
                let stage_key = derive_stage_key(&self.stk, tree_key.key)?;
                (stage_key, Some(branch_changes))
            } else {
                (*self.stk, None)
            }
        } else {
            (*self.stk, None)
        };

        // Decrypt protected payload
        let protected_payload_bytes = decrypt(&stage_key, &protected_payload, &associated_data)?;
        let protected_payload =
            zero_art_proto::ProtectedPayload::decode(&protected_payload_bytes[..])?;
        let protected_payload_tbs = protected_payload.payload.ok_or(SDKError::InvalidInput)?;

        let sender = match protected_payload_tbs.sender.ok_or(SDKError::InvalidInput)? {
            protected_payload_tbs::Sender::UserId(id) => self
                .metadata
                .members
                .get(&id)
                .ok_or(SDKError::InvalidInput)?,
            protected_payload_tbs::Sender::LeafId(_) => return Err(SDKError::InvalidInput),
        };

        // TODO: Verify that owner do AddMember or RemoveMember
        // TODO: Verify proof
        // if *self.stk == stage_key {
        //     schnorr::verify(
        //         &protected_payload.signature,
        //         &vec![sender.public_key],
        //         &Sha3_256::digest(protected_payload_tbs.encode_to_vec()),
        //     )?;
        // }

        if sender.public_key == self.identity_key_pair.public_key {
            return Ok(vec![]);
        }

        if *self.stk == stage_key {
            self.art.update_private_art(&branch_changes.unwrap())?;
            self.advance_epoch()?;
        }

        Ok(protected_payload_tbs.payload)
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
        invitation_keys: InvitationKeys,
        mut payloads: Vec<zero_art_proto::Payload>,
    ) -> Result<(zero_art_proto::Frame, zero_art_proto::Invite), SDKError> {
        let ephemeral_secret_key = ScalarField::rand(&mut self.rng);
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        // 1. Compute new member's leaf secret
        let leaf_secret = self.compute_member_leaf_secret(ephemeral_secret_key, invitation_keys)?;

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
                        self.metadata.to_proto(),
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
                self.this_id.clone(),
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
            .group_id(self.metadata.id.clone())
            .group_operation(group_operation)
            .build();

        // 4. Encrypt provided payload and attach to frame
        let protected_payload =
            self.encrypt(&payload.encode_to_vec(), &frame_tbs.encode_to_vec())?;
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
        let mut invite = self.create_invite(ephemeral_public_key, invitation_keys)?;
        let signature = schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            &Sha3_256::digest(invite.encode_to_vec()),
        )?;

        invite.signature = signature;

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
            .group_id(self.metadata.id.clone())
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
                self.this_id.clone(),
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
            .group_id(self.metadata.id.clone())
            .nonce(nonce.into())
            .build();

        let protected_payload = self.encrypt(
            &payload.encode_to_vec(),
            &Sha3_256::digest(frame_tbs.encode_to_vec()),
        )?;
        frame_tbs.protected_payload = protected_payload;

        // 4. Build and sign (with tree key) frame
        let tk = self.art.get_root_key()?;
        let proof = schnorr::sign(
            &vec![tk.key],
            &vec![(tk.generator * tk.key).into_affine()],
            &Sha3_256::digest(frame_tbs.encode_to_vec()),
        )?;

        let frame = builders::FrameBuilder::new()
            .frame(frame_tbs)
            .proof(proof)
            .build();
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
        payload: &[u8],
    ) -> Result<zero_art_proto::Frame, SDKError> {
        // 1. Update own leaf with provided secret and recompute STK
        let old_secret = self.art.secret_key;

        let (_, changes, artefacts) = self.art.update_key(&leaf_secret)?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::KeyUpdate(changes.serialze()?))
            .build();

        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.metadata.id.clone())
            .group_operation(group_operation)
            .build();

        // 4. Encrypt provided payload and attach to frame
        let protected_payload = self.encrypt(payload, &frame_tbs.encode_to_vec())?;
        frame_tbs.protected_payload = protected_payload;

        let mut frame = builders::FrameBuilder::new().frame(frame_tbs).build();

        // 4. Generate proof for ART change with SHA3-256(frame) in associated data

        // Calculate SHA3-256 digest of frame
        let frame_digest = Sha3_256::digest(frame.encode_to_vec());

        // Prove changes
        let proof = self
            .proof_system
            .prove(artefacts, &vec![old_secret], &frame_digest)?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes)?;

        frame.proof = proof_bytes;

        Ok(frame)
    }

    // Create unsigned invite
    fn create_invite(
        &self,
        ephemeral_public_key: CortadoAffine,
        invitation_keys: InvitationKeys,
    ) -> Result<Invite, SDKError> {
        let invite_data = builders::ProtectedInviteDataBuilder::new()
            .epoch(self.epoch)
            .group_id(self.metadata.id.clone())
            .stage_key(self.stk.to_vec())
            .build()
            .encode_to_vec();
        let protected_invite_data = self.encrypt(&invite_data, b"")?;

        // Serialize own public keys
        let mut identity_public_key_bytes = Vec::new();
        self.identity_key_pair
            .public_key
            .serialize_uncompressed(&mut identity_public_key_bytes)?;

        let mut ephemeral_public_key_bytes = Vec::new();
        ephemeral_public_key.serialize_uncompressed(&mut ephemeral_public_key_bytes)?;

        // Prepare invite builders
        let invite_tbs = builders::InviteTbsBuilder::new()
            .identity_public_key(identity_public_key_bytes)
            .ephemeral_public_key(ephemeral_public_key_bytes)
            .protected_invite_data(protected_invite_data);

        // Create enum Invite
        let invite_tbs = match invitation_keys {
            InvitationKeys::Identified {
                identity_public_key,
                spk_public_key,
            } => {
                let mut identity_public_key_bytes = Vec::new();
                identity_public_key.serialize_uncompressed(&mut identity_public_key_bytes)?;

                let mut spk_public_key_bytes = Vec::new();
                spk_public_key.serialize_uncompressed(&mut spk_public_key_bytes)?;

                let identified_invite = builders::IdentifiedInviteBuilder::new()
                    .identity_public_key(identity_public_key_bytes)
                    .spk_public_key(spk_public_key_bytes)
                    .build();

                invite_tbs
                    .invite(zero_art_proto::invite_tbs::Invite::IdentifiedInvite(
                        identified_invite,
                    ))
                    .build()
            }
            InvitationKeys::Unidentified {
                invitation_secret_key,
            } => {
                let mut invitation_secret_key_bytes = Vec::new();
                invitation_secret_key.serialize_uncompressed(&mut invitation_secret_key_bytes)?;

                let unidentified_invite = builders::UnidentifiedInviteBuilder::new()
                    .private_key(invitation_secret_key_bytes)
                    .build();
                invite_tbs
                    .invite(zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(
                        unidentified_invite,
                    ))
                    .build()
            }
        };

        Ok(builders::InviteBuilder::new().invite(invite_tbs).build())
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
}

// pub fn invite_to_challenge() ->

// pub fn verify_invite(invite: zero_art_proto::Invite) {
//     if invite;

//     let signature = invite.signature;

// }

#[cfg(test)]
mod tests {
    use crate::secrets_factory;

    use super::*;

    #[test]
    fn test_new_context() {
        let mut secrets_factory = secrets_factory::SecretsFactory::default();
        let (identity_public_key, identity_secret_key) =
            secrets_factory.generate_secret_with_public_key();
        let leaf_secret = secrets_factory.generate_secret();

        let user = metadata::user::User::new("id1".to_string(), "user1".to_string(), vec![], identity_public_key);
        let group_info = metadata::group::GroupInfoBuilder::new()
            .id(uuid::Uuid::new_v4().to_string())
            .name("group1".to_string())
            .build();

        let (identified_public_key_1, identified_secret_key_1) =
            secrets_factory.generate_secret_with_public_key();
        let (spk_public_key_1, spk_secret_key_1) =
            secrets_factory.generate_secret_with_public_key();

        let (mut group_context, frame, identified_invites, unidentified_invites) =
            builder::GroupContextBuilder::new(identity_secret_key)
                .create(leaf_secret, user, group_info)
                .unidentified_members_count(2)
                .identified_members_keys(vec![(identified_public_key_1, Some(spk_public_key_1))])
                .build()
                .unwrap();

        group_context
            .process_frame(zero_art_proto::SpFrame {
                seq_num: 0,
                created: None,
                frame: Some(frame),
            })
            .unwrap();
    }

    #[test]
    fn test_create_group() {}

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
