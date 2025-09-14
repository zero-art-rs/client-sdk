use std::{collections::HashMap, marker::PhantomData, vec};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, inv};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, PrivateART, ProverArtefacts},
};
use bulletproofs::r1cs::R1CSError;
use chrono::{DateTime, Utc};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::{CryptoError, schnorr, x3dh::x3dh_a};

use hkdf::Hkdf;
use prost::{DecodeError, Message};
use sha3::{Digest, Sha3_256};
use static_assertions::assert_impl_all;
use zk::art::art_prove;

use crate::{
    builders,
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

mod utils;

#[derive(Error, Debug)]
pub enum SDKError {
    #[error("Art logic Error.")]
    ArtError(#[from] ARTError),
    #[error("Art logic Error.")]
    SerializationError(#[from] SerializationError),
    #[error("Art logic Error.")]
    CryptoError(#[from] CryptoError),
    #[error("Art logic Error.")]
    DecodeError(#[from] DecodeError),
    #[error("Art logic Error.")]
    HKDFError(#[from] hkdf::InvalidLength),
    #[error("Art logic Error.")]
    R1CSError(#[from] R1CSError),

    #[error("Art logic Error.")]
    AesError,

    // R1CSError
    #[error("Art logic Error.")]
    ARTLogicError,
    #[error("Invalid input provided")]
    InvalidInput,
    // #[error("Postcard error: {0}")]
    // Postcard(#[from] postcard::Error),
    // #[error("Serde JSON error: {0}")]
    // SerdeJson(#[from] serde_json::Error),
    // #[error("Node error: {0}")]
    // Node(#[from] ARTNodeError),
    #[error("Cant find path to given node.")]
    PathNotExists,
    #[error("Cant remove th node. It isn't close enough.")]
    RemoveError,
    #[error("Failed to convert &[u8] into &[u8;32] {0}")]
    ConversionError(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point")]
    XCoordinateError,
    #[error("No changes provided in given BranchChanges structure")]
    NoChanges,

    #[error("No changes provided in given BranchChanges structure")]
    InvalidEpoch,
}

pub struct KeyPair {
    secret_key: ScalarField,
    public_key: CortadoAffine,
}

impl KeyPair {
    pub fn new() -> Self {
        let secret_key = ScalarField::rand(&mut StdRng::seed_from_u64(rand::random()));
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();

        Self {
            public_key,
            secret_key,
        }
    }

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

pub mod context_state {
    #[derive(Default)]
    pub struct Initial {}
    #[derive(Default)]
    pub struct NewGroup {}
    #[derive(Default)]
    pub struct FromART {}
    #[derive(Default)]
    pub struct FromInvite {}
}

// TODO: Use typestate pattern
// pub enum GroupContextBuilder {
//     Initial {
//         identity_key_pair: Option<KeyPair>,
//         ephemeral_key_pair: Option<KeyPair>,
//         seed: Option<[u8; 32]>,
//     },
//     NewGroup {
//         group_context: GroupContext,
//     },
//     FromInvite {
//         group_context: GroupContext,
//     },
//     FromART {
//         group_context: GroupContext,
//     }
// }

// impl GroupContextBuilder {
//     pub fn new() -> Self {
//         Self::Initial {identity_key_pair: None, ephemeral_key_pair: None, seed: None}
//     }

//     pub fn identity_key_pair(mut self, _identity_key_pair: KeyPair) -> Self {
//         match &mut self {
//             Self::Initial { identity_key_pair, ephemeral_key_pair: _, seed: _ } => {
//                 *identity_key_pair = Some(_identity_key_pair)
//             }
//             _ => {}
//         }

//         self
//     }

//     pub fn ephemeral_key_pair(mut self, _identity_key_pair: KeyPair) -> Self {
//         match &mut self {
//             Self::Initial { identity_key_pair, ephemeral_key_pair: _, seed: _ } => {
//                 *identity_key_pair = Some(_identity_key_pair)
//             }
//             _ => {}
//         }
//         self
//     }

//     pub fn identity_key_pair(mut self, _identity_key_pair: KeyPair) -> Self {
//         match &mut self {
//             Self::Initial { identity_key_pair, ephemeral_key_pair: _, seed: _ } => {
//                 *identity_key_pair = Some(_identity_key_pair)
//             }
//             _ => {}
//         }
//         self
//     }
// }

// HERE BUILDER
// #[derive(Default)]
// pub struct GroupContextBuilder<T> {
//     identity_key_pair: Option<KeyPair>,
//     ephemeral_key_pair: Option<KeyPair>,
//     seed: Option<[u8; 32]>,
//     invitation_keys: Option<Vec<InvitationKeys>>,
//     group_id: Option<String>,

//     _state: PhantomData<T>,
// }

// impl<S> GroupContextBuilder<S> {
//     fn change_state<U>(self) -> GroupContextBuilder<U> {
//         GroupContextBuilder {
//             identity_key_pair: self.identity_key_pair,
//             prekey: self.prekey,
//             _state: PhantomData,
//         }
//     }
// }

// impl GroupContextBuilder<context_state::Initial> {
//     pub fn new() -> Self {
//         Self::default()
//     }

//     pub fn with_identity(mut self, identity_key_pair: KeyPair) -> Self {
//         self.identity_key_pair = Some(identity_key_pair);
//         self
//     }

//     pub fn with_prekey(mut self, prekey: KeyPair) -> Self {
//         self.prekey = Some(prekey);
//         self
//     }

//     fn fill(&mut self) {
//         if self.identity_key_pair.is_none() {
//             let secret_key = ScalarField::rand(&mut thread_rng());
//             self.identity_key_pair = Some(KeyPair::from_secret_key(secret_key));
//         }

//         if self.prekey.is_none() {
//             let secret_key = ScalarField::rand(&mut thread_rng());
//             self.prekey = Some(KeyPair::from_secret_key(secret_key));
//         }
//     }

//     fn from_invite(mut self, invite: &[u8]) -> GroupContextBuilder<context_state::FromInvite> {
//         self.fill();
//         self.change_state()
//     }

//     fn create(mut self) -> GroupContextBuilder<context_state::NewGroup> {
//         self.fill();
//         self.change_state()
//     }

//     // fn from_art(mut self, a)
// }

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

// message GroupInfo {
//   string id = 1; // document id
//   string name = 2; // document name
//   google.protobuf.Timestamp created = 3; // document creation time
//   bytes picture = 4;
//   repeated User members = 10; // membership list of document
// }

// message User {
//   string id = 1; // actor id
//   string name = 2; // user name
//   bytes public_key = 3; // user identity public key
//   bytes picture = 4; // user picture
//   Role role = 5; // user role
// }

pub struct GroupContext {
    art: PrivateART<CortadoAffine>,
    stk: Box<[u8; 32]>,
    epoch: u64,
    group_id: String,
    proof_system: ProofSystem,

    members: HashMap<String, zero_art_proto::User>,

    rng: StdRng,

    identity_key_pair: KeyPair,
    ephemeral_key_pair: KeyPair,

    ready: bool,
}

impl GroupContext {
    // pub fn new(identity_public_key: KeyPair, ephemeral_public_key: Option<KeyPair>, invitation_keys: &[InvitationKeys]) -> Self {

    // }

    // process_frame should:
    // 1. Deserialize SP frame
    // 2. Validate epoch correctness
    // 3. Verify frame proof/signature
    // 4.
    //
    pub fn process_frame(&mut self, sp_frame: &[u8]) -> Result<Vec<u8>, SDKError> {
        // 1. Deserialize SP frame
        let sp_frame = zero_art_proto::SpFrame::decode(sp_frame)?;
        let mut frame = sp_frame.frame.ok_or(SDKError::InvalidInput)?;

        // Strip proof/signature
        let proof = std::mem::take(&mut frame.proof);
        let frame_serialized_content = frame.encode_to_vec();

        let mut frame_tbs = frame.frame.ok_or(SDKError::InvalidInput)?;

        // Strip protected payload
        let protected_payload = std::mem::take(&mut frame_tbs.protected_payload);

        // Validate that frame belong to this group
        if frame_tbs.group_id != self.group_id {
            return Err(SDKError::InvalidInput);
        }

        // 2. Validate epoch correctness
        let epoch = frame_tbs.epoch;
        if self.epoch != epoch || self.epoch != epoch + 1 {
            return Err(SDKError::InvalidEpoch);
        }

        // 3. Verify frame proof/signature
        // TODO: Verify proof only for ART ops, Init and DropGroup have signature, not proof
        if frame_tbs.group_operation.is_none() {
            let tk = self.art.recompute_root_key()?;
            let ptk = (tk.generator * tk.key).into_affine();
            // TODO: Custom error?
            schnorr::verify(&proof, &vec![ptk], &frame_serialized_content)?;

            // Decrypt protected payload and return
            let payload = self.decrypt(&protected_payload, &frame_tbs.encode_to_vec())?;

            let mut payload = zero_art_proto::ProtectedPayload::decode(&payload[..])?;

            // Strip payload signature
            let signature = std::mem::take(&mut payload.signature);
            let payload_tbs = payload.payload.ok_or(SDKError::InvalidInput)?;
            match payload_tbs.sender.ok_or(SDKError::InvalidInput)? {
                protected_payload_tbs::Sender::UserId(id) => {
                    let sender = self.members.get(&id).ok_or(SDKError::InvalidInput)?;
                    let sender_public_key =
                        CortadoAffine::deserialize_uncompressed(&sender.public_key[..])?;

                    schnorr::verify(
                        &signature,
                        &vec![sender_public_key],
                        &payload_tbs.encode_to_vec(),
                    )?;
                }
                protected_payload_tbs::Sender::LeafId(_) => {}
            };

            return Ok(vec![]);
        }

        let changes = frame_tbs.group_operation.unwrap();

        match changes.operation.unwrap() {
            Operation::Init(_) => {}
            Operation::AddMember(changes) => self.apply_changes(&changes)?,
            Operation::KeyUpdate(changes) => self.apply_changes(&changes)?,
            Operation::RemoveMember(changes) => self.apply_changes(&changes)?,
            Operation::DropGroup(_) => {}
        }

        self.decrypt(&frame_tbs.protected_payload, b"")
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
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SDKError> {
        // 1. Compute new member's leaf secret
        let member_leaf_secret = self.compute_member_leaf_secret(invitation_keys)?;

        // 2. Add node to ART and recompute STK
        let (_, changes, artefacts) = self.art.append_node(&member_leaf_secret)?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::AddMember(changes.serialze()?))
            .build();
        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_id.clone())
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
        let proof = self
            .proof_system
            // review this
            .prove(artefacts, &vec![self.art.secret_key], &frame_digest)?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof.serialize_uncompressed(&mut proof_bytes)?;

        frame.proof = proof_bytes;

        // 6. Create and Sign invite
        let mut invite = self.create_invite(invitation_keys)?;
        let signature = schnorr::sign(
            &vec![self.identity_key_pair.secret_key],
            &vec![self.identity_key_pair.public_key],
            &invite.encode_to_vec(),
        )?;

        invite.signature = signature;

        Ok((frame.encode_to_vec(), invite.encode_to_vec()))
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
        let (_, changes, artefacts) = self.art.make_blank(&public_key, &temporary_leaf_secret)?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::AddMember(changes.serialze()?))
            .build();
        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_id.clone())
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
    ) -> Result<Vec<u8>, SDKError> {
        // 1. Update own leaf with provided secret and recompute STK
        let old_secret = self.art.secret_key;

        let (_, changes, artefacts) = self.art.update_key(&leaf_secret)?;
        self.advance_epoch()?;

        // 3. Create frame without encrypted payload
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::AddMember(changes.serialze()?))
            .build();
        let mut frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_id.clone())
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

        Ok(frame.encode_to_vec())
    }

    // Create unsigned invite
    fn create_invite(&self, invitation_keys: InvitationKeys) -> Result<Invite, SDKError> {
        let invite_data = builders::ProtectedInviteDataBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_id.clone())
            .build()
            .encode_to_vec();
        let protected_invite_data = self.encrypt(&invite_data, b"")?;

        // Serialize own public keys
        let mut identity_public_key_bytes = Vec::new();
        self.identity_key_pair
            .public_key
            .serialize_uncompressed(&mut identity_public_key_bytes)?;

        let mut ephemeral_public_key_bytes = Vec::new();
        self.ephemeral_key_pair
            .public_key
            .serialize_uncompressed(&mut ephemeral_public_key_bytes)?;

        // TODO: Make one builder for both invites
        // Prepare invite builders
        let identified_invite_builder = builders::IdentifiedInviteBuilder::new()
            .identity_public_key(identity_public_key_bytes.clone())
            .ephemeral_public_key(ephemeral_public_key_bytes.clone())
            .protected_invite_data(protected_invite_data.clone());
        let unidentified_invite_builder = builders::UnidentifiedInviteBuilder::new()
            .identity_public_key(identity_public_key_bytes)
            .ephemeral_public_key(ephemeral_public_key_bytes)
            .protected_invite_data(protected_invite_data);

        // Create enum Invite
        let invite = match invitation_keys {
            InvitationKeys::Identified {
                identity_public_key: _,
                spk_public_key,
            } => {
                let mut spk_public_key_bytes = Vec::new();
                spk_public_key.serialize_uncompressed(&mut spk_public_key_bytes)?;

                let identified_invite = identified_invite_builder
                    .spk_public_key(spk_public_key_bytes)
                    .build();
                zero_art_proto::invite::Invite::IdentifiedInvite(identified_invite)
            }
            InvitationKeys::Unidentified {
                invitation_secret_key,
            } => {
                let mut invitation_secret_key_bytes = Vec::new();
                invitation_secret_key.serialize_uncompressed(&mut invitation_secret_key_bytes)?;

                let unidentified_invite = unidentified_invite_builder
                    .private_key(invitation_secret_key_bytes)
                    .build();
                zero_art_proto::invite::Invite::UnidentifiedInvite(unidentified_invite)
            }
        };

        Ok(builders::InviteBuilder::new().invite(invite).build())
    }

    pub fn create_frame() {}

    fn apply_changes(&mut self, changes: &[u8]) -> Result<(), SDKError> {
        self.art
            .update_private_art(&BranchChanges::deserialize(changes)?)?;
        let tk = self.art.recompute_root_key()?;

        // Derive new stage key
        // TODO: Concat with stk
        // self.stk = Key::<Aes256Gcm>::from(hkdf(Some(b"stage-key-derivation"), &serialize_to_vec![tk.key]?)?);

        // Increment epoch
        self.epoch += 1;
        Ok(())
    }
}

// impl GroupContextBuilder<context_state::WithIdentity> {
//     fn new_with_identity(identity_key_pair: KeyPair) -> Self {
//         let mut this = Self::default();
//         this.identity_key_pair = Some(identity_key_pair);
//         this
//     }
// }

// impl GroupContextBuilder<context_state::WithPrekey> {
//     fn new_with_identity(identity_key_pair: KeyPair) -> Self {
//         let mut this = Self::default();
//         this.identity_key_pair = Some(identity_key_pair);
//         this
//     }

//     fn with_prekey(mut self, prekey: KeyPair) -> GroupContextBuilder<context_state::WithPrekey> {
//         self.prekey = Some(prekey);
//         self.change_state()
//     }
// }

pub struct ArtManager {
    art: PrivateART<CortadoAffine>,
    stk: Box<[u8; 32]>,
    epoch: usize,
}

impl ArtManager {
    pub fn new(
        owner_key_pair: KeyPair,
        eph_key_pair: KeyPair,
        leaf_secret: ScalarField,
        identified_keys: Vec<IdentifiedPublicKeys>,
        unidentified_key_pairs: Vec<KeyPair>,
    ) {
        let mut identified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(identified_keys.len());
        let mut unidentified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(unidentified_key_pairs.len());

        for IdentifiedPublicKeys {
            identity_public_key,
            invitation_public_key,
        } in identified_keys.iter()
        {
            let leaf_secret = ScalarField::from_le_bytes_mod_order(
                &x3dh_a::<CortadoAffine>(
                    owner_key_pair.secret_key,
                    eph_key_pair.secret_key,
                    identity_public_key.clone(),
                    invitation_public_key.clone(),
                )
                .unwrap(),
            );

            identified_leaf_secrets.push(leaf_secret);
        }

        for KeyPair { public_key, .. } in unidentified_key_pairs.iter() {
            let leaf_secret = ScalarField::from_le_bytes_mod_order(
                &x3dh_a::<CortadoAffine>(
                    owner_key_pair.secret_key,
                    eph_key_pair.secret_key,
                    public_key.clone(),
                    public_key.clone(),
                )
                .unwrap(),
            );

            unidentified_leaf_secrets.push(leaf_secret);
        }

        // println!("{:?}", identified_keys);
        // Self { art: (), stk: (), epoch: () }
    }

    fn process_frame(&mut self, frame: zero_art_proto::Frame) -> Result<(), SDKError> {
        if frame.frame.is_none() {
            // return error
            return Ok(());
        }

        // TODO: proof

        let frame = frame.frame.unwrap();

        if frame.group_operation.is_some() {
            let grp_operation = frame.group_operation.unwrap();

            let operation = grp_operation.operation.unwrap();

            // match operation {
            //     Operation::Init(_) => {}
            //     Operation::AddMember(changes) => self.apply_changes(&changes)?,
            //     Operation::RemoveMember(changes) => self.apply_changes(&changes)?,
            //     Operation::KeyUpdate(changes) => self.apply_changes(&changes)?,
            //     Operation::DropGroup(_) => self.apply_changes(&changes)?,
            // }
        }

        Ok(())
    }

    fn encrypt() {}
    fn decrypt() {}
}

// impl ArtManager {
//     fn from_
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_context() {}

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
