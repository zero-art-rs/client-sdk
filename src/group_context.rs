use std::marker::PhantomData;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, inv};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::{ARTRootKey, BranchChanges, PrivateART},
};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::{CryptoError, x3dh::x3dh_a};

use hkdf::Hkdf;
use prost::{DecodeError, Message};
use sha3::Sha3_256;

use crate::{
    builders,
    zero_art_proto::{self, group_operation::Operation},
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
    AesError,

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

#[derive(Default)]
pub struct GroupContextBuilder<T> {
    identity_key_pair: Option<KeyPair>,
    prekey: Option<KeyPair>,

    _state: PhantomData<T>,
}

impl<S> GroupContextBuilder<S> {
    fn change_state<U>(self) -> GroupContextBuilder<U> {
        GroupContextBuilder {
            identity_key_pair: self.identity_key_pair,
            prekey: self.prekey,
            _state: PhantomData,
        }
    }
}

impl GroupContextBuilder<context_state::Initial> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_identity(mut self, identity_key_pair: KeyPair) -> Self {
        self.identity_key_pair = Some(identity_key_pair);
        self
    }

    pub fn with_prekey(mut self, prekey: KeyPair) -> Self {
        self.prekey = Some(prekey);
        self
    }

    fn fill(&mut self) {
        if self.identity_key_pair.is_none() {
            let secret_key = ScalarField::rand(&mut thread_rng());
            self.identity_key_pair = Some(KeyPair::from_secret_key(secret_key));
        }

        if self.prekey.is_none() {
            let secret_key = ScalarField::rand(&mut thread_rng());
            self.prekey = Some(KeyPair::from_secret_key(secret_key));
        }
    }

    fn from_invite(mut self, invite: &[u8]) -> GroupContextBuilder<context_state::FromInvite> {
        self.fill();
        self.change_state()
    }

    fn create(mut self) -> GroupContextBuilder<context_state::NewGroup> {
        self.fill();
        self.change_state()
    }

    // fn from_art(mut self, a)
}

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

pub struct GroupContext {
    art: PrivateART<CortadoAffine>,
    stk: Box<[u8; 32]>,
    epoch: u64,
    group_id: String,

    identity_secret_key: ScalarField,
    identity_key_pair: KeyPair,
    ephemeral_secret_key: ScalarField,
    ephemeral_key_pair: KeyPair,
}

impl GroupContext {
    pub fn process_frame(&mut self, sp_frame: &[u8]) -> Result<Vec<u8>, SDKError> {
        let sp_frame = zero_art_proto::SpFrame::decode(sp_frame)?;
        let frame = sp_frame.frame.unwrap();
        let frame_tbs = frame.frame.unwrap();

        let epoch = frame_tbs.epoch;
        if self.epoch != epoch || self.epoch != epoch + 1 {
            return Err(SDKError::InvalidEpoch);
        }

        let changes = frame_tbs.group_operation.unwrap();

        match changes.operation.unwrap() {
            Operation::Init(_) => {}
            Operation::AddMember(changes) => self.apply_changes(&changes)?,
            Operation::KeyUpdate(changes) => self.apply_changes(&changes)?,
            Operation::RemoveMember(changes) => self.apply_changes(&changes)?,
            Operation::DropGroup(_) => {}
        }

        self.decrypt_payload(&frame_tbs.protected_payload)
    }

    pub fn add_member(
        &mut self,
        invitation_keys: InvitationKeys,
        payload: &[u8],
    ) -> Result<Vec<u8>, SDKError> {
        let member_leaf_secret = self.compute_leaf_secret_a(invitation_keys)?;

        // Add member leaf to the ART
        let (tk, changes, artefacts) = self.art.append_node(&member_leaf_secret)?;

        let invite_data = builders::ProtectedInviteDataBuilder::new()
            .epoch(self.epoch)
            .group_id(self.group_id.clone())
            .build()
            .encode_to_vec();
        let protected_invite_data = self.encrypt_payload(&invite_data)?;

        // Serialize own public keys
        let mut identity_public_key_bytes = Vec::new();
        self.identity_key_pair.public_key.serialize_compressed(&mut identity_public_key_bytes)?;

        let mut ephemeral_public_key_bytes = Vec::new();
        self.ephemeral_key_pair
            .public_key
            .serialize_compressed(&mut ephemeral_public_key_bytes)?;

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

        match invitation_keys {
            InvitationKeys::Identified {
                identity_public_key: _,
                spk_public_key,
            } => {
                let mut spk_public_key_bytes = Vec::new();
                spk_public_key.serialize_compressed(&mut spk_public_key_bytes)?;

                let identified_invite = identified_invite_builder
                    .spk_public_key(spk_public_key_bytes)
                    .build();
                

            }
            InvitationKeys::Unidentified {
                invitation_secret_key,
            } => {
                let mut invitation_secret_key_bytes = Vec::new();
                invitation_secret_key.serialize_compressed(&mut invitation_secret_key_bytes)?;

                let unidentified_invite = unidentified_invite_builder
                    .private_key(invitation_secret_key_bytes)
                    .build();
            }
        };

        // builders::InviteBuilder::new().invite(invite)

        // let (_, changes_2, artefacts_2) = art_1.append_node_public_art(&some_secret_key1).unwrap();

        // let (tk, changes) = self.art.update_key(&secret)?;
        // self.update_stk(tk)?;

        Ok(vec![])
    }

    pub fn remove_member(&mut self, payload: &[u8]) -> Result<Vec<u8>, SDKError> {
        Ok(vec![])
    }

    pub fn update_secret(
        &mut self,
        secret: ScalarField,
        payload: &[u8],
    ) -> Result<Vec<u8>, SDKError> {
        let (tk, changes, artefacts) = self.art.update_key(&secret)?;
        self.update_stk(tk)?;

        let protected_payload = self.encrypt_payload(payload)?;
        let group_operation = builders::GroupOperationBuilder::new()
            .operation(Operation::KeyUpdate(changes.serialze()?))
            .build();

        let frame_tbs = builders::FrameTbsBuilder::new()
            .epoch(self.epoch)
            .protected_payload(protected_payload)
            .group_operation(group_operation)
            .build();

        Ok(builders::FrameBuilder::new()
            .frame(frame_tbs)
            .proof(vec![])
            .build()
            .encode_to_vec())
    }

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

    fn update_stk(&mut self, tk: ARTRootKey<CortadoAffine>) -> Result<(), SDKError> {
        // self.stk = Key::<Aes256Gcm>::from(hkdf(Some(b"stage-key-derivation"), &serialize_to_vec![tk.key]?)?);

        // Increment epoch
        self.epoch += 1;
        Ok(())
    }

    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>, SDKError> {
        let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), &self.stk[..]);

        // AES 256 key size - 32 bytes, nonce - 12 bytes
        let mut okm = [0u8; 32 + 12];
        h.expand(&[], &mut okm)?;

        let (key, nonce) = (&okm[..32], &okm[32..]);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

        let cipher = Aes256Gcm::new(key);

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SDKError::AesError)
    }

    fn decrypt_payload(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SDKError> {
        let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), &self.stk[..]);

        // AES 256 key size - 32 bytes, nonce - 12 bytes
        let mut okm = [0u8; 32 + 12];
        h.expand(&[], &mut okm)?;

        let (key, nonce) = (&okm[..32], &okm[32..]);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

        let cipher = Aes256Gcm::new(key);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SDKError::AesError)
    }

    fn compute_leaf_secret_a(&self, invitation_keys: InvitationKeys) -> Result<ScalarField, SDKError> {
        // Compute new member leaf secret
        let (identity_public_key, invitation_public_key) = match invitation_keys {
            InvitationKeys::Identified {
                identity_public_key,
                spk_public_key,
            } => (
                identity_public_key,
                spk_public_key.unwrap_or(identity_public_key),
            ),
            InvitationKeys::Unidentified {
                invitation_secret_key,
            } => {
                let invitation_public_key =
                    (CortadoAffine::generator() * invitation_secret_key).into_affine();
                (invitation_public_key, invitation_public_key)
            }
        };
        
        let member_leaf_secret = ScalarField::from_le_bytes_mod_order(&x3dh_a(
            self.identity_secret_key,
            self.ephemeral_secret_key,
            identity_public_key,
            invitation_public_key,
        )?);
        Ok(member_leaf_secret)
    }

    // TODO: compute_leaf_secret_b for acceptor

    // fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    //     let cipher = Aes256Gcm::new(&self.stk);

    //     if encrypted_data.len() < 12 {
    //         return Err(EncryptionError::InvalidFormat);
    //     }

    //     let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    //     let nonce = Nonce::from_slice(nonce_bytes);

    //     let plaintext = cipher
    //         .decrypt(nonce, ciphertext)
    //         .map_err(|_| EncryptionError::DecryptionFailed)?;

    //     Ok(plaintext)
    // }
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

    fn apply_changes(&mut self, changes: &[u8]) -> Result<(), SDKError> {
        let changes = BranchChanges::deserialize(changes)?;
        self.art.update_private_art(&changes)?;
        let tk = self.art.recompute_root_key()?;
        self.stk = Box::new(hkdf(None, &serialize_to_vec![tk.key]?)?);
        Ok(())
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

            match operation {
                Operation::Init(_) => {}
                Operation::AddMember(changes) => self.apply_changes(&changes)?,
                Operation::RemoveMember(changes) => self.apply_changes(&changes)?,
                Operation::KeyUpdate(changes) => self.apply_changes(&changes)?,
                Operation::DropGroup(changes) => self.apply_changes(&changes)?,
            }
        }

        Ok(())
    }

    fn encrypt() {}
    fn decrypt() {}
}

// impl ArtManager {
//     fn from_
// }

fn hkdf(salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    let h = Hkdf::<Sha3_256>::new(salt, &ikm);
    let mut okm = [0u8; 32];
    h.expand(&[], &mut okm)?;
    Ok(okm)
}

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
