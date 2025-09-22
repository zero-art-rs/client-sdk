use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::traits::ARTPublicView;
use art::types::LeafIter;
use art::{
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::{BranchChanges, PrivateART},
};
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::schnorr;

use sha3::Sha3_256;

use crate::error::{Error, Result};
use crate::models::group_info::GroupInfo;
use crate::proof_system::ProofSystem;
use crate::{models, proof_system};
use ark_std::rand::thread_rng;

use thiserror::Error;

pub mod builder;
pub mod operations;
#[cfg(test)]
mod tests;
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
    stk: [u8; 32],
    epoch: u64,
    proof_system: ProofSystem,

    rng: StdRng,

    identity_key_pair: KeyPair,

    group_info: models::group_info::GroupInfo,

    is_last_sender: bool,
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

    pub fn into_parts(
        self,
    ) -> Result<(
        ScalarField,
        Vec<u8>,
        [u8; 32],
        u64,
        models::group_info::GroupInfo,
    )> {
        Ok((
            self.art.secret_key,
            self.art.serialize()?,
            self.stk,
            self.epoch,
            self.group_info,
        ))
    }

    pub fn from_parts(
        identity_secret_key: ScalarField,
        leaf_secret: ScalarField,
        art: &[u8],
        stk: [u8; 32],
        epoch: u64,
        group_info: models::group_info::GroupInfo,
        is_last_sender: bool,
    ) -> Result<Self> {
        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(art, &leaf_secret)?;

        // 1. Init PRNGs
        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        let proof_system = proof_system::ProofSystem::default();

        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        Ok(GroupContext {
            art,
            stk,
            identity_key_pair,
            epoch,
            group_info,
            proof_system,
            rng: context_rng,
            is_last_sender
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

        let invite_leaf_secret = compute_invite_leaf_secret(
            invite.invite_tbs().invitee(),
            identity_secret_key,
            spk_secret_key,
            inviter_public_key,
            ephemeral_public_key,
        )?;

        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(&art, &invite_leaf_secret)?;

        let context_rng = StdRng::from_rng(thread_rng()).unwrap();

        *user.public_key_mut() = identity_key_pair.public_key;

        let invite_encryption_key = crate::utils::hkdf(
            Some(b"invite-key-derivation"),
            &crate::utils::serialize(invite_leaf_secret)?,
        )?;

        let protected_invite_data =
            models::invite::ProtectedInviteData::decode(&crate::utils::decrypt(
                &invite_encryption_key,
                invite.invite_tbs().protected_invite_data(),
                &[],
            )?)?;
        let mut group_info = protected_invite_data.group_info().clone();

        group_info.members_mut().add_user(user.clone());

        let mut group_context = Self {
            art,
            stk: protected_invite_data.stage_key(),
            epoch: protected_invite_data.epoch(),
            proof_system: proof_system::ProofSystem::default(),
            rng: context_rng,
            group_info: group_info,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
            is_last_sender: false
        };

        let leaf_secret = ScalarField::rand(&mut group_context.rng);

        let group_action_payload =
            models::payload::Payload::Action(models::payload::GroupActionPayload::JoinGroup(user));

        let frame = group_context.key_update(leaf_secret, vec![group_action_payload])?;

        Ok((group_context, frame))
    }

    pub fn process_frame(
        &mut self,
        frame: models::frame::Frame,
    ) -> Result<Vec<models::payload::Payload>> {
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

            self.is_last_sender = false;

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

                let owner_public_key = crate::utils::deserialize(frame.frame_tbs().nonce())?;

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

                self.is_last_sender = false;


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

                self.is_last_sender = false;


                let verifier_artefacts = self.art.compute_artefacts_for_verification(&changes)?;

                let old_leaf_public_key = self.art.get_node(&changes.node_index)?.public_key;
                frame.verify_art::<Sha3_256>(
                    &self.proof_system,
                    verifier_artefacts,
                    old_leaf_public_key,
                )?;

                self.art.update_private_art(&changes)?;
                self.advance_epoch()?;

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
        if !self.is_last_sender {
            let leaf_secret = ScalarField::rand(&mut self.rng);
            return self.key_update(leaf_secret, payloads);
        }

        let tk = self.art.get_root_key()?;
        let frame = self
            .create_frame_tbs(payloads, None)?
            .prove_schnorr::<Sha3_256>(tk.key)?;
        Ok(frame)
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

        crate::utils::derive_stage_key(&self.stk, eph_art.get_root_key()?.key)
    }

    fn create_invite(
        &self,
        invitee: models::invite::Invitee,
        leaf_secret: ScalarField,
        ephemeral_secret_key: ScalarField,
    ) -> Result<models::invite::Invite> {
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        let protected_invite_data =
            models::invite::ProtectedInviteData::new(self.epoch, self.stk, self.group_info.clone());

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
        payloads: Vec<models::payload::Payload>,
        group_operation: Option<models::frame::GroupOperation>,
    ) -> Result<models::frame::FrameTbs> {
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
            group_operation,
            vec![],
        );
        let protected_payload = self.encrypt(
            &protected_payload.encode_to_vec(),
            &frame_tbs.associated_data::<Sha3_256>()?,
        )?;
        frame_tbs.set_protected_payload(protected_payload);

        Ok(frame_tbs)
    }

    fn reorder_members(&mut self) {
        let order = LeafIter::new(self.art.get_root())
            .filter(|node| !node.is_blank)
            .map(|node| node.public_key)
            .enumerate()
            .map(|(k, v)| (v, k))
            .collect::<HashMap<CortadoAffine, usize>>();

        self.group_info.members_mut().reindex(order);
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
