use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use tracing::{instrument, trace};
use zrt_art::types::{ARTNode, LeafIter, LeafStatus, PublicART};
use zrt_art::{traits::ARTPrivateAPI, types::PrivateART};
use zrt_crypto::schnorr;

use sha3::Sha3_256;

use crate::error::{Error, Result};
use crate::group_state::GroupState;
use crate::models::frame::{Frame, GroupOperation};
use crate::models::group_info::{GroupInfo, User, public_key_to_id};
use crate::models::payload::Payload;
use crate::utils::{derive_stage_key, encrypt, hkdf, serialize};
use crate::{models, zero_art_proto};
use ark_std::rand::thread_rng;

pub mod operations;
pub mod processing;
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

pub struct GroupContext {
    state: GroupState,
    pending_state: GroupState,

    rng: StdRng,
    identity_key_pair: KeyPair,
}

impl GroupContext {
    pub fn new(identity_secret_key: ScalarField, group_info: GroupInfo) -> Result<(Self, Frame)> {
        let mut context_rng = StdRng::from_rng(thread_rng()).unwrap();

        let leaf_secret = ScalarField::rand(&mut context_rng);
        let (art, tk) =
            PrivateART::new_art_from_secrets(&vec![leaf_secret], &CortadoAffine::generator())?;

        let state = GroupState::from_parts(
            leaf_secret,
            PublicART {
                root: art.root.clone(),
                generator: CortadoAffine::generator(),
            },
            derive_stage_key(&[0u8; 32], tk.key)?,
            0,
            group_info,
            true,
        )?;

        let group_context = Self::from_state(identity_secret_key, state)?;

        let frame = group_context
            .create_frame_tbs(
                &group_context.state,
                vec![],
                Some(GroupOperation::Init(PublicART {
                    root: group_context.state.art.root.clone(),
                    generator: CortadoAffine::generator(),
                })),
                Some(serialize(group_context.identity_key_pair.public_key)?),
            )?
            .prove_schnorr::<Sha3_256>(identity_secret_key)?;

        return Ok((group_context, frame));
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

        let identity_key_pair = KeyPair::from_secret_key(identity_secret_key);

        Ok(GroupContext {
            pending_state: state.clone(),
            state,
            identity_key_pair,
            rng: context_rng,
        })
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
            .create_frame_tbs(&self.state, payloads, None, None)?
            .prove_schnorr::<Sha3_256>(tk.key)?;
        Ok(frame)
    }

    pub fn commit_state(&mut self) {
        self.state = self.pending_state.clone()
    }

    #[instrument(skip_all)]
    fn create_invite(
        &self,
        state: &GroupState,
        invitee: models::invite::Invitee,
        leaf_secret: ScalarField,
        ephemeral_secret_key: ScalarField,
    ) -> Result<models::invite::Invite> {
        trace!("Group state: {:?}", state);
        trace!("Invitee: {:?}", invitee);
        trace!("Leaf secret: {:?}", leaf_secret);
        trace!("Ephemeral secret key: {:?}", ephemeral_secret_key);

        println!("Group state: {:?}", state);
        println!("Invitee: {:?}", invitee);
        println!("Leaf secret: {:?}", leaf_secret);
        println!("Ephemeral secret key: {:?}", ephemeral_secret_key);

        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();
        trace!("Ephemeral public key: {:?}", ephemeral_public_key);

        println!("Ephemeral public key: {:?}", ephemeral_public_key);

        let protected_invite_data =
            models::invite::ProtectedInviteData::new(state.epoch, state.stk, state.group_info.id());

        let invite_encryption_key = hkdf(Some(b"invite-key-derivation"), &serialize(leaf_secret)?)?;
        trace!("Invite encryption key: {:?}", invite_encryption_key);

        println!("Invite encryption key: {:?}", invite_encryption_key);

        println!(
            "Protected invite data: {:?}",
            protected_invite_data.encode_to_vec()
        );

        let encrypted_invite_data = encrypt(
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
        trace!("Invite: {:?}", invite);

        println!("Invite: {:?}", invite);

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
        nonce: Option<Vec<u8>>,
    ) -> Result<models::frame::FrameTbs> {
        let protected_payload_tbs = models::protected_payload::ProtectedPayloadTbs::new(
            0,
            Utc::now(),
            payloads,
            models::protected_payload::Sender::UserId(public_key_to_id(
                self.identity_key_pair.public_key,
            )),
        );
        let protected_payload =
            protected_payload_tbs.sign::<Sha3_256>(self.identity_key_pair.secret_key)?;

        let mut frame_tbs = models::frame::FrameTbs::new(
            state.group_info.id(),
            state.epoch,
            nonce.unwrap_or_default(),
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
}

fn map_users_to_leaf_ids(
    leafs: LeafIter<'_, CortadoAffine>,
    leafs_to_users: HashMap<CortadoAffine, String>,
) -> HashMap<String, usize> {
    leafs
        .filter(|node| match node {
            ARTNode::Leaf { status, .. } => LeafStatus::Blank != *status,
            _ => unreachable!(),
        })
        .enumerate()
        .map(|(i, node)| {
            (
                leafs_to_users
                    .get(match node {
                        ARTNode::Leaf { public_key, .. } => public_key,
                        _ => unreachable!(),
                    })
                    .expect("")
                    .to_string(),
                i,
            )
        })
        .collect::<HashMap<String, usize>>()
}

pub struct PendingGroupContext(GroupContext);

impl PendingGroupContext {
    pub fn process_frame(&mut self, frame: Frame) -> Result<Vec<Payload>> {
        self.0.process_frame(frame)
    }

    pub fn join_group_as(&mut self, mut user: User) -> Result<Frame> {
        let leaf_secret = ScalarField::rand(&mut thread_rng());

        *user.role_mut() = zero_art_proto::Role::Write;

        let group_action_payload = models::payload::Payload::Action(
            models::payload::GroupActionPayload::JoinGroup(user.clone()),
        );

        let frame = self.0.key_update(leaf_secret, vec![group_action_payload])?;

        let temporary_leaf_public_key =
            (CortadoAffine::generator() * self.0.state.art.secret_key).into_affine();
        self.0
            .pending_state
            .group_info
            .members_mut()
            .replace(&public_key_to_id(temporary_leaf_public_key), user);

        Ok(frame)
    }

    pub fn sign_with_tk(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let tk = self.0.state.art.get_root_key()?;
        let tk_public_key = (CortadoAffine::generator() * tk.key).into_affine();
        Ok(schnorr::sign(&vec![tk.key], &vec![tk_public_key], msg)?)
    }

    pub fn upgrade(mut self) -> GroupContext {
        self.0.commit_state();
        self.0
    }

    // Parts
    pub fn into_state(self) -> GroupState {
        self.0.into_state()
    }

    pub fn to_state(&self) -> GroupState {
        self.0.to_state()
    }

    pub fn from_state(identity_secret_key: ScalarField, state: GroupState) -> Result<Self> {
        Ok(Self(GroupContext::from_state(identity_secret_key, state)?))
    }

    pub fn epoch(&self) -> u64 {
        self.0.state.epoch
    }

    pub fn group_info(&self) -> &GroupInfo {
        &self.0.state.group_info
    }
}
