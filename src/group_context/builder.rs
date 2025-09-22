use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{SeedableRng, rngs::StdRng, thread_rng};
use art::types::{PrivateART, PublicART};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::{
    schnorr,
    x3dh::{x3dh_a, x3dh_b},
};
use prost::Message;
use sha3::{Digest, Sha3_256};

use crate::{
    error::Result,
    group_context::{Error, GroupContext, KeyPair},
    models, proof_system,
    utils::serialize,
    zero_art_proto,
};

pub struct GroupContextBuilder;

impl GroupContextBuilder {
    pub fn new(identity_secret_key: ScalarField) -> InitialGroupContextBuilder {
        InitialGroupContextBuilder {
            identity_secret_key,
            context_prng_seed: None,
            proof_system_prng_seed: None,
        }
    }
}

pub struct InitialGroupContextBuilder {
    identity_secret_key: ScalarField,
    context_prng_seed: Option<[u8; 32]>,
    proof_system_prng_seed: Option<[u8; 32]>,
}

impl InitialGroupContextBuilder {
    pub fn context_prng_seed(mut self, seed: [u8; 32]) -> Self {
        self.context_prng_seed = Some(seed);
        self
    }

    pub fn proof_system_prng_seed(mut self, seed: [u8; 32]) -> Self {
        self.proof_system_prng_seed = Some(seed);
        self
    }

    pub fn create(
        self,
        user: models::group_info::User,
        group_info: models::group_info::GroupInfo,
    ) -> CreateGroupContextBuilder {
        CreateGroupContextBuilder {
            init: self,
            user,
            group_info,
            identified_members_keys: Vec::new(),
            unidentified_members_count: 0,
            payloads: Vec::new(),
        }
    }

    pub fn from_art(
        self,
        art: &[u8],
        leaf_secret: ScalarField,
        stk: [u8; 32],
        epoch: u64,
        group_info: models::group_info::GroupInfo,
        is_last_sender: bool,
    ) -> Result<GroupContext> {
        let art: PrivateART<CortadoAffine> = PrivateART::deserialize(art, &leaf_secret)?;

        // 1. Init PRNGs
        let context_rng = if self.context_prng_seed.is_none() {
            StdRng::from_rng(thread_rng()).unwrap()
        } else {
            StdRng::from_seed(self.context_prng_seed.unwrap())
        };

        let proof_system = if self.proof_system_prng_seed.is_none() {
            proof_system::ProofSystem::default()
        } else {
            proof_system::ProofSystem::new(self.proof_system_prng_seed.unwrap())
        };

        let identity_key_pair = KeyPair::from_secret_key(self.identity_secret_key);

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
        self,
        leaf_secret: ScalarField,
        invite: zero_art_proto::Invite,
        user: models::group_info::User,
    ) -> Result<FromInviteGroupContextBuilder> {
        if invite.invite.is_none() {
            return Err(Error::InvalidInput);
        }

        let invite_tbs = invite.invite.clone().ok_or(Error::InvalidInput)?;
        let inviter_public_key: CortadoAffine =
            crate::utils::deserialize(&invite_tbs.identity_public_key)?;
        schnorr::verify(
            &invite.signature,
            &vec![inviter_public_key],
            &Sha3_256::digest(invite_tbs.encode_to_vec()),
        )?;

        Ok(FromInviteGroupContextBuilder {
            init: self,
            leaf_secret,
            invite,
            user,
            spk_secret_key: None,
        })
    }
}

pub struct CreateGroupContextBuilder {
    init: InitialGroupContextBuilder,
    user: models::group_info::User,
    group_info: models::group_info::GroupInfo,
    identified_members_keys: Vec<(CortadoAffine, Option<CortadoAffine>)>,
    unidentified_members_count: usize,
    payloads: Vec<models::payload::Payload>,
}

impl CreateGroupContextBuilder {
    pub fn identified_members_keys(
        mut self,
        identified_members_keys: Vec<(CortadoAffine, Option<CortadoAffine>)>,
    ) -> Self {
        self.identified_members_keys = identified_members_keys;
        self
    }

    pub fn push_identified_member_keys(
        &mut self,
        identity_public_key: CortadoAffine,
        spk_public_key: Option<CortadoAffine>,
    ) {
        self.identified_members_keys
            .push((identity_public_key, spk_public_key));
    }

    pub fn payloads(mut self, payloads: Vec<models::payload::Payload>) -> Self {
        self.payloads = payloads;
        self
    }

    pub fn push_payload(&mut self, payload: models::payload::Payload) {
        self.payloads.push(payload);
    }

    pub fn unidentified_members_count(mut self, unidentified_members_count: usize) -> Self {
        self.unidentified_members_count = unidentified_members_count;
        self
    }

    pub fn build(
        self,
    ) -> Result<(
        GroupContext,
        models::frame::Frame,
        HashMap<CortadoAffine, models::invite::Invite>,
        Vec<models::invite::Invite>,
    )> {
        // 1. Init PRNGs
        let mut context_rng = if self.init.context_prng_seed.is_none() {
            StdRng::from_rng(thread_rng()).unwrap()
        } else {
            StdRng::from_seed(self.init.context_prng_seed.unwrap())
        };

        let proof_system = self
            .init
            .proof_system_prng_seed
            .map(|seed| proof_system::ProofSystem::new(seed))
            .unwrap_or_default();

        // 2. Compute identity and ephemeral public keys
        let identity_secret_key = self.init.identity_secret_key;
        let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

        let ephemeral_secret_key = ScalarField::rand(&mut context_rng);

        // 3. Prepare buffers for invites
        let identified_members_keys = self.identified_members_keys;
        let unidentified_members_count = self.unidentified_members_count;
        let mut identified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(identified_members_keys.len());
        let mut unidentified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(unidentified_members_count);

        let mut unidentified_secret_keys: Vec<ScalarField> =
            Vec::with_capacity(unidentified_members_count);

        let mut identified_invites: HashMap<CortadoAffine, models::invite::Invite> =
            HashMap::with_capacity(identified_members_keys.len());
        let mut unidentified_invites: Vec<models::invite::Invite> =
            Vec::with_capacity(unidentified_members_count);

        // 4. Compute identified members leaf secrets
        for &(identity_public_key, spk) in identified_members_keys.iter() {
            let spk = spk.unwrap_or(identity_public_key);
            let leaf_secret = ScalarField::from_le_bytes_mod_order(&x3dh_a::<CortadoAffine>(
                identity_secret_key,
                ephemeral_secret_key,
                identity_public_key,
                spk,
            )?);

            identified_leaf_secrets.push(leaf_secret);
        }

        // 5. Compute unidentified members leaf secrets
        for _ in 0..unidentified_members_count {
            let secret_key = ScalarField::rand(&mut context_rng);
            unidentified_secret_keys.push(secret_key);

            let public_key = (CortadoAffine::generator() * secret_key).into_affine();
            let leaf_secret = ScalarField::from_le_bytes_mod_order(&x3dh_a::<CortadoAffine>(
                identity_secret_key,
                ephemeral_secret_key,
                public_key,
                public_key,
            )?);

            unidentified_leaf_secrets.push(leaf_secret);
        }

        // 6. Build ART
        let leaf_secret = ScalarField::rand(&mut context_rng);
        let (art, tk) = PrivateART::new_art_from_secrets(
            &vec![
                vec![leaf_secret],
                identified_leaf_secrets,
                unidentified_leaf_secrets.clone(),
            ]
            .concat(),
            &CortadoAffine::generator(),
        )?;

        // 7. Derive first stage key
        let stk = crate::utils::hkdf(
            Some(b"stage-key-derivation"),
            &vec![&vec![0u8; 32][..], &serialize(tk.key)?].concat(),
        )?;

        // 8. Form initial metadata
        let mut user = self.user;
        let mut group_info = self.group_info;
        *user.public_key_mut() = identity_public_key;
        group_info.members_mut().add_user(user);

        let _epoch = 0;

        // 9. Build group context
        let group_context = GroupContext {
            art,
            epoch: 0,
            stk,
            rng: context_rng,
            proof_system,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
            group_info: group_info.clone(),
            is_last_sender: true,
        };

        // 9. Create invitations
        for (invitee_public_key, spk_public_key) in identified_members_keys {
            let invitee = models::invite::Invitee::Identified {
                identity_public_key: invitee_public_key,
                spk_public_key,
            };
            let leaf_secret =
                group_context.compute_leaf_secret_for_invitee(invitee, ephemeral_secret_key)?;
            let invite = group_context.create_invite(invitee, leaf_secret, ephemeral_secret_key)?;

            identified_invites.insert(invitee_public_key, invite);
        }

        for secret_key in unidentified_leaf_secrets {
            let invitee = models::invite::Invitee::Unidentified(secret_key);
            let leaf_secret =
                group_context.compute_leaf_secret_for_invitee(invitee, ephemeral_secret_key)?;
            let invite = group_context.create_invite(invitee, leaf_secret, ephemeral_secret_key)?;

            unidentified_invites.push(invite);
        }

        let init_payload_bytes = models::payload::Payload::Action(
            models::payload::GroupActionPayload::Init(group_info.clone()),
        );

        let mut payloads = self.payloads;
        payloads.push(init_payload_bytes);

        // TODO: Add Init with PublicART
        let frame = group_context
            .create_frame_tbs(payloads, None)?
            .prove_schnorr::<Sha3_256>(identity_secret_key)?;

        Ok((
            group_context,
            frame,
            identified_invites,
            unidentified_invites,
        ))
    }
}

pub struct FromInviteGroupContextBuilder {
    init: InitialGroupContextBuilder,
    leaf_secret: ScalarField,
    user: models::group_info::User,
    invite: zero_art_proto::Invite,
    spk_secret_key: Option<ScalarField>,
}

impl FromInviteGroupContextBuilder {
    pub fn spk_secret_key(mut self, spk_secret_key: ScalarField) -> Self {
        self.spk_secret_key = Some(spk_secret_key);
        self
    }

    fn compute_invite_leaf_secret(&mut self) -> Result<ScalarField> {
        let invite_tbs = self.invite.clone().invite.ok_or(Error::InvalidInput)?;
        let inviter_public_key = crate::utils::deserialize(&invite_tbs.identity_public_key)?;
        let ephemeral_public_key = crate::utils::deserialize(&invite_tbs.ephemeral_public_key)?;

        let invite_leaf_secret = match invite_tbs.invite.ok_or(Error::InvalidInput)? {
            zero_art_proto::invite_tbs::Invite::IdentifiedInvite(_) => {
                let spk_secret_key = self.spk_secret_key.unwrap_or(self.init.identity_secret_key);
                // TODO: Verify spk
                ScalarField::from_le_bytes_mod_order(&x3dh_b::<CortadoAffine>(
                    self.init.identity_secret_key,
                    spk_secret_key,
                    inviter_public_key,
                    ephemeral_public_key,
                )?)
            }
            zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(inv) => {
                let temporary_secret_key = crate::utils::deserialize(&inv.private_key)?;

                ScalarField::from_le_bytes_mod_order(&x3dh_b::<CortadoAffine>(
                    temporary_secret_key,
                    temporary_secret_key,
                    inviter_public_key,
                    ephemeral_public_key,
                )?)
            }
        };

        Ok(invite_leaf_secret)
    }

    pub fn create_signature(&self) {
        // sign challenge for SP to get art
    }

    pub fn build(
        mut self,
        art: PublicART<CortadoAffine>,
        invite_frame: zero_art_proto::Frame,
    ) -> Result<()> {
        // 1. Init PRNGs
        let mut context_rng = if self.init.context_prng_seed.is_none() {
            StdRng::from_rng(thread_rng()).unwrap()
        } else {
            StdRng::from_seed(self.init.context_prng_seed.unwrap())
        };

        let proof_system = if self.init.proof_system_prng_seed.is_none() {
            proof_system::ProofSystem::default()
        } else {
            proof_system::ProofSystem::new(self.init.proof_system_prng_seed.unwrap())
        };

        let inviter_leaf_secret = self.compute_invite_leaf_secret()?;

        let inviter_leaf_secret_bytes = crate::utils::serialize(inviter_leaf_secret)?;

        let invite_tbs = self.invite.clone().invite.ok_or(Error::InvalidInput)?;

        let protected_invite_data = crate::utils::decrypt(
            &inviter_leaf_secret_bytes.try_into().unwrap(),
            &invite_tbs.protected_invite_data,
            &[],
        )?;

        let protected_invite_data =
            zero_art_proto::ProtectedInviteData::decode(&protected_invite_data[..])?;

        let stage_key: [u8; 32] = protected_invite_data.stage_key.try_into().unwrap();

        let art = PrivateART::from_public_art(art, inviter_leaf_secret)?;

        let mut invite_frame_tbs = invite_frame.frame.ok_or(Error::InvalidInput)?;
        let invite_frame_protected_payload =
            std::mem::take(&mut invite_frame_tbs.protected_payload);

        let invite_frame_protected_payload = crate::utils::decrypt(
            &stage_key,
            &invite_frame_protected_payload,
            &Sha3_256::digest(invite_frame_tbs.encode_to_vec()),
        )?;
        let invite_frame_protected_payload =
            zero_art_proto::ProtectedPayload::decode(&invite_frame_protected_payload[..])?;
        let invite_frame_protected_payload_tbs = invite_frame_protected_payload
            .payload
            .ok_or(Error::InvalidInput)?;
        // let group_action = invite_frame_protected_payload_tbs
        //     .group_action
        //     .ok_or(Error::InvalidInput)?;
        // let group_info = match group_action.action.ok_or(Error::InvalidInput)? {
        //     zero_art_proto::group_action_payload::Action::InviteMember(group_info) => {
        //         models::group_info::GroupInfo::from_proto(&group_info)
        //     }
        //     _ => return Err(Error::InvalidInput),
        // };

        // let group_context = GroupContext {
        //     art,
        //     epoch: protected_invite_data.epoch,
        //     stk: Box::new(stage_key),
        //     rng: context_rng,
        //     proof_system,
        //     identity_key_pair: KeyPair::from_secret_key(self.init.identity_secret_key),
        //     this_id: self.user.id(),
        //     metadata: group_info,
        // };

        // group_context.update_key(self.leaf_secret, payload);
        Ok(())
    }
}
