use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::{SeedableRng, rngs::StdRng, thread_rng};
use art::types::PrivateART;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::x3dh::x3dh_a;

use crate::{
    group_context::{GroupContext, InvitationKeys, KeyPair, SDKError, utils},
    metadata, proof_system, zero_art_proto,
};

use ark_serialize::{CanonicalSerialize, serialize_to_vec};

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
        leaf_secret: ScalarField,
        user: metadata::user::User,
        group_info: metadata::group::GroupInfo,
    ) -> CreateGroupContextBuilder {
        CreateGroupContextBuilder {
            init: self,
            user,
            group_info,
            leaf_secret,
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
        group_info: metadata::group::GroupInfo,
    ) -> Result<GroupContext, SDKError> {
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

    pub fn from_invite(
        self,
        leaf_secret: ScalarField,
        invite: zero_art_proto::Invite,
        user: metadata::user::User,
    ) -> FromInviteGroupContextBuilder {
        FromInviteGroupContextBuilder {
            init: self,
            leaf_secret,
            invite,
            user,
        }
    }
}

pub struct CreateGroupContextBuilder {
    init: InitialGroupContextBuilder,
    user: metadata::user::User,
    group_info: metadata::group::GroupInfo,
    leaf_secret: ScalarField,
    identified_members_keys: Vec<(CortadoAffine, Option<CortadoAffine>)>,
    unidentified_members_count: usize,
    payloads: Vec<zero_art_proto::Payload>,
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
        identified_member_keys: (CortadoAffine, Option<CortadoAffine>),
    ) {
        self.identified_members_keys.push(identified_member_keys);
    }

    pub fn payloads(mut self, payloads: Vec<zero_art_proto::Payload>) -> Self {
        self.payloads = payloads;
        self
    }

    pub fn push_payload(&mut self, payload: zero_art_proto::Payload) {
        self.payloads.push(payload);
    }

    pub fn unidentified_members_count(mut self, unidentified_members_count: usize) -> Self {
        self.unidentified_members_count = unidentified_members_count;
        self
    }

    pub fn build(
        self,
    ) -> Result<
        (
            GroupContext,
            zero_art_proto::Frame,
            HashMap<Vec<u8>, zero_art_proto::Invite>,
            Vec<zero_art_proto::Invite>,
        ),
        SDKError,
    > {
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

        // 2. Compute identity and ephemeral public keys
        let identity_secret_key = self.init.identity_secret_key;
        let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

        let ephemeral_secret_key = ScalarField::rand(&mut context_rng);
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        // 3. Prepare buffers for invites
        let identified_members_keys = self.identified_members_keys;
        let unidentified_members_count = self.unidentified_members_count;
        let mut identified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(identified_members_keys.len());
        let mut unidentified_leaf_secrets: Vec<ScalarField> =
            Vec::with_capacity(unidentified_members_count);

        let mut unidentified_secret_keys: Vec<ScalarField> =
            Vec::with_capacity(unidentified_members_count);

        let mut identified_invites: HashMap<Vec<u8>, zero_art_proto::Invite> =
            HashMap::with_capacity(identified_members_keys.len());
        let mut unidentified_invites: Vec<zero_art_proto::Invite> =
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
        let leaf_secret = self.leaf_secret;
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
        let stk = utils::hkdf(
            Some(b"stage-key-derivation"),
            &vec![&vec![0u8; 32][..], &serialize_to_vec![tk.key]?].concat(),
        )?;

        // 8. Form initial metadata
        let mut user = self.user;
        let mut group_info = self.group_info;
        user.public_key = identity_public_key;
        group_info.members.insert(user.id(), user.clone());

        // 9. Build group context
        let mut group_context = GroupContext {
            art,
            epoch: 0,
            stk: Box::new(stk),
            rng: context_rng,
            proof_system,
            identity_key_pair: KeyPair::from_secret_key(identity_secret_key),
            this_id: user.id(),
            metadata: group_info.clone(),
        };

        // 9. Create invitations
        for (identity_public_key, spk_public_key) in identified_members_keys {
            let invite = group_context.create_invite(
                ephemeral_public_key,
                InvitationKeys::Identified {
                    identity_public_key,
                    spk_public_key: spk_public_key,
                },
            )?;
            let mut public_key_bytes = Vec::new();
            identity_public_key.serialize_uncompressed(&mut public_key_bytes);
            identified_invites.insert(public_key_bytes, invite);
        }

        for secret_key in unidentified_leaf_secrets {
            let invite = group_context.create_invite(
                ephemeral_public_key,
                InvitationKeys::Unidentified {
                    invitation_secret_key: secret_key,
                },
            )?;
            unidentified_invites.push(invite);
        }

        // 10. Build initial frame
        let init_payload_bytes = zero_art_proto::Payload {
            content: Some(zero_art_proto::payload::Content::Action(
                zero_art_proto::GroupActionPayload {
                    action: Some(zero_art_proto::group_action_payload::Action::Init(
                        group_info.to_proto(),
                    )),
                },
            )),
        };

        let mut payloads = self.payloads;
        payloads.push(init_payload_bytes);
        let frame = group_context.create_frame(payloads)?;

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
    user: metadata::user::User,
    invite: zero_art_proto::Invite,
}

pub fn secret_from_identified_invite(invite: zero_art_proto::invite::Invite) {}
