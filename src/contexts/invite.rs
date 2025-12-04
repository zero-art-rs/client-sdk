use crate::{
    contexts::group::{GroupContext, Nonce},
    errors::{Error, Result},
    keyed_validator::KeyedValidator,
    models::{
        group_info::GroupInfo,
        invite::{Invite, Invitee, ProtectedInviteData},
    },
    utils::{decrypt, hkdf},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::{SeedableRng, rngs::StdRng, thread_rng};
use chrono::Utc;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use sha3::Sha3_256;
use tracing::{debug, info, instrument, trace};
use uuid::Uuid;
use zrt_art::art::{PrivateArt, PrivateZeroArt, PublicArt};
use zrt_crypto::schnorr;

pub struct InviteContext {
    identity_secret_key: ScalarField,
    leaf_secret: ScalarField,
    stk: [u8; 32],
    epoch: u64,
    group_id: Uuid,
}

impl InviteContext {
    #[instrument(skip_all)]
    pub fn new(
        identity_secret_key: ScalarField,
        spk_secret_key: Option<ScalarField>,
        invite: Invite,
    ) -> Result<Self> {
        info!("New invite context");

        trace!("Identity secret key: {:?}", identity_secret_key);
        trace!("SPK secret key: {:?}", spk_secret_key);
        trace!("Invitee: {:?}", invite.invite_tbs().invitee());

        trace!("Invite signature: {:?}", invite.signature());
        invite.verify::<Sha3_256>(invite.invite_tbs().inviter_public_key())?;
        debug!("Invite signature verified");

        let inviter_public_key = invite.invite_tbs().inviter_public_key();
        let ephemeral_public_key = invite.invite_tbs().ephemeral_public_key();
        trace!("Inviter public key: {:?}", inviter_public_key);
        trace!("Ephemeral public key: {:?}", ephemeral_public_key);

        let leaf_secret = compute_invite_leaf_secret(
            invite.invite_tbs().invitee(),
            identity_secret_key,
            spk_secret_key,
            inviter_public_key,
            ephemeral_public_key,
        )?;
        debug!("Invite leaf secret computed");
        trace!("Invite leaf secret: {:?}", leaf_secret);

        let invite_encryption_key = hkdf(
            Some(b"invite-key-derivation"),
            &crate::utils::serialize(leaf_secret)?,
        )?;
        debug!("Invite encryption key derived");
        trace!("Invite encryption key: {:?}", invite_encryption_key);

        let protected_invite_data = decrypt(
            &invite_encryption_key,
            invite.invite_tbs().protected_invite_data(),
            &[],
        )?;
        let protected_invite_data = ProtectedInviteData::decode(&protected_invite_data)?;

        Ok(Self {
            identity_secret_key,
            leaf_secret,
            stk: protected_invite_data.stage_key(),
            epoch: protected_invite_data.epoch(),
            group_id: protected_invite_data.group_id(),
        })
    }

    pub fn sign_as_identity(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.identity_secret_key],
            &vec![self.identity_public_key()],
            msg,
        )?)
    }

    pub fn sign_as_leaf(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.leaf_secret],
            &vec![self.leaf_public_key()],
            msg,
        )?)
    }

    // Getters
    pub fn group_id(&self) -> &Uuid {
        &self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn identity_public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.identity_secret_key).into_affine()
    }

    pub fn leaf_public_key(&self) -> CortadoAffine {
        (CortadoAffine::generator() * self.leaf_secret).into_affine()
    }

    pub fn upgrade(self, art: PublicArt<CortadoAffine>) -> Result<GroupContext> {
        let base_art = PrivateArt::new(art, self.leaf_secret)?;
        Ok(GroupContext::from_parts(
            self.identity_secret_key,
            KeyedValidator::new(
                PrivateZeroArt::new(base_art, Box::new(StdRng::from_rng(thread_rng()).unwrap()))
                    .unwrap(),
                self.stk,
                self.epoch,
            ),
            GroupInfo::new(self.group_id, String::new(), Utc::now(), vec![]),
            0,
            Nonce::new(0),
        ))
    }
}

fn compute_invite_leaf_secret(
    invitee: Invitee,
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
        Invitee::Identified {
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
        Invitee::Unidentified(secret_key) => crate::utils::compute_leaf_secret_b(
            secret_key,
            secret_key,
            inviter_public_key,
            ephemeral_public_key,
        ),
    }
}
