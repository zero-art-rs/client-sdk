use crate::{error::{Error, Result}, utils::{deserialize, serialize}};
use ark_ec::{AffineRepr, CurveGroup};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::schnorr;
use prost::Message;
use sha3::Digest;
use uuid::Uuid;

use crate::zero_art_proto;

#[derive(Debug, Clone)]
pub struct Invite {
    invite_tbs: InviteTbs,
    signature: Vec<u8>,
}

impl Invite {
    pub fn new(invite_tbs: InviteTbs, signature: Vec<u8>) -> Self {
        Self {
            invite_tbs,
            signature,
        }
    }

    // Getters
    pub fn invite_tbs(&self) -> &InviteTbs {
        &self.invite_tbs
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    // Verify signature
    pub fn verify<D: Digest>(&self, public_key: CortadoAffine) -> Result<()> {
        Ok(schnorr::verify(
            &self.signature,
            &vec![public_key],
            &D::digest(self.invite_tbs.encode_to_vec()?),
        )?)
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let inner: zero_art_proto::Invite = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::Invite::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::Invite> for Invite {
    type Error = Error;

    fn try_from(value: zero_art_proto::Invite) -> Result<Self> {
        Ok(Self {
            invite_tbs: value.invite.ok_or(Error::RequiredFieldAbsent)?.try_into()?,
            signature: value.signature,
        })
    }
}

impl TryFrom<Invite> for zero_art_proto::Invite {
    type Error = Error;

    fn try_from(value: Invite) -> Result<Self> {
        Ok(Self {
            invite: Some(value.invite_tbs.try_into()?),
            signature: value.signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InviteTbs {
    invitee: Invitee,
    inviter_public_key: CortadoAffine,
    ephemeral_public_key: CortadoAffine,
    protected_invite_data: Vec<u8>,
}

impl InviteTbs {
    pub fn new(
        invitee: Invitee,
        inviter_public_key: CortadoAffine,
        ephemeral_public_key: CortadoAffine,
        protected_invite_data: Vec<u8>,
    ) -> Self {
        Self {
            invitee,
            inviter_public_key,
            ephemeral_public_key,
            protected_invite_data,
        }
    }

    // Getters
    pub fn invitee(&self) -> Invitee {
        self.invitee
    }

    pub fn inviter_public_key(&self) -> CortadoAffine {
        self.inviter_public_key
    }

    pub fn ephemeral_public_key(&self) -> CortadoAffine {
        self.ephemeral_public_key
    }

    pub fn protected_invite_data(&self) -> &[u8] {
        &self.protected_invite_data
    }

    // Sign payload and return Invite
    pub fn sign<D: Digest>(self, secret_key: ScalarField) -> Result<Invite> {
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();
        let signature = schnorr::sign(
            &vec![secret_key],
            &vec![public_key],
            &D::digest(self.encode_to_vec()?),
        )?;
        Ok(Invite {
            invite_tbs: self,
            signature: signature,
        })
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let inner: zero_art_proto::InviteTbs = self.clone().try_into()?;
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::InviteTbs::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::InviteTbs> for InviteTbs {
    type Error = Error;

    fn try_from(value: zero_art_proto::InviteTbs) -> Result<Self> {
        let inviter_public_key =
            deserialize(&value.identity_public_key)?;
        let ephemeral_public_key =
            deserialize(&value.ephemeral_public_key)?;
        Ok(Self {
            invitee: value
                .invite
                .ok_or(Error::InvalidVerificationMethod)?
                .try_into()?,
            inviter_public_key,
            ephemeral_public_key,
            protected_invite_data: value.protected_invite_data,
        })
    }
}

impl TryFrom<InviteTbs> for zero_art_proto::InviteTbs {
    type Error = Error;

    fn try_from(value: InviteTbs) -> Result<Self> {
        Ok(Self {
            protected_invite_data: value.protected_invite_data,
            identity_public_key: serialize(value
            .inviter_public_key)?,
            ephemeral_public_key: serialize(value
            .ephemeral_public_key)?,
            invite: Some(value.invitee.try_into()?),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Invitee {
    Identified {
        identity_public_key: CortadoAffine,
        spk_public_key: Option<CortadoAffine>,
    },
    Unidentified(ScalarField),
}

impl TryFrom<zero_art_proto::invite_tbs::Invite> for Invitee {
    type Error = Error;

    fn try_from(value: zero_art_proto::invite_tbs::Invite) -> Result<Self> {
        match value {
            zero_art_proto::invite_tbs::Invite::IdentifiedInvite(inv) => {
                let identity_public_key =
                    deserialize(&inv.identity_public_key)?;
                let spk_public_key = if inv.spk_public_key.len() == 0 {
                    None
                } else {
                    Some(deserialize(
                        &inv.spk_public_key,
                    )?)
                };
                Ok(Invitee::Identified {
                    identity_public_key,
                    spk_public_key,
                })
            }
            zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(inv) => {
                let secret_key = deserialize(&inv.private_key)?;
                Ok(Invitee::Unidentified(secret_key))
            }
        }
    }
}

impl TryFrom<Invitee> for zero_art_proto::invite_tbs::Invite {
    type Error = Error;

    fn try_from(value: Invitee) -> Result<Self> {
        match value {
            Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => {
                let identity_public_key_bytes = serialize(identity_public_key)?;

                let mut spk_public_key_bytes = Vec::new();
                if let Some(spk_public_key) = spk_public_key {
                    spk_public_key_bytes = serialize(spk_public_key)?;
                }

                Ok(zero_art_proto::invite_tbs::Invite::IdentifiedInvite(
                    zero_art_proto::IdentifiedInvite {
                        identity_public_key: identity_public_key_bytes,
                        spk_public_key: spk_public_key_bytes,
                    },
                ))
            }
            Invitee::Unidentified(secret_key) => {
                Ok(zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(
                    zero_art_proto::UnidentifiedInvite {
                        private_key: serialize(secret_key)?,
                    },
                ))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectedInviteData {
    epoch: u64,
    stage_key: [u8; 32],
    group_id: Uuid,
}

impl ProtectedInviteData {
    pub fn new(epoch: u64, stage_key: [u8; 32], group_id: Uuid) -> Self {
        Self {
            epoch,
            stage_key,
            group_id,
        }
    }

    // Getters
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn stage_key(&self) -> [u8; 32] {
        self.stage_key
    }

    pub fn group_id(&self) -> Uuid {
        self.group_id
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let inner: zero_art_proto::ProtectedInviteData = self.clone().into();
        Ok(inner.encode_to_vec())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::ProtectedInviteData::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::ProtectedInviteData> for ProtectedInviteData {
    type Error = Error;

    fn try_from(value: zero_art_proto::ProtectedInviteData) -> Result<Self> {
        Ok(Self {
            epoch: value.epoch,
            stage_key: value
                .stage_key
                .try_into()
                .map_err(|_| Error::InvalidVerificationMethod)?,
            group_id: Uuid::parse_str(&value.group_id).map_err(|_| Error::InvalidInput)?,
        })
    }
}

impl From<ProtectedInviteData> for zero_art_proto::ProtectedInviteData {
    fn from(value: ProtectedInviteData) -> Self {
        Self {
            epoch: value.epoch,
            stage_key: value.stage_key.to_vec(),
            group_id: value.group_id.to_string(),
        }
    }
}
