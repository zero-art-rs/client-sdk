use crate::group_context::utils::{decrypt, encrypt};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::x3dh::x3dh_a;
use crypto::{schnorr, x3dh::x3dh_b};
use prost::Message;
use sha3::{Digest, Sha3_256};

use crate::group_context::SDKError;
use crate::{metadata, zero_art_proto};

pub struct Invite {
    pub invitee: Invitee,
    pub inviter_public_key: CortadoAffine,
    pub ephemeral_public_key: CortadoAffine,

    // protected_invite_data
    pub epoch: u64,
    pub stage_key: [u8; 32],
    pub group_info: metadata::group::GroupInfo,
}

impl Invite {
    pub fn try_from(
        invite: zero_art_proto::Invite,
        invitee_secrets: Option<(ScalarField, Option<ScalarField>)>,
    ) -> Result<(Self, ScalarField), SDKError> {
        let signature = invite.signature;
        let invite = invite.invite.ok_or(SDKError::InvalidInput)?;
        let invite_digest = Sha3_256::digest(invite.encode_to_vec());

        // Verify invite signature
        let inviter_public_key =
        CortadoAffine::deserialize_uncompressed(&invite.identity_public_key[..])?;
        schnorr::verify(&signature, &vec![inviter_public_key], &invite_digest)?;
        
        let ephemeral_public_key =
        CortadoAffine::deserialize_uncompressed(&invite.ephemeral_public_key[..])?;
        
        // Parse invitee keys
        let invitee = invite.invite.ok_or(SDKError::InvalidInput)?.try_into()?;
        // Verify if this is identified invite that secrets provided
        if let Invitee::Identified {
            identity_public_key,
            spk_public_key,
        } = invitee
        {
            if invitee_secrets.is_none() {
                return Err(SDKError::InvalidInput);
            }
            
            
            let (identity_secret_key, spk_secret_key) = invitee_secrets.unwrap();
            let owned_identity_public_key =
                (CortadoAffine::generator() * identity_secret_key).into_affine();
            let owned_spk_public_key =
                spk_secret_key.map(|s| (CortadoAffine::generator() * s).into_affine());

            if owned_identity_public_key != identity_public_key
                || owned_spk_public_key != spk_public_key
            {
                return Err(SDKError::InvalidInput);
            }
        };

        // Calculate invite leaf secret
        let invite_leaf_secret = match invitee {
            Invitee::Identified { .. } => {
                let (identity_secret_key, spk_secret_key) = invitee_secrets.unwrap();

                ScalarField::from_le_bytes_mod_order(&x3dh_b::<CortadoAffine>(
                    identity_secret_key,
                    spk_secret_key.unwrap_or(identity_secret_key),
                    inviter_public_key,
                    ephemeral_public_key,
                )?)
            }
            Invitee::Unidentified(invite_secret_key) => {
                ScalarField::from_le_bytes_mod_order(&x3dh_b::<CortadoAffine>(
                    invite_secret_key,
                    invite_secret_key,
                    inviter_public_key,
                    ephemeral_public_key,
                )?)
            }
        };

        // Decrypt invite protected data
        let mut invite_stk = [0u8; 32];
        invite_leaf_secret.serialize_uncompressed(&mut invite_stk[..])?;

        let invite_data = decrypt(&invite_stk, &invite.protected_invite_data, &[])?;
        let invite_data = zero_art_proto::ProtectedInviteData::decode(&invite_data[..])?;

        // TODO: Remove unwrap
        let stage_key: [u8; 32] = invite_data.stage_key.try_into().unwrap();
        let epoch = invite_data.epoch;
        let group_info = invite_data
            .group_info
            .ok_or(SDKError::InvalidInput)?
            .try_into()?;

        Ok((
            Self {
                invitee,
                inviter_public_key,
                ephemeral_public_key,
                stage_key,
                epoch,
                group_info,
            },
            invite_leaf_secret,
        ))
    }

    pub fn try_into(
        mut self,
        inviter_secret_key: ScalarField,
        ephemeral_secret_key: ScalarField,
    ) -> Result<zero_art_proto::Invite, SDKError> {
        let inviter_public_key = (CortadoAffine::generator() * inviter_secret_key).into_affine();
        let ephemeral_public_key =
            (CortadoAffine::generator() * ephemeral_secret_key).into_affine();

        self.inviter_public_key = inviter_public_key;
        self.ephemeral_public_key = ephemeral_public_key;

        // Calculate invite leaf secret
        let invite_leaf_secret = match self.invitee {
            Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => ScalarField::from_le_bytes_mod_order(&x3dh_a::<CortadoAffine>(
                inviter_secret_key,
                ephemeral_secret_key,
                identity_public_key,
                spk_public_key.unwrap_or(identity_public_key),
            )?),
            Invitee::Unidentified(invite_secret_key) => {
                let invite_public_key =
                    (CortadoAffine::generator() * invite_secret_key).into_affine();
                ScalarField::from_le_bytes_mod_order(&x3dh_a::<CortadoAffine>(
                    inviter_secret_key,
                    ephemeral_secret_key,
                    invite_public_key,
                    invite_public_key,
                )?)
            }
        };

        // Encrypt invite protected data
        let mut invite_stk = [0u8; 32];
        invite_leaf_secret.serialize_uncompressed(&mut invite_stk[..])?;

        let invite_data = zero_art_proto::ProtectedInviteData {
            epoch: self.epoch,
            stage_key: self.stage_key.to_vec(),
            group_info: Some(self.group_info.into()),
        };
        let protected_invite_data = encrypt(&invite_stk, &invite_data.encode_to_vec(), &[])?;

        let mut inviter_public_key_bytes = Vec::new();
        inviter_public_key.serialize_uncompressed(&mut inviter_public_key_bytes)?;

        let mut ephemeral_public_key_bytes = Vec::new();
        ephemeral_public_key.serialize_uncompressed(&mut ephemeral_public_key_bytes)?;

        let invite_tbs = zero_art_proto::InviteTbs {
            protected_invite_data,
            invite: Some(self.invitee.try_into()?),
            identity_public_key: inviter_public_key_bytes,
            ephemeral_public_key: ephemeral_public_key_bytes,
        };

        let signature = schnorr::sign(
            &vec![inviter_secret_key],
            &vec![inviter_public_key],
            &Sha3_256::digest(invite_tbs.encode_to_vec()),
        )?;

        Ok(zero_art_proto::Invite {
            invite: Some(invite_tbs),
            signature: signature,
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
    type Error = SDKError;

    fn try_from(value: zero_art_proto::invite_tbs::Invite) -> Result<Self, Self::Error> {
        match value {
            zero_art_proto::invite_tbs::Invite::IdentifiedInvite(inv) => {
                let identity_public_key =
                CortadoAffine::deserialize_uncompressed(&inv.identity_public_key[..])?;
                let spk_public_key = if inv.spk_public_key.len() == 0 {
                    None
                } else {
                    Some(CortadoAffine::deserialize_uncompressed(
                        &inv.spk_public_key[..],
                    )?)
                };
                Ok(Invitee::Identified {
                    identity_public_key,
                    spk_public_key,
                })
            }
            zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(inv) => {
                let secret_key = ScalarField::deserialize_uncompressed(&inv.private_key[..])?;
                Ok(Invitee::Unidentified(secret_key))
            }
        }
    }
}

impl TryFrom<Invitee> for zero_art_proto::invite_tbs::Invite {
    type Error = SDKError;

    fn try_from(value: Invitee) -> Result<Self, Self::Error> {
        match value {
            Invitee::Identified {
                identity_public_key,
                spk_public_key,
            } => {
                let mut identity_public_key_bytes = Vec::new();
                identity_public_key.serialize_uncompressed(&mut identity_public_key_bytes)?;

                
                let mut spk_public_key_bytes = Vec::new();
                if let Some(spk_public_key) = spk_public_key {
                    spk_public_key.serialize_uncompressed(&mut spk_public_key_bytes)?;
                }

                Ok(zero_art_proto::invite_tbs::Invite::IdentifiedInvite(
                    zero_art_proto::IdentifiedInvite {
                        identity_public_key: identity_public_key_bytes,
                        spk_public_key: spk_public_key_bytes,
                    },
                ))
            }
            Invitee::Unidentified(secret_key) => {
                let mut secret_key_bytes = Vec::new();
                secret_key.serialize_uncompressed(&mut secret_key_bytes)?;

                Ok(zero_art_proto::invite_tbs::Invite::UnidentifiedInvite(
                    zero_art_proto::UnidentifiedInvite {
                        private_key: secret_key_bytes,
                    },
                ))
            }
        }
    }
}
