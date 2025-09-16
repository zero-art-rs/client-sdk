use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalSerialize, serialize_to_vec};
use art::traits::ARTPrivateAPI;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::{CryptoError, x3dh::x3dh_a};

use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::group_context::InvitationKeys;

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::{Aes256Gcm, Key};

use super::{GroupContext, SDKError};

impl GroupContext {
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SDKError> {
        encrypt(&self.stk, plaintext, aad)
    }

    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SDKError> {
        decrypt(&self.stk, ciphertext, aad)
    }

    pub(super) fn compute_member_leaf_secret(
        &self,
        ephemeral_secret_key: ScalarField,
        invitation_keys: InvitationKeys,
    ) -> Result<ScalarField, SDKError> {
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
            self.identity_key_pair.secret_key,
            ephemeral_secret_key,
            identity_public_key,
            invitation_public_key,
        )?);
        Ok(member_leaf_secret)
    }

    /// Compute next STK and increment epoch
    ///
    /// Should be carefully used, because you can't move backward
    pub(super) fn advance_epoch(&mut self) -> Result<(), SDKError> {
        let tk = self.art.recompute_root_key()?;

        // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
        let stk = hkdf(
            Some(b"stage-key-derivation"),
            &vec![&self.stk[..], &serialize_to_vec![tk.key]?].concat(),
        )?;
        *self.stk.as_mut() = stk;

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }
}

pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32], CryptoError> {
    let h = Hkdf::<Sha3_256>::new(salt, &ikm);
    let mut okm = [0u8; 32];
    h.expand(&[], &mut okm)?;
    Ok(okm)
}

pub fn encrypt(stage_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SDKError> {
    let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), stage_key);

    // AES 256 key size - 32 bytes, nonce - 12 bytes
    let mut okm = [0u8; 32 + 12];
    h.expand(&[], &mut okm)?;

    let (key, nonce) = (&okm[..32], &okm[32..]);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

    let cipher = Aes256Gcm::new(key);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SDKError::AesError)
}

pub fn decrypt(stage_key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SDKError> {
    let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), stage_key);

    // AES 256 key size - 32 bytes, nonce - 12 bytes
    let mut okm = [0u8; 32 + 12];
    h.expand(&[], &mut okm)?;

    let (key, nonce) = (&okm[..32], &okm[32..]);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SDKError::AesError)
}

pub fn derive_stage_key(stage_key: &[u8; 32], tree_key: ScalarField) -> Result<[u8; 32], SDKError> {
    // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
    let stk = hkdf(
        Some(b"stage-key-derivation"),
        &vec![&stage_key[..], &serialize_to_vec![tree_key]?].concat(),
    )?;
    Ok(stk)
}
