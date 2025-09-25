use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use crypto::x3dh::{x3dh_a, x3dh_b};
use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::error::{Error, Result};

pub fn encrypt(stage_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), stage_key);

    // AES 256 key size - 32 bytes, nonce - 12 bytes
    let mut okm = [0u8; 32 + 12];
    h.expand(&[], &mut okm).map_err(|_| Error::InvalidInput)?;

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
        .map_err(|_| Error::AesError)
}

pub fn decrypt(stage_key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), stage_key);

    // AES 256 key size - 32 bytes, nonce - 12 bytes
    let mut okm = [0u8; 32 + 12];
    h.expand(&[], &mut okm).map_err(|_| Error::InvalidInput)?;

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
        .map_err(|_| Error::AesError)
}

pub fn compute_leaf_secret_a(
    ika: ScalarField,
    eka: ScalarField,
    ikb: CortadoAffine,
    ekb: CortadoAffine,
) -> Result<ScalarField> {
    Ok(ScalarField::from_le_bytes_mod_order(
        &x3dh_a::<CortadoAffine>(ika, eka, ikb, ekb).map_err(|_| Error::InvalidInput)?,
    ))
}

pub fn compute_leaf_secret_b(
    ika: ScalarField,
    eka: ScalarField,
    ikb: CortadoAffine,
    ekb: CortadoAffine,
) -> Result<ScalarField> {
    Ok(ScalarField::from_le_bytes_mod_order(
        &x3dh_b::<CortadoAffine>(ika, eka, ikb, ekb).map_err(|_| Error::InvalidInput)?,
    ))
}

pub fn serialize<T: CanonicalSerialize>(value: T) -> Result<Vec<u8>> {
    let mut value_bytes = Vec::new();
    value.serialize_compressed(&mut value_bytes)?;
    Ok(value_bytes)
}

pub fn deserialize<T: CanonicalDeserialize>(value_bytes: &[u8]) -> Result<T> {
    Ok(T::deserialize_compressed(value_bytes)?)
}

pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32]> {
    let h = Hkdf::<Sha3_256>::new(salt, &ikm);
    let mut okm = [0u8; 32];
    h.expand(&[], &mut okm)?;
    Ok(okm)
}

pub fn derive_stage_key(stage_key: &[u8; 32], tree_key: ScalarField) -> Result<[u8; 32]> {
    // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
    let stk = hkdf(
        Some(b"stage-key-derivation"),
        &vec![&stage_key[..], &serialize(tree_key)?].concat(),
    )?;
    Ok(stk)
}
