use ark_serialize::serialize_to_vec;
use art::traits::ARTPrivateAPI;
use cortado::{self, Fr as ScalarField};
use crypto::CryptoError;

use hkdf::Hkdf;
use sha3::Sha3_256;

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::{Aes256Gcm, Key};

use super::{Error, GroupContext};

impl GroupContext {
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        encrypt(&self.stk, plaintext, aad)
    }

    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        decrypt(&self.stk, ciphertext, aad)
    }

    /// Compute next STK and increment epoch
    ///
    /// Should be carefully used, because you can't move backward
    pub(super) fn advance_epoch(&mut self) -> Result<(), Error> {
        let tk = self.art.get_root_key()?;
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

pub fn encrypt(stage_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
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
        .map_err(|_| Error::AesError)
}

pub fn decrypt(stage_key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
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
        .map_err(|_| Error::AesError)
}

pub fn derive_stage_key(stage_key: &[u8; 32], tree_key: ScalarField) -> Result<[u8; 32], Error> {
    // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
    let stk = hkdf(
        Some(b"stage-key-derivation"),
        &vec![&stage_key[..], &serialize_to_vec![tree_key]?].concat(),
    )?;
    Ok(stk)
}
