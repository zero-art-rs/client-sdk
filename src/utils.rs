use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use hkdf::Hkdf;
use sha3::Sha3_256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AES error")]
    AesError,
    #[error("HKDF error")]
    HkdfError,
}

pub fn encrypt(stage_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let h = Hkdf::<Sha3_256>::new(Some(b"encryption-key-derivation"), stage_key);

    // AES 256 key size - 32 bytes, nonce - 12 bytes
    let mut okm = [0u8; 32 + 12];
    h.expand(&[], &mut okm).map_err(|_| Error::HkdfError)?;

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
    h.expand(&[], &mut okm).map_err(|_| Error::HkdfError)?;

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
