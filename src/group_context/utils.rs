use ark_serialize::serialize_to_vec;
use art::traits::ARTPrivateAPI;

use crate::utils::{decrypt, encrypt, hkdf};

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
        self.stk = stk;

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }
}
