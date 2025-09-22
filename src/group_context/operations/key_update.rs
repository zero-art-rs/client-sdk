use art::traits::ARTPrivateAPI;
use sha3::Sha3_256;

use crate::{
    error::Result,
    group_context::GroupContext,
    models::{
        frame::{Frame, GroupOperation},
        payload::Payload,
    },
};
use cortado::Fr as ScalarField;

impl GroupContext {
    // key_update should:
    // 1. Update own leaf with provided secret and recompute STK
    // 2. Create frame without encrypted payload
    // 3. Encrypt provided payload and attach to frame
    // 4. Generate proof for ART change with SHA3-256(frame) in associated data
    // Return Frame(serialized?)
    pub fn key_update(
        &mut self,
        leaf_secret: ScalarField,
        payloads: Vec<Payload>,
    ) -> Result<Frame> {
        let old_secret = self.art.secret_key;

        let (_, changes, prover_artefacts) = self.art.update_key(&leaf_secret)?;
        self.advance_epoch()?;

        let frame = self
            .create_frame_tbs(payloads, Some(GroupOperation::KeyUpdate(changes)))?
            .prove_art::<Sha3_256>(&mut self.proof_system, prover_artefacts, old_secret)?;

        self.is_last_sender = true;
        Ok(frame)
    }
}
