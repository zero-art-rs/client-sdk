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
use tracing::{debug, info, instrument, trace};

impl GroupContext {
    // key_update should:
    // 1. Update own leaf with provided secret and recompute STK
    // 2. Create frame without encrypted payload
    // 3. Encrypt provided payload and attach to frame
    // 4. Generate proof for ART change with SHA3-256(frame) in associated data
    // Return Frame(serialized?)
    #[instrument(skip(self, leaf_secret, payloads))]
    pub fn key_update(
        &mut self,
        leaf_secret: ScalarField,
        payloads: Vec<Payload>,
    ) -> Result<Frame> {
        info!("Start key_update");

        let mut pending_state = self.state.clone();

        let old_secret = pending_state.art.secret_key;
        trace!("Old secret key: {:?}", old_secret);

        let (changes, prover_artefacts) = pending_state.update_key(&leaf_secret)?;
        debug!("Key updated: {:?}", changes);
        debug!("Epoch advanced");

        let frame = self
            .create_frame_tbs(
                &pending_state,
                payloads,
                Some(GroupOperation::KeyUpdate(changes)),
                None,
            )?
            .prove_art::<Sha3_256>(prover_artefacts, old_secret)?;
        debug!("Frame created");
        trace!("Frame: {:?}", frame);

        pending_state.is_last_sender = true;
        self.pending_state = pending_state;

        info!("key_update finished successfully");
        Ok(frame)
    }
}
