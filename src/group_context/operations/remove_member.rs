use ark_ff::UniformRand;
use sha3::Sha3_256;

use crate::{
    error::{Error, Result},
    group_context::GroupContext,
    models::{
        frame::{Frame, GroupOperation},
        group_info::User,
        payload::{GroupActionPayload, Payload},
    },
};
use cortado::{CortadoAffine, Fr as ScalarField};
use tracing::{info, instrument};

impl GroupContext {
    // remove_member should:
    // 1. Generate temporary leaf secret
    // 2. Make node blank in ART and recompute STK
    // 3. Create frame without encrypted payload
    // 4. Encrypt provided payload and attach to frame
    // 5. Generate proof for ART change with SHA3-256(frame) in associated data
    #[instrument(skip(self, payloads))]
    pub fn remove_member(
        &mut self,
        user_id: &str,
        mut payloads: Vec<Payload>,
    ) -> Result<(Frame, Option<User>)> {
        info!("Start remove_member");

        let mut pending_state = self.state.clone();

        // 1. Generate temporary leaf secret
        let temporary_leaf_secret: ark_ff::Fp<ark_ff::MontBackend<cortado::FrConfig, 4>, 4> =
            ScalarField::rand(&mut self.rng);

        let leaf_index = pending_state
            .group_info
            .members()
            .get_index_by_id(user_id)
            .ok_or(Error::InvalidInput)?;

        let removed_user = pending_state.group_info.members_mut().remove(user_id);

        let leaf_public_keys = pending_state
            .iter_leaves()
            .enumerate()
            .filter(|(i, node)| !node.is_blank && *i == leaf_index)
            .map(|(_, node)| node.public_key)
            .collect::<Vec<CortadoAffine>>();

        if leaf_public_keys.len() == 0 {
            return Err(Error::InvalidInput);
        }

        let leaf_public_key = leaf_public_keys[0];

        // 2. Make node blank in ART and recompute STK
        let (changes, prover_artefacts) =
            pending_state.make_blank(&leaf_public_key, &temporary_leaf_secret)?;

        payloads.push(Payload::Action(GroupActionPayload::RemoveMember(
            removed_user.clone().unwrap_or_default(),
        )));

        let frame = self
            .create_frame_tbs(
                &pending_state,
                payloads,
                Some(GroupOperation::RemoveMember(changes)),
                None,
            )?
            .prove_art::<Sha3_256>(prover_artefacts, pending_state.art.secret_key)?;

        pending_state.is_last_sender = true;
        self.pending_state = pending_state;

        info!("remove_member finished successfully");
        Ok((frame, removed_user))
    }
}
