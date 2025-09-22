use ark_ff::UniformRand;
use art::traits::ARTPrivateAPI;
use sha3::Sha3_256;
use tracing::{trace, info, debug, instrument};


use crate::{
    error::Result,
    group_context::GroupContext,
    models::{
        frame::{Frame, GroupOperation},
        invite::{Invite, Invitee},
        payload::{GroupActionPayload, Payload},
    },
};
use cortado::Fr as ScalarField;

impl GroupContext {
    #[instrument(skip(self, invitee, payloads))]
    pub fn add_member(
        &mut self,
        invitee: Invitee,
        mut payloads: Vec<Payload>,
    ) -> Result<(Frame, Invite)> {
        info!("Start add_member");
        trace!("Invitee: {:?}", invitee);

        // 1. Generate ephemeral secret key
        let ephemeral_secret_key = ScalarField::rand(&mut self.rng);
        debug!("Ephemeral secret key generated");
        trace!("Ephemeral secret key: {:?}", ephemeral_secret_key);

        // 2. Compute new member's leaf secret
        let leaf_secret = self.compute_leaf_secret_for_invitee(invitee, ephemeral_secret_key)?;
        debug!("Leaf secret computed");
        trace!("Leaf secret: {:?}", leaf_secret);

        // 3. Add node to ART and advance epoch
        let (_, changes, prover_artefacts) = self.art.append_or_replace_node(&leaf_secret)?;
        debug!("Node added to ART: {:?}", changes);
        self.advance_epoch()?;
        debug!("Epoch advanced");

        // Control order to able to remove users by identity public key
        self.reorder_members();
        trace!("Members reordered");

        // 4. Add payload with group info
        payloads.push(Payload::Action(GroupActionPayload::InviteMember(
            self.group_info.clone(),
        )));

        let frame = self
            .create_frame_tbs(payloads, Some(GroupOperation::AddMember(changes)))?
            .prove_art::<Sha3_256>(
                &mut self.proof_system,
                prover_artefacts,
                self.art.secret_key,
            )?;
        debug!("Frame created");
        trace!("Frame: {:?}", frame);

        let invite = self.create_invite(invitee, leaf_secret, ephemeral_secret_key)?;
        debug!("Invite created");
        trace!("Invite: {:?}", invite);

        self.is_last_sender = true;

        info!("add_member finished successfully");
        Ok((frame, invite))
    }
}
