use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use sha3::Sha3_256;
use tracing::{debug, info, instrument, trace};

use crate::{
    error::Result,
    group_context::{GroupContext, map_users_to_leaf_ids},
    models::{
        frame::{Frame, GroupOperation},
        group_info::{User, public_key_to_id},
        invite::{Invite, Invitee},
        payload::{GroupActionPayload, Payload},
    },
    zero_art_proto,
};
use cortado::{CortadoAffine, Fr as ScalarField};

impl GroupContext {
    #[instrument(skip(self, invitee, payloads))]
    pub fn add_member(
        &mut self,
        invitee: Invitee,
        mut payloads: Vec<Payload>,
    ) -> Result<(Frame, Invite)> {
        info!("Start add_member");
        trace!("Invitee: {:?}", invitee);

        // Pending state is ephemeral state
        let mut pending_state = self.state.clone();

        // 1. Generate ephemeral secret key
        let ephemeral_secret_key = ScalarField::rand(&mut self.rng);
        debug!("Ephemeral secret key generated");
        trace!("Ephemeral secret key: {:?}", ephemeral_secret_key);

        // 2. Compute new member's leaf secret
        let leaf_secret = self.compute_leaf_secret_for_invitee(invitee, ephemeral_secret_key)?;
        let leaf_public_key = (CortadoAffine::generator() * leaf_secret).into_affine();
        debug!("Leaf secret computed");
        trace!("Leaf secret: {:?}", leaf_secret);

        // 3. Add node to ART and advance epoch

        // Since leafs in tree can be added also not only to right
        // we need to reorder group members to follow non blank leafs order
        let mut leaf_member_map = pending_state.map_leafs_to_users();

        let (changes, prover_artefacts) = pending_state.append_leaf(&leaf_secret)?;
        debug!("Node added to ART: {:?}", changes);

        let user = User::new_with_id(
            public_key_to_id(leaf_public_key),
            String::from("Invited"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::Write,
        );
        let user_id = user.id().to_string();

        // Since leafs in tree can be added also not only to right
        // we need to reorder group members to follow non blank leafs order
        pending_state
            .group_info
            .members_mut()
            .insert(user_id.clone(), user);
        leaf_member_map.insert(leaf_public_key, user_id);

        let members_order = map_users_to_leaf_ids(pending_state.iter_leafs(), leaf_member_map);
        pending_state
            .group_info
            .members_mut()
            .reorder(members_order);

        // 4. Add payload with group info
        payloads.push(Payload::Action(GroupActionPayload::InviteMember(
            pending_state.group_info.clone(),
        )));

        let frame = self
            .create_frame_tbs(
                &pending_state,
                payloads,
                Some(GroupOperation::AddMember(changes)),
                None,
            )?
            .prove_art::<Sha3_256>(prover_artefacts, pending_state.art.secret_key)?;
        debug!("Frame created");
        trace!("Frame: {:?}", frame);

        let invite =
            self.create_invite(&pending_state, invitee, leaf_secret, ephemeral_secret_key)?;
        debug!("Invite created");
        trace!("Invite: {:?}", invite);

        self.pending_state.is_last_sender = true;
        self.pending_state = pending_state;

        info!("add_member finished successfully");
        Ok((frame, invite))
    }
}
