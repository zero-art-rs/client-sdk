use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use sha3::Sha3_256;
use tracing::{debug, info, instrument, trace};

use crate::{
    error::Result,
    group_context::GroupContext,
    models::{
        frame::{Frame, GroupOperation},
        group_info::User,
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

        // Create mapping for leaf public keys to member ids
        let mut member_leaf_map = self.map_leafs_to_users();

        let (changes, prover_artefacts) = pending_state.append_leaf(&leaf_secret)?;
        debug!("Node added to ART: {:?}", changes);

        let user = User::new(
            String::from("Invited"),
            CortadoAffine::default(),
            vec![],
            zero_art_proto::Role::Write,
        );
        member_leaf_map.insert(leaf_public_key, user.id().to_string());
        let members_order = self.map_uids_to_indexes_by_leafs(member_leaf_map);
        pending_state.group_info.members_mut().insert_user(user);
        pending_state
            .group_info
            .members_mut()
            .sort_by_keys_indexes(members_order);

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
            .prove_art::<Sha3_256>(
                &mut self.proof_system,
                prover_artefacts,
                pending_state.art.secret_key,
            )?;
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
