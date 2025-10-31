use std::{collections::HashMap, iter::once};

use crate::{
    core::impls::concurrent::linear_keyed_validator::{LinearKeyedValidator, Participant},
    errors::{Error, Result},
    types::{ChangesID, StageKey},
    utils::derive_stage_key,
};
use ark_std::rand::{SeedableRng, rngs::StdRng, thread_rng};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use sha3::{Digest, Sha3_256};
use tracing::{debug, info, instrument, trace, warn};
use zrt_art::{
    art::{ArtAdvancedOps, art_types::PrivateZeroArt},
    changes::{
        ApplicableChange,
        branch_change::{BranchChange, MergeBranchChange},
    },
};

impl LinearKeyedValidator {
    pub(super) fn merge_changes_and_participate(
        &mut self,
        changes_id: ChangesID,
        changes: BranchChange<CortadoAffine>,
        secret_key: ScalarField,
    ) -> Result<StageKey> {
        let mut upstream_art = self.base_art.clone();
        upstream_art.update_key(secret_key)?;
        let tree_key = upstream_art.get_root_secret_key();
        let branch_stk = derive_stage_key(&self.base_stk, tree_key)?;
        trace!("Branch stage key: {:?}", branch_stk);

        let participant = Participant {
            id: changes_id,
            branch: changes.clone(),
            art: upstream_art.clone(),
        };

        let merge_branch_change = MergeBranchChange::new_for_participant(
            self.base_art.clone(),
            changes.clone(),
            self.changes
                .values()
                .cloned()
                .collect::<Vec<BranchChange<CortadoAffine>>>(),
        );
        merge_branch_change.update(&mut upstream_art)?;

        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_secret_key())?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        self.upstream_art = PrivateZeroArt::new(
            upstream_art,
            Box::new(StdRng::from_rng(thread_rng()).unwrap()),
        );
        self.upstream_stk = upstream_stk;

        self.participant = Some(participant);
        self.changes.insert(changes_id, changes);

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        trace!("Resulted epoch: {}", self.epoch);

        info!("End merge changes");
        Ok(branch_stk)
    }

    #[instrument(skip_all)]
    pub(super) fn merge_changes(
        &mut self,
        changes: &BranchChange<CortadoAffine>,
    ) -> Result<StageKey> {
        info!("Start merge changes");

        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(postcard::to_allocvec(&changes)?).to_vec()
            [..8]
            .try_into()
            .unwrap();
        debug!("Changes ID: {:?}", changes_id);

        if self.changes.contains_key(&changes_id) {
            warn!("Changes already applied");
            return Err(Error::ChangesAlreadyApplied);
        }

        if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            info!("Become participant");
            trace!("Participation secret key: {:?}", secret_key);
            return self.merge_changes_and_participate(changes_id, changes.clone(), secret_key);
        }

        // Derive branch stk to decrypt payload
        let mut branch_art = self.base_art.clone();
        changes.update(&mut branch_art)?;
        let branch_stk = derive_stage_key(&self.base_stk, branch_art.get_root_secret_key())?;
        trace!("Branch stk: {:?}", branch_stk);

        let upstream_art = if let Some(participant) = &self.participant {
            // Derive upstream art and stk to advance epoch and encrypt new payloads
            let mut upstream_art = participant.art.clone();
            let target_changes = self
                .changes
                .iter()
                .filter(|&(&id, _)| (id != participant.id))
                .map(|(_, c)| c.clone())
                .chain(std::iter::once(changes.clone()))
                .collect::<Vec<_>>();

            let merge_branch_change = MergeBranchChange::new_for_participant(
                self.base_art.clone(),
                participant.branch.clone(),
                target_changes,
            );

            merge_branch_change.update(&mut upstream_art)?;

            upstream_art
        } else {
            let mut upstream_art = self.base_art.clone();

            let merge_branch_change = MergeBranchChange::new_for_observer(
                self.changes
                    .clone()
                    .into_values()
                    .chain(once(changes.clone()))
                    .collect::<Vec<_>>(),
            );

            merge_branch_change.update(&mut upstream_art)?;

            upstream_art
        };

        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_secret_key())?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        self.upstream_art = PrivateZeroArt::new(
            upstream_art,
            Box::new(StdRng::from_rng(thread_rng()).unwrap()),
        );
        self.upstream_stk = upstream_stk;

        self.changes.insert(changes_id, changes.clone());

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        trace!("Resulted epoch: {}", self.epoch);

        info!("End merge changes");

        Ok(branch_stk)
    }

    #[instrument(skip_all)]
    pub(super) fn apply_changes(
        &mut self,
        changes: &BranchChange<CortadoAffine>,
    ) -> Result<StageKey> {
        info!("Start apply changes");

        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(postcard::to_allocvec(&changes)?).to_vec()
            [..8]
            .try_into()
            .unwrap();

        debug!("Changes ID: {:?}", changes_id);

        if self.changes.contains_key(&changes_id) {
            warn!("Changes already applied");
            return Err(Error::ChangesAlreadyApplied);
        }

        // Derive current stk and art
        let mut upstream_art = self.upstream_art.clone();

        let participant = if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
            info!("We advance epoch");
            upstream_art.update_key(secret_key)?;

            let participant = Participant {
                id: changes_id,
                branch: changes.clone(),
                art: upstream_art.get_private_art().clone(),
            };
            Some(participant)
        } else {
            info!("Other advance epoch");
            changes.update(&mut upstream_art)?;
            None
        };

        let upstream_stk =
            derive_stage_key(&self.upstream_stk, upstream_art.get_root_secret_key())?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        // Advance base
        self.base_art = self.upstream_art.get_private_art().clone();
        self.base_stk = self.upstream_stk;

        // Advance current
        self.upstream_art = upstream_art;
        self.upstream_stk = upstream_stk;

        self.participant = participant;
        self.changes = HashMap::new();
        self.changes.insert(changes_id, changes.clone());
        self.epoch += 1;

        trace!("Resulted base stage key: {:?}", self.base_stk);
        trace!("Resulted upstream stage key: {:?}", self.upstream_stk);
        trace!("Resulted base ART: {:?}", self.base_art);
        trace!("Resulted upstream ART: {:?}", self.upstream_art);
        info!("Epoch advanced to: {}", self.epoch);

        info!("End apply changes");

        Ok(self.upstream_stk)
    }
}
