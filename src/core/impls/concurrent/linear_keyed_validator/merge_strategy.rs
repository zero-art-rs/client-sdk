use std::{collections::HashMap, iter::once};

use crate::{
    core::impls::concurrent::linear_keyed_validator::{LinearKeyedValidator, Participant},
    errors::{Error, Result},
    types::{ChangesID, StageKey},
    utils::derive_stage_key,
};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use sha3::{Digest, Sha3_256};
use tracing::{debug, info, instrument, trace, warn};
use zrt_art::{traits::ARTPrivateAPI, types::BranchChanges};

impl LinearKeyedValidator {
    pub(super) fn merge_changes_and_participate(
        &mut self,
        changes_id: ChangesID,
        changes: BranchChanges<CortadoAffine>,
        secret_key: ScalarField,
    ) -> Result<StageKey> {
        let mut upstream_art = self.base_art.clone();
        let (tree_key, _, _) = upstream_art.update_key(&secret_key)?;
        let branch_stk = derive_stage_key(&self.base_stk, tree_key.key)?;
        trace!("Branch stage key: {:?}", branch_stk);

        let participant = Participant {
            id: changes_id,
            branch: changes.clone(),
            art: upstream_art.clone(),
        };

        upstream_art.merge_for_participant(
            changes.clone(),
            &self
                .changes
                .values()
                .cloned()
                .collect::<Vec<BranchChanges<CortadoAffine>>>(),
            self.base_art.clone(),
        )?;
        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        self.upstream_art = upstream_art;
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
        changes: &BranchChanges<CortadoAffine>,
    ) -> Result<StageKey> {
        info!("Start merge changes");

        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
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
        branch_art.update_private_art(changes)?;
        let branch_stk = derive_stage_key(&self.base_stk, branch_art.get_root_key()?.key)?;
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

            upstream_art.merge_for_participant(
                participant.branch.clone(),
                &target_changes,
                self.base_art.clone(),
            )?;

            upstream_art
        } else {
            let mut upstream_art = self.base_art.clone();
            upstream_art.merge_for_observer(
                &self
                    .changes
                    .clone()
                    .into_values()
                    .chain(once(changes.clone()))
                    .collect::<Vec<_>>(),
            )?;

            upstream_art
        };

        let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        self.upstream_art = upstream_art;
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
        changes: &BranchChanges<CortadoAffine>,
    ) -> Result<StageKey> {
        info!("Start apply changes");

        trace!("Initial base stage key: {:?}", self.base_stk);
        trace!("Initial upstream stage key: {:?}", self.upstream_stk);
        trace!("Initial base ART: {:?}", self.base_art);
        trace!("Initial upstream ART: {:?}", self.upstream_art);
        trace!("Initial epoch: {}", self.epoch);

        // Should never panic
        let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
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
            upstream_art.update_key(&secret_key)?;

            let participant = Participant {
                id: changes_id,
                branch: changes.clone(),
                art: upstream_art.clone(),
            };
            Some(participant)
        } else {
            info!("Other advance epoch");
            upstream_art.update_private_art(changes)?;
            None
        };

        let upstream_stk = derive_stage_key(&self.upstream_stk, upstream_art.get_root_key()?.key)?;
        trace!("Upstream stage key: {:?}", upstream_stk);

        // Advance base
        self.base_art = self.upstream_art.clone();
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
