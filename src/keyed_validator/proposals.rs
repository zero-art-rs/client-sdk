use crate::{
    errors::{Error, Result},
    keyed_validator::{KeyedValidator, group_owner_leaf_public_key},
    types::{
        AddMemberProposal, Identifiable, LeaveGroupProposal, RemoveMemberProposal,
        UpdateKeyProposal,
    },
    utils::{derive_leaf_key, derive_stage_key},
};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use tracing::{debug, instrument};
use zrt_art::{
    art::ArtAdvancedOps,
    art_node::{LeafStatus, TreeMethods},
};

impl KeyedValidator {
    #[instrument(skip_all, fields(current_epoch = %self.epoch))]
    pub fn propose_add_member(&mut self, leaf_secret: ScalarField) -> Result<AddMemberProposal> {
        if self.leaf_public_key() != group_owner_leaf_public_key(self.art.get_upstream_art()) {
            return Err(Error::Forbidden);
        }

        let mut art = self.art.clone();
        art.commit()?;

        let change = art.add_member(leaf_secret)?;

        Ok(AddMemberProposal {
            stage_key: derive_stage_key(&self.upstream_stk, change.get_root_secret())?,
            change,
        })
    }

    #[instrument(skip_all)]
    pub fn propose_remove_member(
        &mut self,
        leaf_public_key: CortadoAffine,
        vanishing_secret_key: ScalarField,
    ) -> Result<RemoveMemberProposal> {
        let leaf = self
            .art
            .get_upstream_art()
            .get_leaf_with(leaf_public_key)?
            .clone();

        debug!("Leaf status: {:?}", leaf.get_status());

        if self.leaf_public_key() != group_owner_leaf_public_key(self.art.get_upstream_art())
            && matches!(leaf.get_status(), Some(LeafStatus::Active))
        {
            return Err(Error::Forbidden);
        }

        let change = self.art.remove_member(
            &self
                .art
                .get_upstream_art()
                .get_path_to_leaf_with(leaf_public_key)?
                .into(),
            vanishing_secret_key,
        )?;

        debug!("Eligibility artefact: {:?}", change.get_eligibility());
        debug!("Change ID: {}", change.id());

        Ok(RemoveMemberProposal {
            stage_key: derive_stage_key(&self.upstream_stk, change.get_root_secret())?,
            change,
        })
    }

    pub fn propose_update_key(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(
            &self.upstream_stk,
            self.art.get_upstream_art().get_leaf_secret_key(),
        )?;

        let change = self.art.update_key(secret_key)?;

        let stage_key = derive_stage_key(&self.upstream_stk, change.get_root_secret())?;

        self.participation_leafs.insert(change.id(), secret_key);

        Ok(UpdateKeyProposal { change, stage_key })
    }

    pub fn propose_leave_group(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(
            &self.upstream_stk,
            self.art.get_upstream_art().get_leaf_secret_key(),
        )?;

        let change = self.art.leave_group(secret_key)?;

        let stage_key = derive_stage_key(&self.upstream_stk, change.get_root_secret())?;

        self.participation_leafs.insert(change.id(), secret_key);

        Ok(LeaveGroupProposal {
            change: change,
            stage_key,
        })
    }
}
