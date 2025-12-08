use crate::{
    errors::{Error, Result},
    keyed_validator::{KeyedValidator, group_owner_leaf_public_key_preview},
    types::{
        AddMemberProposal, Identifiable, LeaveGroupProposal, RemoveMemberProposal,
        UpdateKeyProposal,
    },
    utils::{derive_leaf_key, derive_stage_key},
};
use ark_ec::{AffineRepr, CurveGroup};
use cortado::{self, CortadoAffine, Fr as ScalarField, Fr};
use std::ops::Mul;
use tracing::{debug, error, instrument};
use zrt_art::{
    art::ArtAdvancedOps,
    art_node::{LeafStatus, TreeMethods},
};
use zrt_zk::EligibilityArtefact;

impl<R> KeyedValidator<R> {
    #[instrument(skip_all, fields(current_epoch = %self.epoch))]
    pub fn propose_add_member(&mut self, leaf_secret: ScalarField) -> Result<AddMemberProposal> {
        let owner_leaf_public_key = group_owner_leaf_public_key_preview(self.art.preview().root());
        if self.leaf_public_key_preview() != owner_leaf_public_key {
            return Err(Error::Forbidden);
        }

        let (tk, change, prover_branch) = self.art.add_member(leaf_secret)?;
        let leaf_sk = self.art.secrets().preview().leaf();
        let leaf_pk = CortadoAffine::generator().mul(leaf_sk).into_affine();

        Ok(AddMemberProposal {
            stage_key: derive_stage_key(&self.upstream_stk, tk)?,
            prover_branch,
            change,
            eligibility_artefact: EligibilityArtefact::Owner((leaf_sk, leaf_pk)),
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
            .public_art()
            .preview()
            .root()
            .leaf_with(leaf_public_key)?
            .clone();

        let own_leaf_public_key = self.leaf_public_key_preview();
        let owner_leaf_public_key = group_owner_leaf_public_key_preview(self.art.preview().root());

        let is_owner = own_leaf_public_key == owner_leaf_public_key;

        let eligibility_artefact = match leaf.status() {
            None => {
                error!("Node with LeafStatus = None, is internal, and impossible to remove.");
                return Err(Error::Forbidden);
            }
            Some(LeafStatus::Active) => {
                if is_owner {
                    let leaf_sk = self.art.secrets().preview().leaf();
                    let leaf_pk = CortadoAffine::generator().mul(leaf_sk).into_affine();
                    EligibilityArtefact::Owner((leaf_sk, leaf_pk))
                } else {
                    error!("Only owner can remove member with LeafStatus::Active.");
                    return Err(Error::Forbidden);
                }
            }
            Some(LeafStatus::Blank | LeafStatus::PendingRemoval) => {
                let root_sk = self.art.secrets().preview().root();
                let root_pk = CortadoAffine::generator().mul(root_sk).into_affine();
                EligibilityArtefact::Member((root_sk, root_pk))
            }
        };

        let (tk, change, prover_branch) = self.art.remove_member(
            &self
                .art
                .public_art()
                .preview()
                .root()
                .path_to_leaf_with(leaf_public_key)?
                .into(),
            vanishing_secret_key,
        )?;

        // debug!("Eligibility artefact: {:?}", change.get_eligibility());
        // debug!("Change ID: {}", change.id());

        Ok(RemoveMemberProposal {
            stage_key: derive_stage_key(&self.upstream_stk, tk)?,
            prover_branch,
            change,
            eligibility_artefact,
        })
    }

    pub fn propose_update_key(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.art.secrets().preview().leaf())?;

        let (tk, change, prover_branch) = self.art.update_key(secret_key)?;

        let stage_key = derive_stage_key(&self.upstream_stk, tk)?;

        self.participation_leafs.insert(change.id(), secret_key);

        let leaf_sk = self.art.secrets().preview().leaf();
        let leaf_pk = CortadoAffine::generator().mul(leaf_sk).into_affine();
        let eligibility_artefact = EligibilityArtefact::Member((leaf_sk, leaf_pk));

        Ok(UpdateKeyProposal {
            change,
            stage_key,
            prover_branch,
            eligibility_artefact,
        })
    }

    pub fn propose_leave_group(&mut self) -> Result<UpdateKeyProposal> {
        let secret_key = derive_leaf_key(&self.upstream_stk, self.art.secrets().preview().leaf())?;

        let (tk, change, prover_branch) = self.art.leave_group(secret_key)?;

        let stage_key = derive_stage_key(&self.upstream_stk, tk)?;

        self.participation_leafs.insert(change.id(), secret_key);

        let leaf_sk = self.art.secrets().preview().leaf();
        let leaf_pk = CortadoAffine::generator().mul(leaf_sk).into_affine();
        let eligibility_artefact = EligibilityArtefact::Member((leaf_sk, leaf_pk));

        Ok(LeaveGroupProposal {
            change,
            stage_key,
            prover_branch,
            eligibility_artefact,
        })
    }
}
