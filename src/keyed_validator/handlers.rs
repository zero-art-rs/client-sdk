use crate::{
    errors::{self, Error, Result},
    keyed_validator::{KeyedValidator, group_owner_leaf_public_key},
    models,
    types::{GroupOperation, Identifiable, ValidationWithKeyResult},
    utils::derive_stage_key,
};
use cortado::{self, CortadoAffine};
use sha3::{Digest, Sha3_256};
use tracing::{debug, instrument};
use zrt_art::{
    art::PublicArt,
    art_node::{LeafStatus, TreeMethods},
    changes::{ApplicableChange, branch_change::BranchChange},
};
use zrt_zk::{EligibilityRequirement, engine::ZeroArtVerifierEngine};

impl<R> KeyedValidator<R> {
    pub(super) fn handle_add_member_as_merge(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let owner_public_key = group_owner_leaf_public_key(self.art.public_art());

        let verifier = ZeroArtVerifierEngine::default();

        let proof = match frame.proof() {
            models::frame::Proof::ArtProof(proof) => proof,
            models::frame::Proof::SchnorrSignature(_) => return Err(Error::ArtLogicError),
        };

        verifier
            .new_context(EligibilityRequirement::Previleged((
                owner_public_key,
                vec![],
            )))
            .for_branch(&self.art.verification_branch(change)?)
            .with_associated_data(&Sha3_256::digest(frame.frame_tbs().encode_to_vec()?))
            .verify(proof)
            .map_err(|_| Error::InvalidInput);

        let operation = GroupOperation::AddMember {
            member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        return Ok((Some(operation), self.upstream_stk));
    }

    pub(super) fn handle_add_member(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        debug!("change: {}", change.id());
        let public_zero_art =
            PublicZeroArt::new(self.art.get_upstream_art().get_public_art().clone())?;
        let public_key = group_owner_leaf_public_key(self.art.get_upstream_art().get_public_art());

        frame.verify_art::<Sha3_256>(
            change.clone(),
            public_zero_art,
            zrt_zk::EligibilityRequirement::Previleged((public_key, vec![])),
        )?;
        debug!("change2: {}", change.id());
        let operation = GroupOperation::AddMember {
            member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();
        art.commit()?;
        let root_secret_key = change.apply(&mut art)?;

        let stage_key = derive_stage_key(&self.upstream_stk, root_secret_key)?;
        self.art = art;
        self.base_stk = self.upstream_stk;
        self.upstream_stk = stage_key;
        self.epoch += 1;

        Ok((Some(operation), stage_key))
    }

    pub(super) fn handle_remove_member_as_merge(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        if *self.art.get_node_index() == change.node_index {
            return Err(Error::UserRemovedFromGroup);
        }

        let public_zero_art = PublicZeroArt::new(self.art.get_base_art().get_public_art().clone())?;
        let eligibility = if LeafStatus::Active
            != self
                .art
                .get_base_art()
                .get_node(&change.node_index)?
                .get_status()
                .ok_or(Error::InvalidInput)?
        {
            EligibilityRequirement::Member(self.art.get_base_art().get_root_public_key())
        } else {
            EligibilityRequirement::Previleged((
                group_owner_leaf_public_key(self.art.get_base_art()),
                vec![],
            ))
        };

        frame.verify_art::<Sha3_256>(change.clone(), public_zero_art, eligibility)?;

        let member_public_key = self
            .art
            .get_base_art()
            .get_node(&change.node_index)?
            .get_public_key();

        let operation = GroupOperation::RemoveMember {
            old_public_key: member_public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();
        let root_secret_key = change.apply(&mut art)?;
        let stage_key = derive_stage_key(&self.base_stk, root_secret_key)?;

        let upstream_stk =
            derive_stage_key(&self.base_stk, art.get_upstream_art().get_root_secret_key())?;

        self.art = art;
        self.upstream_stk = upstream_stk;

        Ok((Some(operation), stage_key))
    }

    #[instrument(skip_all)]
    pub(super) fn handle_remove_member(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        debug!("Change ID: {}", change.id());

        if *self.art.get_node_index() == change.node_index {
            return Err(Error::UserRemovedFromGroup);
        }

        let public_zero_art =
            PublicZeroArt::new(self.art.get_upstream_art().get_public_art().clone())?;
        let status = self
            .art
            .get_upstream_art()
            .get_node(&change.node_index)?
            .get_status()
            .ok_or(Error::InvalidInput)?;

        debug!("Leaf status: {:?}", status);

        let eligibility = if LeafStatus::Active != status {
            debug!("Eligibility member");
            EligibilityRequirement::Member(self.art.get_upstream_art().get_root_public_key())
        } else {
            EligibilityRequirement::Previleged((
                group_owner_leaf_public_key(self.art.get_upstream_art()),
                vec![],
            ))
        };

        frame.verify_art::<Sha3_256>(change.clone(), public_zero_art, eligibility)?;

        let member_public_key = self
            .art
            .get_upstream_art()
            .get_node(&change.node_index)?
            .get_public_key();

        let operation = GroupOperation::RemoveMember {
            old_public_key: member_public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();
        art.commit()?;

        let root_secret_key = change.apply(&mut art)?;
        let stage_key = derive_stage_key(&self.upstream_stk, root_secret_key)?;

        self.base_stk = self.upstream_stk;
        self.upstream_stk = stage_key;
        self.epoch += 1;

        Ok((Some(operation), stage_key))
    }

    pub(super) fn handle_update_key_as_merge(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let public_zero_art = PublicZeroArt::new(self.art.get_base_art().get_public_art().clone())?;
        let public_key = self
            .art
            .get_base_art()
            .get_node(&change.node_index)?
            .get_public_key();

        frame.verify_art::<Sha3_256>(
            change.clone(),
            public_zero_art,
            zrt_zk::EligibilityRequirement::Member(public_key),
        )?;
        let operation = GroupOperation::KeyUpdate {
            old_public_key: public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();

        let root_secret_key = if let Some(secret_key) = self.participation_leafs.get(&change.id()) {
            secret_key.apply(&mut art)?
        } else {
            change.apply(&mut art)?
        };

        let stage_key = derive_stage_key(&self.base_stk, root_secret_key)?;

        let upstream_stk =
            derive_stage_key(&self.base_stk, art.get_upstream_art().get_root_secret_key())?;

        self.art = art;
        self.upstream_stk = upstream_stk;

        Ok((Some(operation), stage_key))
    }

    pub(super) fn handle_update_key(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let public_zero_art =
            PublicZeroArt::new(self.art.get_upstream_art().get_public_art().clone())?;
        let public_key = self
            .art
            .get_upstream_art()
            .get_node(&change.node_index)?
            .get_public_key();

        frame.verify_art::<Sha3_256>(
            change.clone(),
            public_zero_art,
            zrt_zk::EligibilityRequirement::Member(public_key),
        )?;
        let operation = GroupOperation::KeyUpdate {
            old_public_key: public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();
        art.commit()?;

        let root_secret_key = if let Some(secret_key) = self.participation_leafs.get(&change.id()) {
            secret_key.apply(&mut art)?
        } else {
            change.apply(&mut art)?
        };

        let stage_key = derive_stage_key(&self.upstream_stk, root_secret_key)?;

        self.art = art;
        self.base_stk = self.upstream_stk;
        self.upstream_stk = stage_key;
        self.epoch += 1;

        Ok((Some(operation), stage_key))
    }

    pub(super) fn handle_leave_group_as_merge(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let public_zero_art = PublicZeroArt::new(self.art.get_base_art().get_public_art().clone())?;
        let public_key = self
            .art
            .get_base_art()
            .get_node(&change.node_index)?
            .get_public_key();

        frame.verify_art::<Sha3_256>(
            change.clone(),
            public_zero_art,
            zrt_zk::EligibilityRequirement::Member(public_key),
        )?;
        let operation = GroupOperation::LeaveGroup {
            old_public_key: public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();

        let root_secret_key = if let Some(secret_key) = self.participation_leafs.get(&change.id()) {
            secret_key.apply(&mut art)?
        } else {
            change.apply(&mut art)?
        };

        let stage_key = derive_stage_key(&self.base_stk, root_secret_key)?;

        let upstream_stk =
            derive_stage_key(&self.base_stk, art.get_upstream_art().get_root_secret_key())?;

        self.art = art;
        self.upstream_stk = upstream_stk;

        Ok((Some(operation), stage_key))
    }

    pub(super) fn handle_leave_group(
        &mut self,
        change: &BranchChange<CortadoAffine>,
        frame: &models::frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let public_zero_art =
            PublicZeroArt::new(self.art.get_upstream_art().get_public_art().clone())?;
        let public_key = self
            .art
            .get_upstream_art()
            .get_node(&change.node_index)?
            .get_public_key();

        frame.verify_art::<Sha3_256>(
            change.clone(),
            public_zero_art,
            zrt_zk::EligibilityRequirement::Member(public_key),
        )?;

        let operation = GroupOperation::LeaveGroup {
            old_public_key: public_key,
            new_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
        };

        let mut art = self.art.clone();
        art.commit()?;

        let root_secret_key = if let Some(secret_key) = self.participation_leafs.get(&change.id()) {
            secret_key.apply(&mut art)?
        } else {
            change.apply(&mut art)?
        };

        let stage_key = derive_stage_key(&self.upstream_stk, root_secret_key)?;

        self.art = art;
        self.base_stk = self.upstream_stk;
        self.upstream_stk = stage_key;
        self.epoch += 1;

        Ok((Some(operation), stage_key))
    }
}
