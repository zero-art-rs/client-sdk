use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng, thread_rng};
use sha3::{Digest, Sha3_256};
use std::fmt::{Debug, Formatter};
use std::ops::Mul;
use tracing::{debug, error, instrument, trace};
use zrt_art::art::{PrivateArt, PublicArt};
use zrt_art::art_node::{ArtNode, ArtNodePreview, LeafStatus, TreeMethods};
use zrt_art::changes::branch_change::{BranchChange, BranchChangeType};
use zrt_art::node_index::NodeIndex;
use zrt_crypto::schnorr;
use zrt_zk::EligibilityRequirement;
use zrt_zk::engine::{ZeroArtProverEngine, ZeroArtVerifierEngine};

use crate::contexts::group::GroupContext;
use crate::types::{ChangeID, Identifiable, Proposal};
use crate::utils::derive_stage_key;
use crate::{
    bounded_map::BoundedMap,
    errors::{Error, Result},
    models::frame,
    types::{GroupOperation, StageKey, ValidationResult, ValidationWithKeyResult},
    utils::deserialize,
};
use crate::{errors, models};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use prost_types::field_descriptor_proto::Type::Group;
use rand_core::CryptoRngCore;
use zrt_art::changes::ApplicableChange;
use zrt_zk::art::ArtProof;

// mod handlers;
// mod merge_strategy;
mod proposals;

pub struct KeyedValidator<R> {
    art: PrivateArt<CortadoAffine>,

    upstream_stk: StageKey,
    base_stk: StageKey,

    epoch: u64,

    participation_leafs: BoundedMap<ChangeID, ScalarField>,

    prover_engine: ZeroArtProverEngine,
    verifier_engine: ZeroArtVerifierEngine,
    rng: R,
}

impl<R> Debug for KeyedValidator<R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyedValidator")
            .field("art", &self.art)
            .field("upstream_stk", &self.upstream_stk)
            .field("base_stk", &self.base_stk)
            .field("epoch", &self.epoch)
            .field("participation_leafs", &self.participation_leafs)
            .finish()
    }
}

impl<R> KeyedValidator<R> {
    pub fn validate(&mut self, frame: &frame::Frame) -> Result<ValidationResult> {
        let (result, _) = self.validate_and_derive_key(frame)?;
        Ok(result)
    }

    pub fn tree(&self) -> &PublicArt<CortadoAffine> {
        &self.art.public_art()
    }

    pub fn tree_public_key(&self) -> CortadoAffine {
        self.art.public_art().root().data().public_key()
    }

    pub fn tree_public_key_preview(&self) -> CortadoAffine {
        self.art.public_art().preview().root().public_key()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn prove(
        &mut self,
        proposal: &Proposal<CortadoAffine>,
        associated_data: &[u8],
    ) -> Result<ArtProof>
    where
        R: CryptoRngCore,
    {
        debug!(
            eligibility_artefact = ?proposal.eligibility_artefact,
            "prove_schnorr"
        );

        let art_proof = self
            .prover_engine
            .new_context(proposal.eligibility_artefact.clone())
            .for_branch(&proposal.prover_branch)
            .with_associated_data(associated_data)
            .prove(&mut self.rng)?;

        Ok(art_proof)
    }
}

impl<R> KeyedValidator<R> {
    #[instrument(skip_all, target = "validator", level = "debug", fields(frame_id = %frame.id()))]
    pub fn validate_and_derive_key(
        &mut self,
        frame: &frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        debug!(
            epoch = self.epoch,
            frame_epoch = frame.frame_tbs().epoch(),
            "Start frame validation and key derivation"
        );

        let frame_epoch = frame.frame_tbs().epoch();
        let is_next_epoch = frame_epoch == self.epoch + 1;
        if frame_epoch != self.epoch && !is_next_epoch {
            return Err(Error::InvalidEpoch);
        }

        debug!(is_next_epoch);

        if let models::frame::Proof::SchnorrSignature(signature) = frame.proof() {
            debug!("Frame proof is schnorr signature");
            if is_next_epoch {
                return Err(Error::InvalidEpoch);
            }

            let frame_operation = frame.frame_tbs().group_operation();

            match frame_operation {
                Some(models::frame::GroupOperation::Init(_)) => {
                    // Verify schnorr signature
                    let public_key =
                        CortadoAffine::deserialize_compressed(&*frame.frame_tbs().nonce())?;

                    schnorr::verify(
                        signature,
                        &vec![public_key],
                        &Sha3_256::digest(frame.frame_tbs().encode_to_vec()?),
                    )
                    .inspect_err(|err| {
                        error!(
                            public_key = ?public_key,
                            "Failed to verify schnorr signature for GroupOperation::Init: {err}.",
                        )
                    })?;

                    let operation = GroupOperation::<CortadoAffine>::Init;

                    return Ok((Some(operation), self.upstream_stk));
                }
                None => {
                    // Verify schnorr signature
                    let public_key = self.art.public_art().preview().root().public_key();
                    // let public_key = self.art.public_art().preview().root().public_key();
                    schnorr::verify(
                        signature,
                        &vec![public_key],
                        &Sha3_256::digest(frame.frame_tbs().encode_to_vec()?),
                    )
                    .inspect_err(|err| {
                        error!(
                            public_key = ?public_key,
                            "Failed to verify schnorr signature for GroupOperation::Init: {err}.",
                        )
                    })?;
                }
                _ => todo!(),
            }

            return Ok((None, self.upstream_stk));
        }

        let proof = match frame.proof() {
            models::frame::Proof::ArtProof(proof) => proof,
            models::frame::Proof::SchnorrSignature(_) => unreachable!(),
        };

        let frame_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidInput)?;
        let (change, eligibility_requirement, operation) = match (frame_operation, is_next_epoch) {
            (models::frame::GroupOperation::AddMember(change), true) => {
                let eligibility_requirement = EligibilityRequirement::Previleged((
                    group_owner_leaf_public_key_preview(self.art.public_art().preview().root()),
                    vec![],
                ));

                let operation = GroupOperation::AddMember {
                    member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::AddMember(change), false) => {
                let operation = GroupOperation::AddMember {
                    member_public_key: *change.public_keys.last().ok_or(Error::InvalidInput)?,
                };

                return Ok((Some(operation), self.upstream_stk));
            }
            (models::frame::GroupOperation::KeyUpdate(change), true) => {
                let eligibility_requirement = EligibilityRequirement::Member(
                    self.art
                        .public_art()
                        .preview()
                        .node(&change.node_index)?
                        .public_key(),
                );

                let old_public_key = self.art.preview().node(&change.node_index)?.public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::KeyUpdate(change), false) => {
                let eligibility_requirement = EligibilityRequirement::Member(
                    self.art
                        .public_art()
                        .node(&change.node_index)?
                        .data()
                        .public_key(),
                );

                let old_public_key = self.art.node(&change.node_index)?.data().public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::KeyUpdate {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::RemoveMember(change), true) => {
                if self.art.node_index().eq(&change.node_index) {
                    return Err(Error::UserRemovedFromGroup);
                }

                let root = self.art.public_art().preview().root();
                let eligibility_requirement = match self
                    .art
                    .public_art()
                    .preview()
                    .node(&change.node_index)?
                    .status()
                    .ok_or(Error::InvalidNode)?
                {
                    LeafStatus::Active => EligibilityRequirement::Previleged((
                        group_owner_leaf_public_key_preview(root),
                        vec![],
                    )),
                    LeafStatus::Blank => EligibilityRequirement::Member(root.public_key()),
                    LeafStatus::PendingRemoval => EligibilityRequirement::Member(root.public_key()),
                };

                let old_public_key = self
                    .art
                    .public_art()
                    .preview()
                    .node(&change.node_index)?
                    .public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::RemoveMember {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::RemoveMember(change), false) => {
                if self.art.node_index().eq(&change.node_index) {
                    return Err(Error::UserRemovedFromGroup);
                }

                let eligibility_requirement = match self
                    .art
                    .public_art()
                    .node(&change.node_index)?
                    .data()
                    .status()
                    .ok_or(Error::InvalidNode)?
                {
                    LeafStatus::Active => EligibilityRequirement::Previleged((
                        group_owner_leaf_public_key(self.art.root()),
                        vec![],
                    )),
                    LeafStatus::Blank => {
                        EligibilityRequirement::Member(self.art.root().data().public_key())
                    }
                    LeafStatus::PendingRemoval => {
                        EligibilityRequirement::Member(self.art.root().data().public_key())
                    }
                };

                let old_public_key = self.art.node(&change.node_index)?.data().public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::RemoveMember {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::LeaveGroup(change), true) => {
                // if self.art.node_index().eq(&change.node_index) {
                //     return Err(Error::UserRemovedFromGroup)
                // }

                let eligibility_requirement = EligibilityRequirement::Member(
                    self.art.preview().node(&change.node_index)?.public_key(),
                );

                let old_public_key = self.art.preview().node(&change.node_index)?.public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (models::frame::GroupOperation::LeaveGroup(change), false) => {
                // if self.art.node_index().eq(&change.node_index) {
                //     return Err(Error::UserRemovedFromGroup)
                // }

                let eligibility_requirement = EligibilityRequirement::Member(
                    self.art.node(&change.node_index)?.data().public_key(),
                );

                let old_public_key = self.art.preview().node(&change.node_index)?.public_key();
                let new_public_key = *change.public_keys.last().ok_or(Error::InvalidInput)?;
                let operation = GroupOperation::LeaveGroup {
                    old_public_key,
                    new_public_key,
                };

                (change, eligibility_requirement, operation)
            }
            (_, _) => unimplemented!(),
        };

        debug!(
            operation = ?operation,
            is_next_epoch = ?is_next_epoch,
            "GroupOperation data"
        );

        // let eligibility_requirement =
        //     get_eligibility_requirement(self.art.public_art(), change, is_next_epoch)?;
        let verification_branch = if is_next_epoch {
            self.art
                .preview()
                .verification_branch(change)
                .inspect_err(|err| {
                    error!(
                        "Failed to retrieve verification branch for next epoch: {}",
                        err
                    )
                })?
        } else {
            self.art.verification_branch(change).inspect_err(|err| {
                error!(
                    "Failed to retrieve verification branch for current epoch: {}",
                    err
                )
            })?
        };

        self.verifier_engine
            .new_context(eligibility_requirement)
            .for_branch(&verification_branch)
            .with_associated_data(&frame.frame_tbs().digest::<Sha3_256>()?)
            .verify(proof)?;

        if is_next_epoch {
            self.art.commit()?;
            self.epoch += 1;
        }

        let root_secret_key = if let Some(secret_key) = self.participation_leafs.get(&change.id()) {
            secret_key
                .apply(&mut self.art)
                .inspect_err(|err| error!("Fail to apply own key update or leave: {err}"))?
        } else {
            change
                .apply(&mut self.art)
                .inspect_err(|err| error!("Fail to apply change: {err}"))?
        };

        // let root_secret_key = change.apply(&mut self.art)?;
        // self.art.apply::<BranchChange<_>, _>(&change)?;

        let stage_key = if is_next_epoch {
            let stage_key = derive_stage_key(&self.upstream_stk, root_secret_key)?;
            // let upstream_stk =
            //     derive_stage_key(&self.upstream_stk, self.art.secrets().preview().root())?;

            self.base_stk = self.upstream_stk;
            self.upstream_stk = stage_key;

            stage_key
        } else {
            let stage_key = derive_stage_key(&self.base_stk, root_secret_key)?;
            let upstream_stk =
                derive_stage_key(&self.base_stk, self.art.secrets().preview().root())?;

            self.upstream_stk = upstream_stk;

            stage_key
        };

        Ok((Some(operation), stage_key))

        // Err(Error::AesError)
    }

    pub fn sign_with_leaf_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.art.leaf_secret_key()],
            &vec![self.art.leaf_public_key()],
            message,
        )?)
    }

    pub fn sign_with_tree_key(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(schnorr::sign(
            &vec![self.art.root_secret_key()],
            &vec![self.art.root_public_key()],
            message,
        )?)
    }

    pub fn leaf_public_key(&self) -> CortadoAffine {
        self.art.leaf_public_key()
    }

    pub fn leaf_public_key_preview(&self) -> CortadoAffine {
        let leaf_key_preview = self.art.secrets().preview().leaf();
        CortadoAffine::generator()
            .mul(leaf_key_preview)
            .into_affine()
    }

    pub fn stage_key(&self) -> StageKey {
        self.upstream_stk
    }

    pub fn leaf_key(&self) -> ScalarField {
        self.art.leaf_secret_key()
    }

    pub fn tree_key(&self) -> ScalarField {
        self.art.root_secret_key()
    }

    pub fn tree_key_preview(&self) -> ScalarField {
        self.art.secrets().preview().root()
    }
}

impl<R> KeyedValidator<R> {
    pub fn new(art: PrivateArt<CortadoAffine>, base_stk: StageKey, epoch: u64, rng: R) -> Self {
        Self {
            art,
            upstream_stk: base_stk,
            base_stk,
            epoch,
            participation_leafs: BoundedMap::with_capacity(8),
            verifier_engine: ZeroArtVerifierEngine::default(),
            prover_engine: ZeroArtProverEngine::default(),
            rng,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        type Parts = (
            PrivateArt<CortadoAffine>,
            StageKey,
            StageKey,
            u64,
            BoundedMap<ChangeID, ScalarField>,
        );

        let parts: Parts = (
            self.art.clone(),
            self.upstream_stk,
            self.base_stk,
            self.epoch,
            self.participation_leafs.clone(),
        );
        postcard::to_allocvec(&parts).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8], rng: R) -> Result<Self> {
        type Parts = (
            PrivateArt<CortadoAffine>,
            StageKey,
            StageKey,
            u64,
            BoundedMap<ChangeID, ScalarField>,
        );
        let parts: Parts = postcard::from_bytes(value).map_err(|_| errors::Error::InvalidInput)?;

        Ok(Self {
            art: parts.0,
            upstream_stk: parts.1,
            base_stk: parts.2,
            epoch: parts.3,
            participation_leafs: parts.4,
            prover_engine: Default::default(),
            verifier_engine: Default::default(),
            rng,
        })
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.art.node_index()
    }
}

#[cfg(test)]
mod tests;

fn group_owner_leaf_public_key<A: TreeMethods<Node = ArtNode<CortadoAffine>>>(
    art: &A,
) -> CortadoAffine {
    art.root()
        .leaf_iter()
        .next()
        .expect("ART can't be empty")
        .data()
        .public_key()
}

fn group_owner_leaf_public_key_preview(art: ArtNodePreview<CortadoAffine>) -> CortadoAffine {
    art.leaf_iter()
        .next()
        .expect("ART can't be empty")
        .public_key()
}

fn get_eligibility_requirement(
    art: &PublicArt<CortadoAffine>,
    change: &BranchChange<CortadoAffine>,
    is_next_epoch: bool,
) -> Result<EligibilityRequirement> {
    let eligibility_requirement = match (change.change_type, is_next_epoch) {
        (BranchChangeType::AddMember, true) => EligibilityRequirement::Previleged((
            group_owner_leaf_public_key_preview(art.preview().root()),
            vec![],
        )),
        (BranchChangeType::AddMember, false) => {
            EligibilityRequirement::Previleged((group_owner_leaf_public_key(art), vec![]))
        }
        (BranchChangeType::UpdateKey, true) => {
            EligibilityRequirement::Member(art.preview().node(&change.node_index)?.public_key())
        }
        (BranchChangeType::UpdateKey, false) => {
            EligibilityRequirement::Member(art.node(&change.node_index)?.data().public_key())
        }
        (BranchChangeType::RemoveMember, true) => {
            match art
                .preview()
                .node(&change.node_index)?
                .status()
                .ok_or(Error::InvalidNode)?
            {
                LeafStatus::Active => EligibilityRequirement::Previleged((
                    group_owner_leaf_public_key_preview(art.preview().root()),
                    vec![],
                )),
                LeafStatus::Blank => {
                    EligibilityRequirement::Member(art.preview().root().public_key())
                }
                LeafStatus::PendingRemoval => {
                    EligibilityRequirement::Member(art.preview().root().public_key())
                }
            }
        }
        (BranchChangeType::RemoveMember, false) => {
            match art
                .node(&change.node_index)?
                .data()
                .status()
                .ok_or(Error::InvalidNode)?
            {
                LeafStatus::Active => EligibilityRequirement::Previleged((
                    group_owner_leaf_public_key(art.root()),
                    vec![],
                )),
                LeafStatus::Blank => EligibilityRequirement::Member(art.root().data().public_key()),
                LeafStatus::PendingRemoval => {
                    EligibilityRequirement::Member(art.root().data().public_key())
                }
            }
        }
        (BranchChangeType::Leave, true) => {
            EligibilityRequirement::Member(art.preview().node(&change.node_index)?.public_key())
        }
        (BranchChangeType::Leave, false) => {
            EligibilityRequirement::Member(art.node(&change.node_index)?.data().public_key())
        }
    };

    Ok(eligibility_requirement)
}
