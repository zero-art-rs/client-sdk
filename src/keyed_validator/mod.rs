use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng, thread_rng};
use sha3::{Digest, Sha3_256};
use tracing::instrument;
use zrt_art::art::{PrivateArt, PublicArt};
use zrt_art::art_node::{
    ArtNode, ArtNodePreview, LeafIter, LeafIterWithPath, LeafStatus, TreeMethods,
    TreeNodeIterWithPath,
};
use zrt_art::changes::branch_change::{BranchChange, BranchChangeType};
use zrt_art::node_index::NodeIndex;
use zrt_crypto::schnorr;
use zrt_zk::EligibilityRequirement;
use zrt_zk::engine::{ZeroArtProverEngine, ZeroArtVerifierEngine};

use crate::types::ChangeID;
use crate::{
    bounded_map::BoundedMap,
    errors::{Error, Result},
    models::frame,
    types::{GroupOperation, StageKey, ValidationResult, ValidationWithKeyResult},
    utils::deserialize,
};
use crate::{errors, models};
use cortado::{self, CortadoAffine, Fr as ScalarField};

mod handlers;
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

impl<R> KeyedValidator<R> {
    pub fn validate(&mut self, frame: &frame::Frame) -> Result<ValidationResult> {
        let (result, _) = self.validate_and_derive_key(frame)?;
        Ok(result)
    }

    pub fn tree(&self) -> &PublicArt<CortadoAffine> {
        &self.art.public_art()
    }

    pub fn tree_public_key(&self) -> CortadoAffine {
        self.art.public_art().root().public_key()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl<R> KeyedValidator<R> {
    #[instrument(skip_all, name = "validate", fields(current_epoch = %self.epoch, frame_epoch = %frame.frame_tbs().epoch()))]
    pub fn validate_and_derive_key(
        &mut self,
        frame: &frame::Frame,
    ) -> Result<ValidationWithKeyResult> {
        let frame_epoch = frame.frame_tbs().epoch();
        let is_next_epoch = frame_epoch == self.epoch + 1;
        if frame_epoch != self.epoch && !is_next_epoch {
            return Err(Error::InvalidEpoch);
        }

        if let models::frame::Proof::SchnorrSignature(signature) = frame.proof() {
            if is_next_epoch {
                return Err(Error::InvalidEpoch);
            }

            // Verify schnorr signature
            schnorr::verify(
                signature,
                &vec![self.art.public_art().preview().root().public_key()],
                &Sha3_256::digest(frame.frame_tbs().encode_to_vec()?),
            )?;

            return Ok((None, self.upstream_stk));
        }

        let proof = match frame.proof() {
            models::frame::Proof::ArtProof(proof) => proof,
            models::frame::Proof::SchnorrSignature(_) => unreachable!(),
        };

        let (change, eligibility_requirement, operation) = match (frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidInput)?, is_next_epoch) {
        (models::frame::GroupOperation::AddMember(change), true) => {
            let eligibility = EligibilityRequirement::Previleged((
            group_owner_leaf_public_key_preview(self.art.public_art().preview().root()),
            vec![],
        ));
        
    },
        (models::frame::GroupOperation::AddMember(change), false) => {
            EligibilityRequirement::Previleged((group_owner_leaf_public_key(self.art.public_art()), vec![]))
        }
        (models::frame::GroupOperation::KeyUpdate(change), true) => {
            EligibilityRequirement::Member(self.art.public_art().preview().node(&change.node_index)?.public_key())
        }
        (models::frame::GroupOperation::KeyUpdate(change), false) => {
            EligibilityRequirement::Member(self.art.public_art().node(&change.node_index)?.public_key())
        }
        (models::frame::GroupOperation::RemoveMember(change), true) => {
            let root = self.art.public_art().preview().root();
            match self.art
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
                LeafStatus::Blank => {
                    EligibilityRequirement::Member(root.public_key())
                }
                LeafStatus::PendingRemoval => {
                    EligibilityRequirement::Member(root.public_key())
                }
            }
        }
        (models::frame::GroupOperation::RemoveMember(change), false) => {
            match art
                .node(&change.node_index)?
                .status()
                .ok_or(Error::InvalidNode)?
            {
                LeafStatus::Active => EligibilityRequirement::Previleged((
                    group_owner_leaf_public_key(art.root()),
                    vec![],
                )),
                LeafStatus::Blank => EligibilityRequirement::Member(art.root().public_key()),
                LeafStatus::PendingRemoval => {
                    EligibilityRequirement::Member(art.root().public_key())
                }
            }
        }
        (models::frame::GroupOperation::LeaveGroup(change), true) => {
            EligibilityRequirement::Member(art.preview().node(&change.node_index)?.public_key())
        }
        (models::frame::GroupOperation::LeaveGroup(change), false) => {
            EligibilityRequirement::Member(art.node(&change.node_index)?.public_key())
        }
        (_, _) => unimplemented!()
    };

        let eligibility_requirement =
            get_eligibility_requirement(self.art.public_art(), change, is_next_epoch)?;
        let verification_branch = if is_next_epoch {
            self.art.preview().verification_branch(change)
        } else {
            self.art.verification_branch(change)
        }?;

        self.verifier_engine
            .new_context(eligibility_requirement)
            .for_branch(&verification_branch)
            .with_associated_data(&frame.frame_tbs().digest::<Sha3_256>()?)
            .verify(proof)
            .map_err(|_| Error::InvalidInput);

        let art_backup = self.art.clone();
        if is_next_epoch {
            self.art.commit()?
        }

        Err(Error::AesError)
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

    pub fn stage_key(&self) -> StageKey {
        self.upstream_stk
    }

    pub fn leaf_key(&self) -> ScalarField {
        self.art.leaf_secret_key()
    }

    pub fn tree_key(&self) -> ScalarField {
        self.art.root_secret_key()
    }
}

impl<R: Rng> KeyedValidator<R> {
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
            PrivateArt<CortadoAffine>,
            AggregationNode<bool>,
            Vec<BranchChange<CortadoAffine>>,
            StageKey,
            StageKey,
            u64,
            BoundedMap<ChangeID, ScalarField>,
        );

        let private_zero_art_parts = self.art.clone().into_parts();

        let parts: Parts = (
            private_zero_art_parts.0,
            private_zero_art_parts.1,
            private_zero_art_parts.2,
            private_zero_art_parts.3,
            self.upstream_stk,
            self.base_stk,
            self.epoch,
            self.participation_leafs.clone(),
        );
        postcard::to_allocvec(&parts).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        type Parts = (
            PrivateArt<CortadoAffine>,
            PrivateArt<CortadoAffine>,
            AggregationNode<bool>,
            Vec<BranchChange<CortadoAffine>>,
            StageKey,
            StageKey,
            u64,
            BoundedMap<ChangeID, ScalarField>,
        );
        let parts: Parts = postcard::from_bytes(value).map_err(|_| errors::Error::InvalidInput)?;

        Ok(Self {
            art: PrivateZeroArt::recover(
                parts.0,
                parts.1,
                parts.2,
                parts.3,
                Box::new(StdRng::from_rng(thread_rng()).unwrap()),
            )?,
            upstream_stk: parts.4,
            base_stk: parts.5,
            epoch: parts.6,
            participation_leafs: parts.7,
        })
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.art.get_node_index()
    }
}

#[cfg(test)]
mod tests;

fn group_owner_leaf_public_key<A: TreeMethods<Node = ArtNode<CortadoAffine>>>(
    art: &A,
) -> CortadoAffine {
    LeafIter::new(art.root())
        .next()
        .expect("ART can't be empty")
        .public_key()
}

fn group_owner_leaf_public_key_preview(art: ArtNodePreview<CortadoAffine>) -> CortadoAffine {
    for (node, _) in TreeNodeIterWithPath::new(art) {
        if node.is_leaf() {
            return node.public_key();
        }
    }

    panic!("ART can't be empty")
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
            EligibilityRequirement::Member(art.node(&change.node_index)?.public_key())
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
                .status()
                .ok_or(Error::InvalidNode)?
            {
                LeafStatus::Active => EligibilityRequirement::Previleged((
                    group_owner_leaf_public_key(art.root()),
                    vec![],
                )),
                LeafStatus::Blank => EligibilityRequirement::Member(art.root().public_key()),
                LeafStatus::PendingRemoval => {
                    EligibilityRequirement::Member(art.root().public_key())
                }
            }
        }
        (BranchChangeType::Leave, true) => {
            EligibilityRequirement::Member(art.preview().node(&change.node_index)?.public_key())
        }
        (BranchChangeType::Leave, false) => {
            EligibilityRequirement::Member(art.node(&change.node_index)?.public_key())
        }
    };

    Ok(eligibility_requirement)
}
