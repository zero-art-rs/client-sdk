use std::cmp::max;

use ark_ec::{AffineRepr, CurveGroup};
use serde::{Deserialize, Serialize};
use zrt_art::art_node::LeafStatus;

use crate::trees::binary_tree::BinaryTree;

pub struct MergeTree<G: AffineRepr>(BinaryTree<MtNodeData<G>>);

/// Merge tree node data
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
pub struct MtNodeData<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) strong_key: Option<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) weak_key: Option<G>,
    pub(crate) status: Option<LeafStatus>,
    pub(crate) weight_change: i32,
}

impl<G> MtNodeData<G>
where
    G: AffineRepr,
{
    pub fn new(
        strong_key: Option<G>,
        weak_key: Option<G>,
        status: Option<LeafStatus>,
        weight_change: i32,
    ) -> Self {
        Self {
            weak_key,
            strong_key,
            status,
            weight_change,
        }
    }
    pub fn weak_key(&self) -> Option<G> {
        self.weak_key
    }

    pub fn mut_weak_key(&mut self) -> &mut Option<G> {
        &mut self.weak_key
    }

    pub fn strong_key(&self) -> Option<G> {
        self.strong_key
    }

    pub fn mut_strong_key(&mut self) -> &mut Option<G> {
        &mut self.strong_key
    }

    pub fn status(&self) -> Option<LeafStatus> {
        self.status
    }

    pub fn update_weight_change(&mut self, increment: bool) {
        if increment {
            self.weight_change += 1;
        } else {
            self.weight_change -= 1;
        }
    }

    pub fn update_status(&mut self, status: LeafStatus) {
        if let Some(inner_status) = &mut self.status {
            *inner_status = max(status, *inner_status);
        } else {
            self.status = Some(status);
        }
    }

    pub fn update_public_key(&mut self, public_key: G, weak_only: bool) {
        if weak_only || self.strong_key.is_some() {
            match self.weak_key {
                None => self.weak_key = Some(public_key),
                Some(current_weak_key) => {
                    self.weak_key = Some((current_weak_key + public_key).into_affine())
                }
            }
        } else {
            self.strong_key = Some(public_key)
        }
    }
}
