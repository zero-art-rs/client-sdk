use std::mem;

use ark_ec::AffineRepr;
use serde::{Deserialize, Serialize};
use zrt_art::{art_node::LeafStatus, errors::ArtError, node_index::Direction};

use crate::trees::binary_tree::BinaryTree;

pub struct AsynchronousRatchetTree<G: AffineRepr>(BinaryTree<ArtNodeData<G>>);

impl<G: AffineRepr> AsynchronousRatchetTree<G> {}

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(bound = "")]
pub struct ArtNodeData<G: AffineRepr> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    public_key: G,
    role: ArtNodeRole,
}

#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
#[serde(bound = "")]
pub enum ArtNodeRole {
    Leaf { status: LeafStatus },
    Internal { weight: usize },
}

impl<G> ArtNodeData<G>
where
    G: AffineRepr,
{
    /// Creates a new ArtNode leaf with the given public key.
    pub fn new_leaf(public_key: G) -> Self {
        Self {
            public_key,
            role: ArtNodeRole::Leaf {
                status: LeafStatus::Active,
            },
        }
    }

    /// Creates a new ArtNode internal node with the given public key.
    pub fn new_internal_node(public_key: G, weight: usize) -> Self {
        Self {
            public_key,
            role: ArtNodeRole::Internal { weight },
        }
    }

    /// Returns the weight of the node.
    pub fn weight(&self) -> usize {
        match self.role {
            ArtNodeRole::Internal { weight, .. } => weight,
            ArtNodeRole::Leaf { status, .. } => match status {
                LeafStatus::Active => 1,
                _ => 0,
            },
        }
    }

    pub fn mut_weight(&mut self) -> Result<&mut usize, ArtError> {
        match &mut self.role {
            ArtNodeRole::Leaf { .. } => Err(ArtError::InternalNodeOnly),
            ArtNodeRole::Internal { weight, .. } => Ok(weight),
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn status(&self) -> Option<LeafStatus> {
        match self.role {
            ArtNodeRole::Leaf { status, .. } => Some(status),
            ArtNodeRole::Internal { .. } => None,
        }
    }

    /// If the node is leaf, return its status, else None
    pub fn set_status(&mut self, new_status: LeafStatus) -> Result<(), ArtError> {
        match &mut self.role {
            ArtNodeRole::Leaf { status, .. } => *status = new_status,
            ArtNodeRole::Internal { .. } => return Err(ArtError::LeafOnly),
        }

        Ok(())
    }

    // Returns a copy of its public key
    pub fn public_key(&self) -> G {
        self.public_key
    }

    /// Move current node down to left child, and append other node to the right. The current node
    /// becomes internal.
    pub fn extend(&mut self, other: Self) {
        let new_weight = self.weight() + other.weight();

        let mut tmp = Self::default();
        mem::swap(self, &mut tmp);

        let mut new_self = Self::Internal {
            public_key: self.public_key(),
            l: Box::new(tmp),
            r: Box::new(other),
            weight: new_weight,
        };

        mem::swap(&mut new_self, self);
    }

    /// If exists, return a reference on the leaf with the provided `public_key`. Else return `ArtError`.
    pub(crate) fn leaf_with(&self, public_key: G) -> Result<&Self, ArtError> {
        for (node, _) in NodeIterWithPath::new(self) {
            if node.is_leaf() && node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// If exists, return a mutable reference on the node with the provided `public_key`. Else return `ArtError`.
    pub(crate) fn node_with(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self) {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Searches for a leaf with the provided `public_key`. If there is no such leaf, return `ArtError`.
    pub fn path_to_leaf_with(&self, public_key: G) -> Result<Vec<Direction>, ArtError> {
        for (node, path) in NodeIterWithPath::new(self) {
            if node.is_leaf() && node.public_key().eq(&public_key) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Increment or decrement weight by 1. Return error for leaf node.
    pub(crate) fn update_weight(&mut self, increment: bool) -> Result<(), ArtError> {
        match self {
            ArtNode::Leaf { .. } => return Err(ArtError::InternalNodeOnly),
            ArtNode::Internal { weight, .. } => match increment {
                true => *weight += 1,
                false => *weight -= 1,
            },
        }

        Ok(())
    }

    pub(crate) fn preview_public_key(&self, merge_data: &PublicMergeData<G>) -> G {
        let mut resulting_public_key = self.public_key();

        if let Some(strong_key) = merge_data.strong_key() {
            resulting_public_key = strong_key;
        }

        if let Some(weak_key) = merge_data.weak_key() {
            resulting_public_key = resulting_public_key.add(&weak_key).into_affine();
        }

        resulting_public_key
    }

    pub(crate) fn commit(
        &mut self,
        merge_data: Option<&PublicMergeData<G>>,
    ) -> Result<G, ArtError> {
        if let Some(merge_data) = merge_data {
            *self.mut_public_key() = self.preview_public_key(merge_data);

            if let Some(status) = merge_data.status() {
                self.set_status(status)?;
            }

            if let Ok(weight) = self.mut_weight() {
                match merge_data.weight_change.cmp(&0) {
                    Ordering::Less => *weight -= merge_data.weight_change.abs() as usize,
                    Ordering::Equal => {}
                    Ordering::Greater => *weight += merge_data.weight_change as usize,
                }
            }
        };

        Ok(self.public_key())
    }
}
