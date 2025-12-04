use ark_ec::AffineRepr;

use crate::trees::{asynchronous_ratchet_tree::AsynchronousRatchetTree, merge_tree::MergeTree};

struct ArtSystem<G: AffineRepr> {
    art: AsynchronousRatchetTree<G>,
    merge_tree: MergeTree<G>,
}
