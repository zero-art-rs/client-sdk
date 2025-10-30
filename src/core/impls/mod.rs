use cortado::CortadoAffine;

pub mod concurrent;
pub mod sequential;

fn group_owner_leaf_public_key<A: ARTPublicView<CortadoAffine>>(art: &A) -> CortadoAffine {
    LeafIter::new(art.get_root())
        .next()
        .expect("ART can't be empty")
        .get_public_key()
}
