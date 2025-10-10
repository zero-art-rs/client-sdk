use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use sha3::Digest;
use uuid::Uuid;

use crate::{models::frame, proof_system::get_proof_system, types::StageKey, utils::encrypt};

use super::*;

#[derive(Debug, Default)]
struct Nonce(u64);

impl Nonce {
    fn new(value: u64) -> Self {
        Self(value)
    }

    fn next(&mut self) -> Vec<u8> {
        let nonce = self.0.to_le_bytes().to_vec();
        self.0 += 1;
        nonce
    }
}

#[test]
fn test_create_validator() {
    let mut rng = StdRng::seed_from_u64(0);
    let mut nonce = Nonce::new(0);
    let group_id = Uuid::new_v4();

    let leaf_secret_0_0 = ScalarField::rand(&mut rng);

    let (base_art, tree_key) =
        PrivateART::new_art_from_secrets(&vec![leaf_secret_0_0], &CortadoAffine::generator())
            .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), tree_key.key)
        .expect("Failed to derive base stage key");

    let mut keyed_validator_0 = LinearKeyedValidator::new(base_art, base_stk, 0);

    // Member 1
    let leaf_secret_1_0 = ScalarField::rand(&mut rng);

    let proposal = keyed_validator_0
        .propose_add_member(leaf_secret_1_0)
        .expect("Failed to predict add member");

    // Frame construction
    let frame_0_tbs = frame::FrameTbs::new(
        group_id,
        1,
        nonce.next(),
        Some(frame::GroupOperation::AddMember(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_0_aad = Sha3_256::digest(
        frame_0_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_0 = frame::Frame::new(
        frame_0_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_0_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    // Frame validation
    let _ = keyed_validator_0
        .validate(&frame_0)
        .expect("Failed to validate frame 0");

    let upstream_art: PrivateART<CortadoAffine> =
        PrivateART::from_public_art_and_secret(keyed_validator_0.tree().clone(), leaf_secret_1_0)
            .expect("Failed to create base/upstream art for another member");
    let mut keyed_validator_1 = LinearKeyedValidator::new(
        upstream_art,
        keyed_validator_0.stage_key(),
        keyed_validator_0.epoch(),
    );

    // Member 2
    let leaf_secret_2_0 = ScalarField::rand(&mut rng);

    let proposal = keyed_validator_0
        .propose_add_member(leaf_secret_2_0)
        .expect("Failed to predict add member");

    // Frame construction
    let frame_1_tbs = frame::FrameTbs::new(
        group_id,
        2,
        nonce.next(),
        Some(frame::GroupOperation::AddMember(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_1_aad = Sha3_256::digest(
        frame_1_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_1 = frame::Frame::new(
        frame_1_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_1_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    // Frame validation
    let _ = keyed_validator_0
        .validate(&frame_1)
        .expect("Failed to validate frame 1 for validator 0");
    let _ = keyed_validator_1
        .validate(&frame_1)
        .expect("Failed to validate frame 1 for validator 1");

    assert_eq!(
        keyed_validator_0.epoch(),
        keyed_validator_1.epoch(),
        "Validator epoch mismatch"
    );
    assert_eq!(
        keyed_validator_0.stage_key(),
        keyed_validator_1.stage_key(),
        "Validator upstream stk mismatch"
    );

    let proposal = keyed_validator_0
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_2_tbs = frame::FrameTbs::new(
        group_id,
        3,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_2_aad = Sha3_256::digest(
        frame_2_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_2 = frame::Frame::new(
        frame_2_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_2_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    let _ = keyed_validator_0
        .validate(&frame_2)
        .expect("Failed to validate frame 1 for validator 0");
    let _ = keyed_validator_1
        .validate(&frame_2)
        .expect("Failed to validate frame 1 for validator 1");

    assert_eq!(
        keyed_validator_0.epoch(),
        keyed_validator_1.epoch(),
        "Validator epoch mismatch"
    );
    assert_eq!(
        keyed_validator_0.stage_key(),
        keyed_validator_1.stage_key(),
        "Validator upstream stk mismatch"
    );
    assert!(
        keyed_validator_0.is_participant(),
        "Validator 0 should participate in epoch"
    );
    assert!(
        !keyed_validator_1.is_participant(),
        "Validator 1 should not participate in epoch"
    );

    let proposal = keyed_validator_0
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_3_tbs = frame::FrameTbs::new(
        group_id,
        4,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_3_aad = Sha3_256::digest(
        frame_3_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_3 = frame::Frame::new(
        frame_3_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_3_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    let proposal = keyed_validator_1
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_4_tbs = frame::FrameTbs::new(
        group_id,
        4,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_4_aad = Sha3_256::digest(
        frame_4_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_4 = frame::Frame::new(
        frame_4_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_4_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    let _ = keyed_validator_0
        .validate(&frame_3)
        .expect("Failed to validate frame 3 for validator 0");
    let _ = keyed_validator_1
        .validate(&frame_3)
        .expect("Failed to validate frame 3 for validator 1");

    let _ = keyed_validator_0
        .validate(&frame_4)
        .expect("Failed to validate frame 4 for validator 0");
    let _ = keyed_validator_1
        .validate(&frame_4)
        .expect("Failed to validate frame 4 for validator 1");

    assert_eq!(
        keyed_validator_0.epoch(),
        keyed_validator_1.epoch(),
        "Validator epoch mismatch"
    );
    assert_eq!(
        keyed_validator_0.stage_key(),
        keyed_validator_1.stage_key(),
        "Validator upstream stk mismatch"
    );
    assert!(
        keyed_validator_0.is_participant(),
        "Validator 0 should participate in epoch"
    );
    assert!(
        keyed_validator_1.is_participant(),
        "Validator 1 should participate in epoch"
    );

    let proposal = keyed_validator_1
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_5_tbs = frame::FrameTbs::new(
        group_id,
        5,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(proposal.changes)),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_5_aad = Sha3_256::digest(
        frame_5_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let frame_5 = frame::Frame::new(
        frame_5_tbs,
        frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_5_aad,
                )
                .expect("Failed to prove frame 0"),
        ),
    );

    let _ = keyed_validator_0
        .validate(&frame_5)
        .expect("Failed to validate frame 5 for validator 0");
    let _ = keyed_validator_1
        .validate(&frame_5)
        .expect("Failed to validate frame 5 for validator 1");

    assert_eq!(keyed_validator_0.epoch(), 5);
    assert_eq!(
        keyed_validator_0.epoch(),
        keyed_validator_1.epoch(),
        "Validator epoch mismatch"
    );
    assert_eq!(
        keyed_validator_0.stage_key(),
        keyed_validator_1.stage_key(),
        "Validator upstream stk mismatch"
    );
    assert!(
        !keyed_validator_0.is_participant(),
        "Validator 0 should not participate in epoch"
    );
    assert!(
        keyed_validator_1.is_participant(),
        "Validator 1 should participate in epoch"
    );
}
