use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use sha3::Digest;
use uuid::Uuid;
use zrt_art::changes::ProvableChange;

use crate::{
    models::frame::{self, Proof},
    types::{Proposal, StageKey},
    utils::{derive_stage_key, encrypt},
};

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

fn frame_from_proposal(
    proposal: Proposal<CortadoAffine>,
    epoch: u64,
    payload: &[u8],
) -> frame::Frame {
    let frame_tbs = frame::FrameTbs::new(
        Uuid::new_v4(),
        epoch,
        vec![],
        Some(proposal.change.get_branch_change().clone().into()),
        encrypt(&proposal.stage_key, payload, b"").expect("Failed to encrypt payload"),
    );
    let frame_aad = Sha3_256::digest(
        frame_tbs
            .encode_to_vec()
            .expect("Failed to encode frame tbs"),
    );

    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_aad, None)
            .expect("Failed to prove"),
    );
    frame::Frame::new(frame_tbs, proof)
}

#[test]
fn test_sequential_invite_members() {
    // let _ = tracing_subscriber::fmt()
    //     .with_max_level(tracing::Level::TRACE) // щоб бачили trace/debug/info
    //     .with_test_writer() // щоб писало в буфер тестів
    //     .try_init();

    let mut rng = StdRng::seed_from_u64(0);

    // Create Private ART
    let leaf_secret = ScalarField::rand(&mut rng);
    let base_art = PrivateZeroArt::setup(&vec![leaf_secret], Box::new(StdRng::seed_from_u64(1)))
        .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), base_art.get_root_secret_key())
        .expect("Failed to derive base stage key");

    // Create KeyedValidator
    let mut keyed_validator = KeyedValidator::new(base_art, base_stk, 0);

    // Generate members leaf keys
    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();

    for member_secret in members_secrets.iter() {
        let proposal = keyed_validator
            .propose_add_member(*member_secret)
            .expect("Failed to propose add member");

        let frame = frame_from_proposal(proposal, keyed_validator.epoch() + 1, b"Hello world!");

        keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame");
    }

    assert_eq!(
        keyed_validator.epoch, 3,
        "After adding 3 member epoch should be 3"
    );
    assert_eq!(
        LeafIter::new(keyed_validator.art.get_upstream_art().get_root()).count(),
        4,
        "In group should be 4 members"
    );
}

#[test]
fn test_sequential_invite_members_with_observer() {
    let mut rng = StdRng::seed_from_u64(0);

    let owner_leaf_secret = ScalarField::rand(&mut rng);
    let base_art =
        PrivateZeroArt::setup(&vec![owner_leaf_secret], Box::new(StdRng::seed_from_u64(1)))
            .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), base_art.get_root_secret_key())
        .expect("Failed to derive base stage key");

    let mut owner_keyed_validator = KeyedValidator::new(base_art, base_stk, 0);

    let observer_leaf_secret = ScalarField::rand(&mut rng);

    let proposal = owner_keyed_validator
        .propose_add_member(observer_leaf_secret)
        .expect("Failed to propose to add observer");
    let frame = frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");
    let (_, stage_key) = owner_keyed_validator
        .validate_and_derive_key(&frame)
        .expect("Failed to validate add observer frame");

    //
    let observer_art = PrivateZeroArt::new(
        PrivateArt::new(
            owner_keyed_validator
                .art
                .get_upstream_art()
                .get_public_art()
                .clone(),
            observer_leaf_secret,
        )
        .expect("Failed to create private art"),
        Box::new(StdRng::seed_from_u64(2)),
    )
    .expect("Failed to create observer art");
    let mut observer_keyed_validator =
        KeyedValidator::new(observer_art, stage_key, owner_keyed_validator.epoch);

    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();

    for member_secret in members_secrets.iter() {
        let proposal = owner_keyed_validator
            .propose_add_member(*member_secret)
            .expect("Failed to propose add member");

        let frame =
            frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");

        owner_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (owner)");
        observer_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (observer)");
    }

    assert_eq!(
        owner_keyed_validator.epoch, 4,
        "Group should have epoch 4 after adding 4 members"
    );
    assert_eq!(
        LeafIter::new(owner_keyed_validator.art.get_upstream_art().get_root()).count(),
        5,
        "In group should be 5 members (owner + observer + 3 members)"
    );

    assert_eq!(owner_keyed_validator.epoch, observer_keyed_validator.epoch);
    assert_eq!(owner_keyed_validator.art, observer_keyed_validator.art);
    assert_eq!(
        owner_keyed_validator.upstream_stk,
        observer_keyed_validator.upstream_stk
    );
    // assert_eq!(
    //     owner_keyed_validator.base_art,
    //     observer_keyed_validator.base_art
    // );
    assert_eq!(
        owner_keyed_validator.base_stk,
        observer_keyed_validator.base_stk
    );
}

#[test]
fn test_sequential_cross_key_updates() {
    let mut rng = StdRng::seed_from_u64(0);

    let owner_leaf_secret = ScalarField::rand(&mut rng);
    let base_art =
        PrivateZeroArt::setup(&vec![owner_leaf_secret], Box::new(StdRng::seed_from_u64(1)))
            .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), base_art.get_root_secret_key())
        .expect("Failed to derive base stage key");

    let mut owner_keyed_validator = KeyedValidator::new(base_art, base_stk, 0);

    let observer_leaf_secret = ScalarField::rand(&mut rng);

    let proposal = owner_keyed_validator
        .propose_add_member(observer_leaf_secret)
        .expect("Failed to propose to add observer");
    let frame = frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");
    let (_, stage_key) = owner_keyed_validator
        .validate_and_derive_key(&frame)
        .expect("Failed to validate add observer frame");

    let observer_art = PrivateArt::new(
        owner_keyed_validator
            .art
            .get_upstream_art()
            .get_public_art()
            .clone(),
        observer_leaf_secret,
    )
    .expect("Failed to create observer art");
    let mut observer_keyed_validator = KeyedValidator::new(
        PrivateZeroArt::new(observer_art, Box::new(StdRng::seed_from_u64(2)))
            .expect("Failed to create private zero art"),
        stage_key,
        owner_keyed_validator.epoch,
    );

    for _ in 0..10 {
        let proposal = owner_keyed_validator
            .propose_update_key()
            .expect("Failed propose to key update for owner");
        let frame =
            frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");

        owner_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (owner)");
        observer_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (observer)");

        let proposal = observer_keyed_validator
            .propose_update_key()
            .expect("Failed propose to key update for owner");
        let frame = frame_from_proposal(
            proposal,
            observer_keyed_validator.epoch() + 1,
            b"Hello world!",
        );

        owner_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (owner)");
        observer_keyed_validator
            .validate_and_derive_key(&frame)
            .expect("Failed to validate frame (observer)");
    }

    assert_eq!(
        owner_keyed_validator.epoch, 21,
        "Group should have epoch 21 after adding member and 20 key updates "
    );
    assert_eq!(
        LeafIter::new(owner_keyed_validator.art.get_root()).count(),
        2,
        "In group should be 2 members (owner + observer)"
    );

    assert_eq!(owner_keyed_validator.epoch, observer_keyed_validator.epoch);
    assert_eq!(owner_keyed_validator.art, observer_keyed_validator.art);
    assert_eq!(
        owner_keyed_validator.upstream_stk,
        observer_keyed_validator.upstream_stk
    );
    // assert_eq!(
    //     owner_keyed_validator.base_art,
    //     observer_keyed_validator.base_art
    // );
    assert_eq!(
        owner_keyed_validator.base_stk,
        observer_keyed_validator.base_stk
    );
}

#[test]
fn test_concurrent_key_updates() {
    let mut rng = StdRng::seed_from_u64(0);

    let owner_leaf_secret = ScalarField::rand(&mut rng);

    let base_art =
        PrivateZeroArt::setup(&vec![owner_leaf_secret], Box::new(StdRng::seed_from_u64(1)))
            .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), base_art.get_root_secret_key())
        .expect("Failed to derive base stage key");

    let mut owner_keyed_validator = KeyedValidator::new(base_art, base_stk, 0);

    let participant_leaf_secret = ScalarField::rand(&mut rng);

    let proposal = owner_keyed_validator
        .propose_add_member(participant_leaf_secret)
        .expect("Failed to propose to add observer");
    let frame = frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");
    let (_, stage_key) = owner_keyed_validator
        .validate_and_derive_key(&frame)
        .expect("Failed to validate add observer frame");

    let participant_art = PrivateArt::new(
        owner_keyed_validator
            .art
            .get_upstream_art()
            .get_public_art()
            .clone(),
        participant_leaf_secret,
    )
    .expect("Failed to create participant art");
    let mut participant_keyed_validator = KeyedValidator::new(
        PrivateZeroArt::new(participant_art, Box::new(StdRng::seed_from_u64(2)))
            .expect("Failed to create private zero art"),
        stage_key,
        owner_keyed_validator.epoch(),
    );

    let observer_leaf_secret = ScalarField::rand(&mut rng);

    let proposal = owner_keyed_validator
        .propose_add_member(observer_leaf_secret)
        .expect("Failed to propose to add observer");
    let frame = frame_from_proposal(proposal, owner_keyed_validator.epoch() + 1, b"Hello world!");
    let (_, stage_key) = owner_keyed_validator
        .validate_and_derive_key(&frame)
        .expect("Failed to validate add observer frame");
    let _ = participant_keyed_validator
        .validate_and_derive_key(&frame)
        .expect("Failed to validate particiapnt");

    let observer_art = PrivateArt::new(
        owner_keyed_validator
            .art
            .get_upstream_art()
            .get_public_art()
            .clone(),
        observer_leaf_secret,
    )
    .expect("Failed to create observer art");
    let observer_keyed_validator = KeyedValidator::new(
        PrivateZeroArt::new(observer_art, Box::new(StdRng::seed_from_u64(3)))
            .expect("Failed to create private zero art"),
        stage_key,
        owner_keyed_validator.epoch(),
    );

    assert_eq!(
        owner_keyed_validator.epoch(),
        participant_keyed_validator.epoch()
    );
    assert_eq!(
        observer_keyed_validator.epoch(),
        participant_keyed_validator.epoch()
    );

    let mut validators = vec![
        owner_keyed_validator,
        participant_keyed_validator,
        observer_keyed_validator,
    ];

    for i in 3..7 {
        let mut frames: Vec<frame::Frame> = Vec::with_capacity(3);

        if i >> 2 & 1 == 1 {
            trace!("Validator 0 proposal");
            let proposal = validators[0]
                .propose_update_key()
                .expect("Failed to propose update key for validator 0");
            frames.push(frame_from_proposal(
                proposal,
                validators[0].epoch() + 1,
                b"Hello World",
            ));
        }

        if i >> 1 & 1 == 1 {
            trace!("Validator 1 proposal");
            let proposal = validators[1]
                .propose_update_key()
                .expect("Failed to propose update key for validator 1");
            frames.push(frame_from_proposal(
                proposal,
                validators[1].epoch() + 1,
                b"Hello World",
            ));
        }

        if i >> 0 & 1 == 1 {
            trace!("Validator 2 proposal");
            let proposal = validators[2]
                .propose_update_key()
                .expect("Failed to propose update key for validator 2");
            frames.push(frame_from_proposal(
                proposal,
                validators[2].epoch() + 1,
                b"Hello World",
            ));
        }

        for (_, validator) in validators.iter_mut().enumerate() {
            for (_, frame) in frames.iter().enumerate() {
                let _ = validator
                    .validate_and_derive_key(frame)
                    .expect("Failed to validate frame");
            }
        }
    }

    assert_eq!(validators[0].art, validators[1].art);
    assert_eq!(validators[2].art, validators[1].art);

    assert_eq!(validators[0].upstream_stk, validators[1].upstream_stk);
    assert_eq!(validators[2].upstream_stk, validators[1].upstream_stk);
}

#[test]
fn test_create_validator2() {
    let mut rng = StdRng::seed_from_u64(0);
    let mut nonce = Nonce::new(0);
    let group_id = Uuid::new_v4();

    let leaf_secret_0_0 = ScalarField::rand(&mut rng);

    let base_art =
        PrivateZeroArt::setup(&vec![leaf_secret_0_0], Box::new(StdRng::seed_from_u64(1)))
            .expect("Failed to create art from secret");
    let base_stk = derive_stage_key(&StageKey::default(), base_art.get_root_secret_key())
        .expect("Failed to derive base stage key");

    let mut keyed_validator_0 = KeyedValidator::new(base_art, base_stk, 0);

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
        Some(frame::GroupOperation::AddMember(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_0_aad = Sha3_256::digest(
        frame_0_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );

    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_0_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_0 = frame::Frame::new(frame_0_tbs, proof);

    // Frame validation
    let _ = keyed_validator_0
        .validate(&frame_0)
        .expect("Failed to validate frame 0");

    let upstream_art: PrivateArt<CortadoAffine> =
        PrivateArt::new(keyed_validator_0.tree().clone(), leaf_secret_1_0)
            .expect("Failed to create base/upstream art for another member");
    let mut keyed_validator_1 = KeyedValidator::new(
        PrivateZeroArt::new(upstream_art, Box::new(StdRng::seed_from_u64(2)))
            .expect("Faile to create private zero art"),
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
        Some(frame::GroupOperation::AddMember(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_1_aad = Sha3_256::digest(
        frame_1_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_1_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_1 = frame::Frame::new(frame_1_tbs, proof);

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
        Some(frame::GroupOperation::KeyUpdate(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_2_aad = Sha3_256::digest(
        frame_2_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );

    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_2_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_2 = frame::Frame::new(frame_2_tbs, proof);

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
    // assert!(
    //     keyed_validator_0.is_participant(),
    //     "Validator 0 should participate in epoch"
    // );
    // assert!(
    //     !keyed_validator_1.is_participant(),
    //     "Validator 1 should not participate in epoch"
    // );

    let proposal = keyed_validator_0
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_3_tbs = frame::FrameTbs::new(
        group_id,
        4,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_3_aad = Sha3_256::digest(
        frame_3_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_3_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_3 = frame::Frame::new(frame_3_tbs, proof);

    let proposal = keyed_validator_1
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_4_tbs = frame::FrameTbs::new(
        group_id,
        4,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_4_aad = Sha3_256::digest(
        frame_4_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_4_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_4 = frame::Frame::new(frame_4_tbs, proof);

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
    // assert!(
    //     keyed_validator_0.is_participant(),
    //     "Validator 0 should participate in epoch"
    // );
    // assert!(
    //     keyed_validator_1.is_participant(),
    //     "Validator 1 should participate in epoch"
    // );

    let proposal = keyed_validator_1
        .propose_update_key()
        .expect("Failed to predict update key");

    // Frame construction
    let frame_5_tbs = frame::FrameTbs::new(
        group_id,
        5,
        nonce.next(),
        Some(frame::GroupOperation::KeyUpdate(
            proposal.change.get_branch_change().clone().into(),
        )),
        encrypt(&proposal.stage_key, b"Hello world!", b"").expect("Failed to encrypt payload"),
    );
    let frame_5_aad = Sha3_256::digest(
        frame_5_tbs
            .encode_to_vec()
            .expect("Failed to encode frame 0 tbs"),
    );
    let proof = Proof::ArtProof(
        proposal
            .change
            .prove(&frame_5_aad, None)
            .expect("Failed to prove frame"),
    );

    let frame_5 = frame::Frame::new(frame_5_tbs, proof);

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
    // assert!(
    //     !keyed_validator_0.is_participant(),
    //     "Validator 0 should not participate in epoch"
    // );
    // assert!(
    //     keyed_validator_1.is_participant(),
    //     "Validator 1 should participate in epoch"
    // );
}
