use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use chrono::Utc;
use sha3::Digest;
use uuid::Uuid;
use zrt_art::types::LeafIter;
use std::collections::HashMap;

use ark_ec::{AffineRepr, CurveGroup};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use tracing::{debug, instrument, span, trace, Level};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafStatus, PrivateART, PublicART},
};
use zrt_crypto::schnorr;

use crate::{
    bounded_map::BoundedMap, contexts::{group::GroupContext, invite::InviteContext}, core::{
        impls::concurrent::linear_keyed_validator::LinearKeyedValidator, traits::{KeyedValidator, Validator}
    }, errors::{Error, Result}, models, types::{
        AddMemberProposal, ChangesID, GroupOperation, RemoveMemberProposal, StageKey,
        UpdateKeyProposal, ValidationResult, ValidationWithKeyResult,
    }, utils::{self, compute_changes_id, derive_leaf_key, derive_stage_key, deserialize}
};
use cortado::{self, CortadoAffine, Fr as ScalarField};

use crate::{
    proof_system::get_proof_system,
    types::{Proposal},
    utils::encrypt,
};

use super::*;

fn frame_from_proposal(
    proposal: Proposal<CortadoAffine>,
    epoch: u64,
    payload: &[u8],
) -> models::frame::Frame {
    let frame_tbs = models::frame::FrameTbs::new(
        Uuid::new_v4(),
        epoch,
        vec![],
        Some(proposal.changes.into()),
        encrypt(&proposal.stage_key, payload, b"").expect("Failed to encrypt payload"),
    );
    let frame_aad = Sha3_256::digest(
        frame_tbs
            .encode_to_vec()
            .expect("Failed to encode frame tbs"),
    );
    models::frame::Frame::new(
        frame_tbs,
        models::frame::Proof::ArtProof(
            get_proof_system()
                .prove(
                    proposal.prover_artefacts,
                    &[proposal.aux_secret_key],
                    &frame_aad,
                )
                .expect("Failed to prove frame"),
        ),
    )
}

#[test]
fn test_create_group() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();
    
    let group_info = models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();
    let identity_public_key_bytes = utils::serialize(identity_public_key).expect("Failed to serialize identity public key");

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info).expect("Failed to create group context");

    // Validate initial frame
    assert!(matches!(frame.frame_tbs().group_operation(), Some(models::frame::GroupOperation::Init(_))), "Initial frame should containt Init group operation");
    assert_eq!(frame.frame_tbs().epoch(), 0, "Initial frame epoch should be 0");
    assert_eq!(frame.frame_tbs().group_id(), group_id, "Group id invalid");
    assert_eq!(frame.frame_tbs().nonce(), identity_public_key_bytes, "Initial frame nonce should contain serialize identity public key");
    frame.verify_schnorr::<Sha3_256>(identity_public_key).expect("Frame should be signed by identity secret key");

    // Validate group context
    assert_eq!(group_context.epoch(), 0, "Group context starts from epoch 0");
    assert_eq!(group_context.group_info().members().len(), 1, "Group members contain owner");

    group_context.process_frame(frame).expect("Process initial frame");
}

#[test]
fn test_add_member() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();
    
    let group_info = models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info).expect("Failed to create group context");

    group_context.process_frame(frame).expect("Process initial frame");


    let member_identity_secret_key = ScalarField::rand(&mut rng);
    let member_identity_public_key = (CortadoAffine::generator() * member_identity_secret_key).into_affine();

    let invitee = models::invite::Invitee::Identified { identity_public_key: member_identity_public_key, spk_public_key: None };
    let (frame, _) = group_context.add_member(invitee, vec![]).expect("Failed to propose add member");

    assert_eq!(group_context.group_info().members().len(), 1, "Add member is just proposal, so in group should be only owner");

    group_context.process_frame(frame).expect("Failed to process add member proposal");

    assert_eq!(group_context.group_info().members().len(), 2, "After proposal processing group should have 2 members");
}

#[test]
fn test_join_group() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();
    
    let group_info = models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info).expect("Failed to create group context");

    group_context.process_frame(frame).expect("Process initial frame");


    let member_identity_secret_key = ScalarField::rand(&mut rng);
    let member_identity_public_key = (CortadoAffine::generator() * member_identity_secret_key).into_affine();

    let invitee = models::invite::Invitee::Identified { identity_public_key: member_identity_public_key, spk_public_key: None };
    let (frame, invite) = group_context.add_member(invitee, vec![]).expect("Failed to propose add member");

    group_context.process_frame(frame.clone()).expect("Failed to process add member proposal");


    let invite_context = InviteContext::new(member_identity_secret_key, None, invite).expect("Failed to create invite context");

    let mut member_group_context = invite_context.upgrade(group_context.tree()).expect("Failed to upgrade group context");

    assert_eq!(member_group_context.group_info().members().len(), 0, "If invite context was upgraded to group context, members should be empty");
    member_group_context.process_frame(frame).expect("Failed to process add member frame for member");
    assert_eq!(member_group_context.epoch(), group_context.epoch(), "Epoch of all members should be equal");
    assert_eq!(member_group_context.group_info().members().len(), 2, "Group info should contain owner and invited member");

    let member = models::group_info::User::new(String::from("Member"), member_identity_public_key, vec![]);
    let frame = member_group_context.join_group_as(member).expect("Failed to propose to join group");

    group_context.process_frame(frame.clone()).expect("Failed to process join group frame for owner");
    member_group_context.process_frame(frame).expect("Failed to process join group frame for member");


    assert_eq!(member_group_context.epoch(), group_context.epoch(), "Epoch of all members should be equal");
    assert_eq!(member_group_context.group_info().members().len(), 2, "Group info should contain owner and invited member");
}

#[test]
fn test_invite_many_members_and_sync() {

        let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE) // щоб бачили trace/debug/info
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();
    
    let group_info = models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    // Create group
    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);
    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info).expect("Failed to create group context");
    group_context.process_frame(frame).expect("Process initial frame");

    trace!("Members: {:?}", group_context.group_info().members());
    trace!("Identity public key: {:?}", identity_public_key);

    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();
    let member_public_keys = members_secrets.iter().map(|s| (CortadoAffine::generator() * s).into_affine()).collect::<Vec<CortadoAffine>>();

    let mut frames: Vec<models::frame::Frame> = Vec::with_capacity(members_secrets.len());
    let mut trees: Vec<PublicART<CortadoAffine>> = Vec::with_capacity(members_secrets.len());
    let mut invites: Vec<models::invite::Invite> = Vec::with_capacity(members_secrets.len());

    for public_key in member_public_keys.iter() {
        let invitee = models::invite::Invitee::Identified { identity_public_key: *public_key, spk_public_key: None };
        let (frame, invite) = group_context.add_member(invitee, vec![]).expect("Failed to propose add member");
        group_context.process_frame(frame.clone()).expect("Failed to process add member proposal");

        frames.push(frame);
        trees.push(group_context.tree());
        invites.push(invite);
    }

    let mut contexts: Vec<GroupContext> = Vec::with_capacity(members_secrets.len());

    for (i, secret_key) in members_secrets.iter().enumerate() {
        println!("{}", i);
        let invite_context = InviteContext::new(*secret_key, None, invites[i].clone()).expect("Failed to create invite context");
        let mut member_group_context = invite_context.upgrade(trees[i].clone()).expect("Failed to upgrade group context");

        for frame in frames.iter().skip(i) {
            member_group_context.process_frame(frame.clone()).expect("Failed to process frame");
        }

        let user = models::group_info::User::new(format!("Member {}", i), member_public_keys[i], vec![]);
        let frame = member_group_context.join_group_as(user).expect("Failed to join group");
        
        member_group_context.process_frame(frame.clone()).expect("Failed to process own join group frame");
        group_context.process_frame(frame.clone()).expect("Failed to process join group context for owner");

        frames.push(frame);
        contexts.push(member_group_context);
    }



}
