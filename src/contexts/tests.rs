use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use chrono::Utc;
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use ark_ec::{AffineRepr, CurveGroup};
use sha3::Sha3_256;
use zrt_art::art::PublicArt;

use crate::{
    contexts::{group::GroupContext, invite::InviteContext},
    errors::Error,
    models::{self, group_info::public_key_to_id},
    utils,
};
use cortado::{self, CortadoAffine, Fr as ScalarField};

#[test]
fn test_create_group() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();
    let identity_public_key_bytes =
        utils::serialize(identity_public_key).expect("Failed to serialize identity public key");

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");

    // Validate initial frame
    assert!(
        matches!(
            frame.frame_tbs().group_operation(),
            Some(models::frame::GroupOperation::Init(_))
        ),
        "Initial frame should containt Init group operation"
    );
    assert_eq!(
        frame.frame_tbs().epoch(),
        0,
        "Initial frame epoch should be 0"
    );
    assert_eq!(frame.frame_tbs().group_id(), group_id, "Group id invalid");
    assert_eq!(
        frame.frame_tbs().nonce(),
        identity_public_key_bytes,
        "Initial frame nonce should contain serialize identity public key"
    );
    frame
        .verify_schnorr::<Sha3_256>(identity_public_key)
        .expect("Frame should be signed by identity secret key");

    // Validate group context
    assert_eq!(
        group_context.epoch(),
        0,
        "Group context starts from epoch 0"
    );
    assert_eq!(
        group_context.group_info().members().len(),
        1,
        "Group members contain owner"
    );

    group_context
        .process_frame(frame)
        .expect("Process initial frame");
}

#[test]
fn test_add_member() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");

    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let member_identity_secret_key = ScalarField::rand(&mut rng);
    let member_identity_public_key =
        (CortadoAffine::generator() * member_identity_secret_key).into_affine();

    let invitee = models::invite::Invitee::Identified {
        identity_public_key: member_identity_public_key,
        spk_public_key: None,
    };
    let (frame, _) = group_context
        .add_member(invitee, vec![])
        .expect("Failed to propose add member");

    assert_eq!(
        group_context.group_info().members().len(),
        1,
        "Add member is just proposal, so in group should be only owner"
    );

    group_context
        .process_frame(frame)
        .expect("Failed to process add member proposal");

    assert_eq!(
        group_context.group_info().members().len(),
        2,
        "After proposal processing group should have 2 members"
    );
}

#[test]
fn test_join_group() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");

    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let member_identity_secret_key = ScalarField::rand(&mut rng);
    let member_identity_public_key =
        (CortadoAffine::generator() * member_identity_secret_key).into_affine();

    let invitee = models::invite::Invitee::Identified {
        identity_public_key: member_identity_public_key,
        spk_public_key: None,
    };
    let (frame, invite) = group_context
        .add_member(invitee, vec![])
        .expect("Failed to propose add member");

    group_context
        .process_frame(frame.clone())
        .expect("Failed to process add member proposal");

    let invite_context = InviteContext::new(member_identity_secret_key, None, invite)
        .expect("Failed to create invite context");

    let mut member_group_context = invite_context
        // .upgrade(group_context.tree())
        .upgrade(group_context.commited_tree().expect("Public tree must be commitable"))
        .expect("Failed to upgrade group context");

    assert_eq!(
        member_group_context.group_info().members().len(),
        0,
        "If invite context was upgraded to group context, members should be empty"
    );
    // TODO: can't validate frame, which is already applied.
    // member_group_context.update();

    member_group_context
        .process_frame(frame)
        .expect("Failed to process add member frame for member");
    assert_eq!(
        member_group_context.epoch(),
        group_context.epoch(),
        "Epoch of all members should be equal"
    );
    assert_eq!(
        member_group_context.group_info().members().len(),
        2,
        "Group info should contain owner and invited member"
    );

    let member =
        models::group_info::User::new(String::from("Member"), member_identity_public_key, vec![]);
    let frame = member_group_context
        .join_group_as(member)
        .expect("Failed to propose to join group");

    group_context
        .process_frame(frame.clone())
        .expect("Failed to process join group frame for owner");
    member_group_context
        .process_frame(frame)
        .expect("Failed to process join group frame for member");

    assert_eq!(
        member_group_context.epoch(),
        group_context.epoch(),
        "Epoch of all members should be equal"
    );
    assert_eq!(
        member_group_context.group_info().members().len(),
        2,
        "Group info should contain owner and invited member"
    );
}

#[test]
fn test_invite_many_members_and_sync() {
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    // Create group
    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);
    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");
    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();
    let member_public_keys = members_secrets
        .iter()
        .map(|s| (CortadoAffine::generator() * s).into_affine())
        .collect::<Vec<CortadoAffine>>();

    let mut frames: Vec<models::frame::Frame> = Vec::with_capacity(members_secrets.len());
    let mut trees: Vec<PublicArt<CortadoAffine>> = Vec::with_capacity(members_secrets.len());
    let mut invites: Vec<models::invite::Invite> = Vec::with_capacity(members_secrets.len());

    for public_key in member_public_keys.iter() {
        let invitee = models::invite::Invitee::Identified {
            identity_public_key: *public_key,
            spk_public_key: None,
        };
        let (frame, invite) = group_context
            .add_member(invitee, vec![])
            .expect("Failed to propose add member");
        group_context
            .process_frame(frame.clone())
            .expect("Failed to process add member proposal");

        frames.push(frame);
        trees.push(group_context.commited_tree().expect("Public tree must be commitable"));
        invites.push(invite);
    }

    let mut contexts: Vec<GroupContext<StdRng>> = Vec::with_capacity(members_secrets.len());

    for (i, secret_key) in members_secrets.iter().enumerate() {
        let invite_context = InviteContext::new(*secret_key, None, invites[i].clone())
            .expect("Failed to create invite context");
        let mut member_group_context = invite_context
            .upgrade(trees[i].clone())
            .expect("Failed to upgrade group context");

        for frame in frames.iter().skip(i) {
            member_group_context
                .process_frame(frame.clone())
                .expect("Failed to process frame");
        }

        let user =
            models::group_info::User::new(format!("Member {}", i), member_public_keys[i], vec![]);
        let frame = member_group_context
            .join_group_as(user)
            .expect("Failed to join group");

        member_group_context
            .process_frame(frame.clone())
            .expect("Failed to process own join group frame");

        frames.push(frame);
        contexts.push(member_group_context);
    }

    contexts.insert(0, group_context);

    for (i, context) in contexts.iter_mut().enumerate() {
        for j in i + 3..frames.len() {
            context
                .process_frame(frames[j].clone())
                .expect("Failed to process frame");
        }
    }

    assert_eq!(contexts[0].tree(), contexts[1].tree());
    assert_eq!(contexts[2].tree(), contexts[1].tree());
    assert_eq!(contexts[2].tree(), contexts[3].tree());

    assert_eq!(contexts[0].epoch(), contexts[1].epoch());
    assert_eq!(contexts[2].epoch(), contexts[1].epoch());
    assert_eq!(contexts[2].epoch(), contexts[3].epoch());

    let frame = contexts[2]
        .create_frame(vec![])
        .expect("Failed to create frame");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[1]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[3]
        .process_frame(frame.clone())
        .expect("Failed to process frame");

    let frame = contexts[2]
        .create_frame(vec![])
        .expect("Failed to create frame");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[1]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[3]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
}

#[test]
fn test_remove_member() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE) // щоб бачили trace/debug/info
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    // Create group
    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);
    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");
    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();
    let member_public_keys = members_secrets
        .iter()
        .map(|s| (CortadoAffine::generator() * s).into_affine())
        .collect::<Vec<CortadoAffine>>();

    let mut frames: Vec<models::frame::Frame> = Vec::with_capacity(members_secrets.len());
    let mut trees: Vec<PublicArt<CortadoAffine>> = Vec::with_capacity(members_secrets.len());
    let mut invites: Vec<models::invite::Invite> = Vec::with_capacity(members_secrets.len());

    for public_key in member_public_keys.iter() {
        let invitee = models::invite::Invitee::Identified {
            identity_public_key: *public_key,
            spk_public_key: None,
        };
        let (frame, invite) = group_context
            .add_member(invitee, vec![])
            .expect("Failed to propose add member");
        group_context
            .process_frame(frame.clone())
            .expect("Failed to process add member proposal");

        frames.push(frame);
        trees.push(group_context.commited_tree().expect("Failed to commit tree"));
        invites.push(invite);
    }

    let mut contexts: Vec<GroupContext<StdRng>> = Vec::with_capacity(members_secrets.len());

    for (i, secret_key) in members_secrets.iter().enumerate() {
        let invite_context = InviteContext::new(*secret_key, None, invites[i].clone())
            .expect("Failed to create invite context");
        let mut member_group_context = invite_context
            .upgrade(trees[i].clone())
            .expect("Failed to upgrade group context");

        for frame in frames.iter().skip(i) {
            member_group_context
                .process_frame(frame.clone())
                .expect("Failed to process frame");
        }

        let user =
            models::group_info::User::new(format!("Member {}", i), member_public_keys[i], vec![]);
        let frame = member_group_context
            .join_group_as(user)
            .expect("Failed to join group");

        member_group_context
            .process_frame(frame.clone())
            .expect("Failed to process own join group frame");

        frames.push(frame);
        contexts.push(member_group_context);
    }

    contexts.insert(0, group_context);

    for (i, context) in contexts.iter_mut().enumerate() {
        for j in i + 3..frames.len() {
            context
                .process_frame(frames[j].clone())
                .expect("Failed to process frame");
        }
    }

    let user_id = public_key_to_id(member_public_keys[0]);

    let frame = contexts[0]
        .remove_member(&user_id, vec![])
        .expect("Failed to propose remove member");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    let process_result = contexts[1].process_frame(frame.clone());
    assert!(
        matches!(
            process_result,
            Err(Error::UserRemovedFromGroup),
        ),
        "Got {process_result:?}, while expected Err(Error::UserRemovedFromGroup)"
    );
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[3]
        .process_frame(frame.clone())
        .expect("Failed to process frame");

    assert_eq!(
        contexts[0].group_info().members().len(),
        3,
        "After member removing there should be 3 users"
    );

    assert_eq!(
        contexts[2].group_info().members().len(),
        4,
        "After member removing there should be 3 users and 1 pending removal"
    );
    assert_eq!(
        contexts[3].group_info().members().len(),
        4,
        "After member removing there should be 3 users and 1 pending removal"
    );

    assert!(
        contexts[0]
            .group_info()
            .members()
            .get(&public_key_to_id(identity_public_key))
            .is_some()
    );

    trace!("{:?}", contexts[0].group_info().members());
}

#[test]
fn test_change_group() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG) // щоб бачили trace/debug/info
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();
    let _identity_public_key_bytes =
        utils::serialize(identity_public_key).expect("Failed to serialize identity public key");

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");

    frame
        .verify_schnorr::<Sha3_256>(identity_public_key)
        .expect("Frame should be signed by identity secret key");

    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let frame = group_context
        .change_group(Some(String::from("NewGrpName")), None)
        .expect("Create frame with group change");

    group_context
        .process_frame(frame)
        .expect("Process group change frame");

    assert_eq!(
        group_context.group_info().name,
        "NewGrpName",
        "Group should change name"
    );
}

#[test]
fn test_send_frame() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG) // щоб бачили trace/debug/info
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();
    let _identity_public_key_bytes =
        utils::serialize(identity_public_key).expect("Failed to serialize identity public key");

    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);

    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");

    frame
        .verify_schnorr::<Sha3_256>(identity_public_key)
        .expect("Frame should be signed by identity secret key");

    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let frame = group_context
        .create_frame(vec![])
        .expect("Create frame with group change");

    group_context
        .process_frame(frame)
        .expect("Process group change frame");
}

#[test]
fn test_leave_member() {
    let _ = tracing_subscriber::fmt()
        // .with_max_level(tracing::Level::TRACE) // щоб бачили trace/debug/info
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    let mut rng = StdRng::seed_from_u64(0);

    let group_id = Uuid::new_v4();

    let group_info =
        models::group_info::GroupInfo::new(group_id, String::from("Group"), Utc::now(), vec![]);

    let identity_secret_key = ScalarField::rand(&mut rng);
    let identity_public_key = (CortadoAffine::generator() * identity_secret_key).into_affine();

    // Create group
    let owner = models::group_info::User::new(String::from("Owner"), identity_public_key, vec![]);
    let (mut group_context, frame) = GroupContext::new(identity_secret_key, owner, group_info)
        .expect("Failed to create group context");
    group_context
        .process_frame(frame)
        .expect("Process initial frame");

    let members_secrets: Vec<ScalarField> = (0..3)
        .into_iter()
        .map(|_| ScalarField::rand(&mut rng))
        .collect();
    let member_public_keys = members_secrets
        .iter()
        .map(|s| (CortadoAffine::generator() * s).into_affine())
        .collect::<Vec<CortadoAffine>>();

    let mut frames: Vec<models::frame::Frame> = Vec::with_capacity(members_secrets.len());
    let mut trees: Vec<PublicArt<CortadoAffine>> = Vec::with_capacity(members_secrets.len());
    let mut invites: Vec<models::invite::Invite> = Vec::with_capacity(members_secrets.len());

    for public_key in member_public_keys.iter() {
        let invitee = models::invite::Invitee::Identified {
            identity_public_key: *public_key,
            spk_public_key: None,
        };
        let (frame, invite) = group_context
            .add_member(invitee, vec![])
            .expect("Failed to propose add member");
        group_context
            .process_frame(frame.clone())
            .expect("Failed to process add member proposal");

        frames.push(frame);
        trees.push(group_context.commited_tree().expect("Failed to commit tree"));
        invites.push(invite);
    }

    let mut contexts: Vec<GroupContext<StdRng>> = Vec::with_capacity(members_secrets.len());

    for (i, secret_key) in members_secrets.iter().enumerate() {
        let invite_context = InviteContext::new(*secret_key, None, invites[i].clone())
            .expect("Failed to create invite context");
        let mut member_group_context = invite_context
            .upgrade(trees[i].clone())
            .expect("Failed to upgrade group context");

        for frame in frames.iter().skip(i) {
            member_group_context
                .process_frame(frame.clone())
                .expect("Failed to process frame");
        }

        let user =
            models::group_info::User::new(format!("Member {}", i), member_public_keys[i], vec![]);
        let frame = member_group_context
            .join_group_as(user)
            .expect("Failed to join group");

        member_group_context
            .process_frame(frame.clone())
            .expect("Failed to process own join group frame");

        frames.push(frame);
        contexts.push(member_group_context);
    }

    contexts.insert(0, group_context);

    for (i, context) in contexts.iter_mut().enumerate() {
        for j in i + 3..frames.len() {
            context
                .process_frame(frames[j].clone())
                .expect("Failed to process frame");
        }
    }

    info!("Leave group with contexts[3]");
    let frame = contexts[3]
        .leave_group()
        .expect("Failed to propose leave group");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[1]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[3]
        .process_frame(frame.clone())
        .expect("Failed to process frame");

    let user_id = public_key_to_id(member_public_keys[2]);
    assert!(matches!(
        contexts[0]
            .group_info()
            .members()
            .get(&user_id)
            .unwrap()
            .status,
        models::group_info::Status::Left
    ));

    let frame = contexts[1]
        .remove_member(&user_id, vec![])
        .expect("Failed to propose remove member");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[1]
        .process_frame(frame.clone())
        .expect("Should error");
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[3]
        .process_frame(frame.clone())
        .expect_err("Should error");

    assert_eq!(
        contexts[0].group_info().members().len(),
        4,
        "After member removing there should be 3 users"
    );

    assert_eq!(
        contexts[1].group_info().members().len(),
        3,
        "After member removing there should be 3 users and 1 pending removal"
    );
    assert_eq!(
        contexts[2].group_info().members().len(),
        4,
        "After member removing there should be 3 users and 1 pending removal"
    );

    let frame = contexts[2]
        .remove_member(&user_id, vec![])
        .expect("Failed to propose remove member");

    contexts[0]
        .process_frame(frame.clone())
        .expect("Failed to process frame");
    contexts[1]
        .process_frame(frame.clone())
        .expect("Should error");
    contexts[2]
        .process_frame(frame.clone())
        .expect("Failed to process frame");

    assert_eq!(
        contexts[0].group_info().members().len(),
        4,
        "After member removing there should be 3 users"
    );

    assert_eq!(
        contexts[1].group_info().members().len(),
        3,
        "After member removing there should be 3 users and 1 pending removal"
    );
    assert_eq!(
        contexts[2].group_info().members().len(),
        3,
        "After member removing there should be 3 users and 1 pending removal"
    );
}
