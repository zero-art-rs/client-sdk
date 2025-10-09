use ark_std::rand::RngCore;
use uuid::Uuid;
use zrt_art::types::PublicART;

use crate::{
    invite_context::InviteContext,
    models::{frame::GroupOperation, group_info::User, invite::Invitee},
};

use super::*;

fn generate_key_pair(rng: &mut StdRng) -> (CortadoAffine, ScalarField) {
    let secret_key = ScalarField::rand(rng);
    let public_key = (CortadoAffine::generator() * secret_key).into_affine();
    (public_key, secret_key)
}

fn generate_uuid(rng: &mut StdRng) -> Uuid {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    Uuid::from_bytes(bytes)
}

#[test]
fn test_create_group() {
    // Use determined seed for reproducability
    let mut _rng = StdRng::seed_from_u64(0);
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();

    let (owner_public_key, owner_secret_key) = generate_key_pair(&mut rng);

    let owner = User::new(
        "owner".to_string(),
        owner_public_key,
        vec![],
        Role::Ownership,
    );

    let group_info = GroupInfo::new(
        generate_uuid(&mut rng),
        "group".to_string(),
        Utc::now(),
        vec![],
    );

    let (group_context, initial_frame) = GroupContext::new(owner_secret_key, owner, group_info)
        .expect("Failed to create GroupContext");

    // Check group context correctness
    assert_eq!(
        group_context.epoch(),
        0,
        "New group should have epoch 0 at start"
    );
    assert_eq!(
        group_context.identity_key_pair.public_key, owner_public_key,
        "Invalid group context identity public key"
    );
    assert_eq!(
        group_context.identity_key_pair.secret_key, owner_secret_key,
        "Invalid group context identity secret key"
    );

    // Check correctness of group info
    assert_eq!(
        group_context.group_info().members().len(),
        1,
        "Group should have only one member - owner"
    );
    assert!(
        group_context
            .group_info()
            .members()
            .get(&public_key_to_id(owner_public_key))
            .is_some(),
        "Owner should be in group members"
    );

    // Check initial frame
    initial_frame
        .verify_schnorr::<Sha3_256>(owner_public_key)
        .expect("Frame proof should be owner schnorr signature");
    assert_eq!(
        initial_frame.frame_tbs().group_id(),
        group_context.group_info().id(),
        "Initial frame group_id should be equal to group_context id"
    );
    assert_eq!(
        initial_frame.frame_tbs().epoch(),
        0,
        "Initial frame epoch should be 0"
    );

    let group_operation = initial_frame
        .frame_tbs()
        .group_operation()
        .expect("Initial frame should have group operation");
    if let GroupOperation::Init(art) = group_operation {
        assert_eq!(
            art,
            &PublicART {
                root: group_context.state.art.root.clone(),
                generator: CortadoAffine::generator()
            },
            "Invalid ART in the initial frame"
        );
    } else {
        panic!("Initial frame have invalid group operation");
    }
}

#[test]
fn test_add_identified_member() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE) // щоб бачили trace/debug/info
        .with_test_writer() // щоб писало в буфер тестів
        .try_init();
    // Use determined seed for reproducability
    let mut rng = StdRng::seed_from_u64(0);

    let (owner_public_key, owner_secret_key) = generate_key_pair(&mut rng);
    let (member_identity_public_key, member_identity_secret_key) = generate_key_pair(&mut rng);
    let (member_spk_public_key, member_spk_secret_key) = generate_key_pair(&mut rng);

    let owner = User::new(
        "owner".to_string(),
        owner_public_key,
        vec![],
        Role::Ownership,
    );

    let group_info = GroupInfo::new(
        generate_uuid(&mut rng),
        "group".to_string(),
        Utc::now(),
        vec![],
    );

    let (mut group_context, _) = GroupContext::new(owner_secret_key, owner, group_info)
        .expect("Failed to create GroupContext");

    let (frame_0, invite) = group_context
        .add_member(
            Invitee::Identified {
                identity_public_key: member_identity_public_key,
                spk_public_key: Some(member_spk_public_key),
            },
            vec![],
        )
        .expect("Failed to add member in group context");

    group_context.commit_state();
    assert_eq!(
        group_context.epoch(),
        1,
        "Add member should increment epoch"
    );

    let new_leaf_secret = ScalarField::rand(&mut rng);
    let frame_1 = group_context
        .key_update(new_leaf_secret, vec![])
        .expect("Failed to key update");
    assert_eq!(group_context.epoch(), 1);
    let public_art = PublicART {
        root: group_context.state.art.root.clone(),
        generator: CortadoAffine::generator(),
    };
    group_context.commit_state();
    assert_eq!(group_context.epoch(), 2);

    let invite_context = InviteContext::new(
        member_identity_secret_key,
        Some(member_spk_secret_key),
        invite,
    )
    .expect("Failed to create InviritContext");
    let mut pending_group_context = invite_context
        .upgrade(public_art)
        .expect("Failed to upgrade invite context to pending group context");
    pending_group_context
        .process_frame(frame_0)
        .expect("Failed to process sync frame");
    pending_group_context
        .process_frame(frame_1)
        .expect("Failed to sync 2");

    let user = User::new(
        "user".to_string(),
        member_identity_public_key,
        vec![],
        Role::Write,
    );

    let frame_2 = pending_group_context
        .join_group_as(user)
        .expect("Failed to join group");
    let _member_group_context = pending_group_context;

    group_context
        .process_frame(frame_2)
        .expect("Failed to process accept invite flow");

    let _ = ScalarField::rand(&mut rng);
    // let frame_3 = member_group_context
    //     .key_update(new_leaf_secret, vec![])
    //     .expect("awd");
    // member_group_context.commit_state();

    // group_context.process_frame(frame_3).expect("awdawdawd");
    // assert_eq!(group_context.epoch(), 4);
    // let frame_4 = group_context.create_frame(vec![]).expect("awd");
    // assert!(matches!(
    //     frame_4.frame_tbs().group_operation(),
    //     Some(GroupOperation::KeyUpdate(_))
    // ))
}

#[test]
fn test_add_remove_flow() {
    // Use determined seed for reproducability
    let mut rng = StdRng::seed_from_u64(0);

    let (owner_public_key, owner_secret_key) = generate_key_pair(&mut rng);

    let owner = User::new(
        "owner".to_string(),
        owner_public_key,
        vec![],
        Role::Ownership,
    );

    let group_info = GroupInfo::new(
        generate_uuid(&mut rng),
        "group".to_string(),
        Utc::now(),
        vec![],
    );

    let (mut group_context, _) = GroupContext::new(owner_secret_key, owner, group_info)
        .expect("Failed to create GroupContext");

    assert_eq!(
        group_context.state.group_info.members().len(),
        1,
        "Group should have only one member"
    );
    assert!(
        matches!(
            group_context
                .state
                .group_info
                .members()
                .get(&public_key_to_id(owner_public_key)),
            Some(_)
        ),
        "Owner should be in group members"
    );

    let (member_1_identity_public_key, member_1_identity_secret_key) = generate_key_pair(&mut rng);
    let (member_1_spk_public_key, member_1_spk_secret_key) = generate_key_pair(&mut rng);
    // let (member_2_identity_public_key, member_2_identity_secret_key) = generate_key_pair(&mut rng);
    // let (member_2_spk_public_key, member_2_spk_secret_key) = generate_key_pair(&mut rng);

    let (frame_0, invite) = group_context
        .add_member(
            Invitee::Identified {
                identity_public_key: member_1_identity_public_key,
                spk_public_key: Some(member_1_spk_public_key),
            },
            vec![],
        )
        .expect("Failed to add member in group context");
    group_context.commit_state();

    assert_eq!(
        group_context.state.group_info.members().len(),
        2,
        "Group should have 2 members"
    );
    assert!(
        matches!(
            group_context
                .state
                .group_info
                .members()
                .get(&public_key_to_id(owner_public_key)),
            Some(_)
        ),
        "Owner should be in group members"
    );

    let invite_context = InviteContext::new(
        member_1_identity_secret_key,
        Some(member_1_spk_secret_key),
        invite,
    )
    .expect("Failed to create invite context");
    let mut pending_group_context = invite_context
        .upgrade(PublicART {
            root: group_context.state.art.root.clone(),
            generator: CortadoAffine::generator(),
        })
        .expect("Failed to upgrade invite context");

    let user_1 = User::new(
        "user_1".to_string(),
        member_1_identity_public_key,
        vec![],
        Role::Write,
    );

    pending_group_context
        .process_frame(frame_0)
        .expect("Failed to process frame");

    let frame_1 = pending_group_context
        .join_group_as(user_1)
        .expect("Failed to create join gorup frame");
    group_context
        .process_frame(frame_1)
        .expect("Failed to process frame");

    // let member_1_group_context = pending_group_context.upgrade();

    // println!("GroupInfo 1: {:?}", group_context.state.group_info);
    // println!("GroupInfo 2: {:?}", member_1_group_context.state.group_info);

    // let id_to_remove = invited_user.id().to_string();

    // let (frame_1, removed_user) = group_context.remove_member(&id_to_remove, vec![]).expect("Failed to remove member");
    // group_context.commit_state();
    // println!("Remove user: {:?}", removed_user);

    // assert_eq!(group_context.state.group_info.members().len(), 1, "Group should have 1 member after removing");
    // assert!(matches!(group_context.state.group_info.members().get_by_public_key(&owner_public_key), Some(_)), "Owner should be in group members");

    // group_context.remove_member(user_id, payloads);
}

#[test]
fn test_add_unidentified_member() {}

#[test]
fn test_accept_unidentified_invite() {}

#[test]
fn test_key_update() {}

#[test]
fn test_create_frame() {}

#[test]
fn test_process_frame_data() {}

#[test]
fn test_process_frame_init() {}

#[test]
fn test_process_frame_add_member() {}

#[test]
fn test_process_frame_key_update() {}

#[test]
fn test_process_frame_() {}
