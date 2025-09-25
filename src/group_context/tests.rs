use ark_std::rand::{Rng, RngCore};
use art::types::PublicART;
use uuid::Uuid;

use crate::{
    models::{
        frame::GroupOperation,
        group_info::{GroupMembers, User},
        invite::Invitee,
    },
    secrets_factory::SecretsFactory,
    zero_art_proto,
};

use super::*;

fn create_secrets_factory(rng: &mut StdRng) -> SecretsFactory {
    let mut secrets_factory_seed = [0u8; 32];
    rng.fill(&mut secrets_factory_seed);

    SecretsFactory::new(secrets_factory_seed)
}

fn generate_uuid(rng: &mut StdRng) -> Uuid {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    Uuid::from_bytes(bytes)
}

// fn generate_seed(rng: &mut StdRng) -> [u8; 32] {
//     let mut seed = [0u8; 32];
//     rng.fill(&mut seed);
//     seed
// }

#[test]
fn test_create_group() {
    // Use determined seed for reproducability
    let mut rng = StdRng::seed_from_u64(0);

    let mut secrets_factory = create_secrets_factory(&mut rng);

    let (owner_public_key, owner_secret_key) = secrets_factory.generate_secret_with_public_key();

    let owner = User::new(
        "owner".to_string(),
        owner_public_key,
        vec![],
        zero_art_proto::Role::Ownership,
    );

    let mut group_info = GroupInfo::new(
        generate_uuid(&mut rng),
        "group".to_string(),
        Utc::now(),
        vec![],
        GroupMembers::default(),
    );

    group_info.members_mut().insert_user(owner);

    let (group_context, initial_frame) =
        GroupContext::new(owner_secret_key, group_info).expect("Failed to create GroupContext");

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
            .get_by_public_key(&owner_public_key)
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
    // Use determined seed for reproducability
    let mut rng = StdRng::seed_from_u64(0);

    let mut secrets_factory = create_secrets_factory(&mut rng);

    let (owner_public_key, owner_secret_key) = secrets_factory.generate_secret_with_public_key();
    let (member_identity_public_key, member_identity_secret_key) = secrets_factory.generate_secret_with_public_key();
    let (member_spk_public_key, member_spk_secret_key) = secrets_factory.generate_secret_with_public_key();

    let owner = User::new(
        "owner".to_string(),
        owner_public_key,
        vec![],
        zero_art_proto::Role::Ownership,
    );

    let mut group_info = GroupInfo::new(
        generate_uuid(&mut rng),
        "group".to_string(),
        Utc::now(),
        vec![],
        GroupMembers::default(),
    );

    group_info.members_mut().insert_user(owner);

    let (mut group_context, _) =
        GroupContext::new(owner_secret_key, group_info).expect("Failed to create GroupContext");

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
    let frame_1 = group_context.key_update(new_leaf_secret, vec![]).expect("Failed to key update");
    assert_eq!(group_context.epoch(), 1);
    let public_art = PublicART { root: group_context.state.art.root.clone(), generator: CortadoAffine::generator() };
    group_context.commit_state();
    assert_eq!(group_context.epoch(), 2);

    let invite_context = InviteContext::new(member_identity_secret_key, Some(member_spk_secret_key), invite).expect("Failed to create InviritContext");
    let mut pending_group_context = invite_context.upgrade(public_art).expect("Failed to upgrade invite context to pending group context");
    pending_group_context.process_frame(frame_0).expect("Failed to process sync frame");
    pending_group_context.process_frame(frame_1).expect("Failed to sync 2");
    
    let user = User::new(
        "user".to_string(),
        member_identity_public_key,
        vec![],
        zero_art_proto::Role::Write,
    );

    let frame_2 = pending_group_context.join_group_as(user).expect("Failed to join group");
    let mut member_group_context = pending_group_context.upgrade();

    println!("{}", frame_2.frame_tbs().epoch());
    group_context.process_frame(frame_2).expect("Failed to process accept invite flow");

    let new_leaf_secret = ScalarField::rand(&mut rng);
    let frame_3 = member_group_context.key_update(new_leaf_secret, vec![]).expect("awd");
    member_group_context.commit_state();

    group_context.process_frame(frame_3).expect("awdawdawd");
    assert_eq!(group_context.epoch(), 4);
    println!("IS LAST?: {:?}", group_context.state.is_last_sender);
    let frame_4 = group_context.create_frame(vec![]).expect("awd");
    assert!(matches!(frame_4.frame_tbs().group_operation(), Some(GroupOperation::KeyUpdate(_))))
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

// #[test]
// fn test_create_group() {
//     // Use determined seed for reproducability
//     let mut rng = StdRng::seed_from_u64(0);

//     let mut secrets_factory = create_secrets_factory(&mut rng);

//     // Predefined key pairs
//     let mut key_pairs = Vec::new();
//     for _ in 0..20 {
//         key_pairs.push(secrets_factory.generate_secret_with_public_key());
//     }

//     let owner_user = models::group_info::User::new(
//         String::from("owner"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let group_info = models::group_info::GroupInfo::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
//         String::from("group_1"),
//         Utc::now(),
//         vec![],
//         models::group_info::GroupMembers::default(),
//     );

//     let mut context_seed = [0u8; 32];
//     rng.fill(&mut context_seed);

//     let mut proof_system_seed = [0u8; 32];
//     rng.fill(&mut proof_system_seed);

//     let result = group_context::builder::GroupContextBuilder::new(key_pairs[0].1)
//         .context_prng_seed(context_seed)
//         .proof_system_prng_seed(proof_system_seed)
//         .create(owner_user, group_info)
//         .identified_members_keys(vec![
//             (key_pairs[1].0, Some(key_pairs[2].0)),
//             (key_pairs[3].0, None),
//         ])
//         .unidentified_members_count(3)
//         .payloads(vec![])
//         .build();

//     assert!(result.is_ok(), "Failed to create group context");

//     let (mut group_context, _init_frame, identified_invites, unidentified_invites) =
//         result.unwrap();

//     assert_eq!(
//         identified_invites.len(),
//         2,
//         "Group created with 2 identified invites"
//     );
//     assert_eq!(
//         unidentified_invites.len(),
//         3,
//         "Group created with 3 unidentified invites"
//     );

//     // Check if identified invite is invited users
//     let public_key_1_bytes = crate::utils::serialize(key_pairs[1].0).unwrap();
//     let public_key_3_bytes = crate::utils::serialize(key_pairs[3].0).unwrap();

//     identified_invites.get(&key_pairs[1].0).unwrap();
//     identified_invites.get(&key_pairs[3].0).unwrap();

//     assert_eq!(
//         group_context.art.get_root().weight,
//         6,
//         "ART should have 6 leafs (owner + 2 identified + 3 unidentified)"
//     );

//     let _public_art_bytes = group_context.art.serialize().unwrap();

//     let _user_1 = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440002").unwrap(),
//         String::from("user"),
//         CortadoAffine::generator(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let _invite = identified_invites.get(&key_pairs[1].0).unwrap().clone();

//     let (_identity_public_key_1, _identity_secret_key_1) = key_pairs[1];
//     let (_spk_public_key_2, _spk_secret_key_2) = key_pairs[2];

//     // let (mut secondary_group_context, join_group_frame) = GroupContext::from_invite(
//     //     identity_secret_key_1,
//     //     Some(spk_secret_key_2),
//     //     public_art_bytes.clone(),
//     //     invite,
//     //     user_1,
//     // )
//     // .unwrap();

//     let (identity_public_key_4, identity_secret_key_4) = key_pairs[4];
//     let (spk_public_key_5, spk_secret_key_5) = key_pairs[5];

//     let (_frame, invite) = group_context
//         .add_member(
//             models::invite::Invitee::Identified {
//                 identity_public_key: identity_public_key_4,
//                 spk_public_key: Some(spk_public_key_5),
//             },
//             vec![],
//         )
//         .unwrap();

//     let public_art_bytes = group_context.art.serialize().unwrap();

//     let user_1 = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440003").unwrap(),
//         String::from("user"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let (mut _secondary_group_context, join_group_frame) = GroupContext::from_invite(
//         identity_secret_key_4,
//         Some(spk_secret_key_5),
//         public_art_bytes,
//         invite,
//         user_1,
//     )
//     .unwrap();

//     let (leaf_secret, art, stk, epoch, group_info) = group_context.into_parts().unwrap();
//     let mut group_context = GroupContext::from_parts(
//         key_pairs[0].1,
//         leaf_secret,
//         &art,
//         stk.try_into().unwrap(),
//         epoch,
//         group_info.try_into().unwrap(),
//         false,
//     )
//     .unwrap();

//     group_context.process_frame(join_group_frame).unwrap();

//     // let payloads = secondary_group_context
//     //     .process_frame(zero_art_proto::SpFrame {
//     //         seq_num: 0,
//     //         created: None,
//     //         frame: Some(join_group_frame),
//     //     })
//     //     .unwrap();
//     // assert_eq!(payloads.len(), 0);
// }

// #[test]
// fn test_create_new_group_2() {
//     // Use determined seed for reproducability
//     let mut rng = StdRng::seed_from_u64(0);

//     let mut secrets_factory_seed = [0u8; 32];
//     rng.fill(&mut secrets_factory_seed);

//     let mut secrets_factory = secrets_factory::SecretsFactory::new(secrets_factory_seed);

//     // Predefined key pairs
//     let mut key_pairs = Vec::new();
//     for _ in 0..20 {
//         key_pairs.push(secrets_factory.generate_secret_with_public_key());
//     }

//     let owner_user = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440001").unwrap(),
//         String::from("owner"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let group_info = models::group_info::GroupInfo::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
//         String::from("group_1"),
//         Utc::now(),
//         vec![],
//         models::group_info::GroupMembers::default(),
//     );

//     let mut context_seed = [0u8; 32];
//     rng.fill(&mut context_seed);

//     let mut proof_system_seed = [0u8; 32];
//     rng.fill(&mut proof_system_seed);

//     let result = group_context::builder::GroupContextBuilder::new(key_pairs[0].1)
//         .context_prng_seed(context_seed)
//         .proof_system_prng_seed(proof_system_seed)
//         .create(owner_user, group_info)
//         .unidentified_members_count(1)
//         .payloads(vec![])
//         .build();
//     assert!(result.is_ok(), "Failed to create group context");

//     let (mut group_context, _init_frame, _identified_invites, _unidentified_invites) =
//         result.unwrap();

//     let (_invite_public_key_1, _invite_secret_key_1) = key_pairs[1];

//     let (_frame, invite) = group_context
//         .add_member(
//             models::invite::Invitee::Identified {
//                 identity_public_key: key_pairs[1].0,
//                 spk_public_key: None,
//             },
//             vec![],
//         )
//         .unwrap();

//     let public_art_bytes = group_context.art.serialize().unwrap();

//     let user_1 = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440002").unwrap(),
//         String::from("user"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     println!("awd");
//     let (mut _secondary_group_context, join_group_frame) =
//         GroupContext::from_invite(key_pairs[1].1, None, public_art_bytes, invite, user_1).unwrap();

//     println!("Frame epocch: {}", join_group_frame.frame_tbs().epoch());

//     println!("Epoch: {}", group_context.epoch);
//     let paylaods = group_context.process_frame(join_group_frame).unwrap();

//     println!("Epoch: {}", group_context.epoch);
//     assert!(paylaods.len() != 0);
// }

// #[test]
// fn test_create_group_add_unidentified() {
//     // Use determined seed for reproducability
//     let mut rng = StdRng::seed_from_u64(0);

//     let mut secrets_factory_seed = [0u8; 32];
//     rng.fill(&mut secrets_factory_seed);

//     let mut secrets_factory = secrets_factory::SecretsFactory::new(secrets_factory_seed);

//     // Predefined key pairs
//     let mut key_pairs = Vec::new();
//     for _ in 0..20 {
//         key_pairs.push(secrets_factory.generate_secret_with_public_key());
//     }

//     let owner_user = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440001").unwrap(),
//         String::from("owner"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let group_info = models::group_info::GroupInfo::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440000").unwrap(),
//         String::from("group_1"),
//         Utc::now(),
//         vec![],
//         models::group_info::GroupMembers::default(),
//     );

//     //
//     let mut context_seed = [0u8; 32];
//     rng.fill(&mut context_seed);

//     let mut proof_system_seed = [0u8; 32];
//     rng.fill(&mut proof_system_seed);

//     let result = group_context::builder::GroupContextBuilder::new(key_pairs[0].1)
//         .context_prng_seed(context_seed)
//         .proof_system_prng_seed(proof_system_seed)
//         .create(owner_user, group_info)
//         .unidentified_members_count(1)
//         .payloads(vec![])
//         .build();
//     assert!(result.is_ok(), "Failed to create group context");

//     let (mut group_context, _init_frame, _identified_invites, _unidentified_invites) =
//         result.unwrap();

//     let (_frame, invite) = group_context
//         .add_member(
//             models::invite::Invitee::Unidentified(key_pairs[2].1),
//             vec![],
//         )
//         .unwrap();

//     let public_art_bytes = group_context.art.serialize().unwrap();

//     //

//     let user_1 = models::group_info::User::new(
//         Uuid::parse_str("123e4567-e89b-12d3-a456-426655440002").unwrap(),
//         String::from("user"),
//         CortadoAffine::default(),
//         vec![],
//         zero_art_proto::Role::default(),
//     );
//     let (_identity_public_key_1, identity_secret_key_1) = key_pairs[1];
//     let (mut _secondary_group_context, _join_group_frame) = GroupContext::from_invite(
//         identity_secret_key_1,
//         None,
//         public_art_bytes,
//         invite,
//         user_1,
//     )
//     .unwrap();
// }

// #[test]
// fn test_indexation() {
//     // Use determined seed for reproducability
//     let mut rng = StdRng::seed_from_u64(0);

//     let mut secrets_factory_seed = [0u8; 32];
//     rng.fill(&mut secrets_factory_seed);

//     let mut secrets_factory = secrets_factory::SecretsFactory::new(secrets_factory_seed);

//     let (public_key_1, secret_key_1) = secrets_factory.generate_secret_with_public_key();
//     println!("PublicKey 1: {}", public_key_1);
//     let (public_key_2, secret_key_2) = secrets_factory.generate_secret_with_public_key();
//     println!("PublicKey 2: {}", public_key_2);
//     let (public_key_3, secret_key_3) = secrets_factory.generate_secret_with_public_key();
//     println!("PublicKey 3: {}", public_key_3);
//     let (public_key_4, secret_key_4) = secrets_factory.generate_secret_with_public_key();
//     println!("PublicKey 4: {}", public_key_4);

//     let (mut private_art, _) = PrivateART::new_art_from_secrets(
//         &vec![secret_key_1, secret_key_2, secret_key_3],
//         &CortadoAffine::generator(),
//     )
//     .unwrap();

//     private_art
//         .make_blank(
//             &private_art.get_path_to_leaf(&public_key_2).unwrap(),
//             &secret_key_4,
//         )
//         .unwrap();

//     for (i, public_key) in LeafIter::new(&private_art.root)
//         .filter_map(|node| {
//             if node.is_blank {
//                 None
//             } else {
//                 Some(node.public_key)
//             }
//         })
//         .enumerate()
//     {
//         println!("PublicKey iter {}: {}", i, public_key);
//     }
// }
