pub mod builders;
pub mod group_context;
pub mod metadata;
pub mod proof_system;
pub mod secrets_factory;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod zero_art_proto {
    include!(concat!(env!("OUT_DIR"), "/zero_art_proto.rs"));
}
