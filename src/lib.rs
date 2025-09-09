use prost::Message;

pub mod builders;
pub mod group_context;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

mod zero_art_proto {
    include!(concat!(env!("OUT_DIR"), "/zero_art_proto.rs"));
}

/// Returns a large shirt of the specified color
pub fn create_large_shirt() {
    let mut a = zero_art_proto::FrameTbs::default();
    let mut a = zero_art_proto::Frame::default();
    // a.epoch = 100;

    let mut buf = Vec::new();
    buf.reserve(a.encoded_len());
    a.encode(&mut buf).unwrap();

    println!("Encoded bytes: {:?}", buf);

    // let mut shirt = items::Shirt::default();
    // shirt.color = color;
    // shirt.set_size(items::shirt::Size::Large);
    // shirt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        create_large_shirt();
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
