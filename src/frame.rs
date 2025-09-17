enum FrameProof {
    ArtProof,
    GeneralSignature { signature: Vec<u8>, msg: Vec<u8> },
    OwnerSignature { signature: Vec<u8>, msg: Vec<u8> },
}

struct Frame {
    group_id: String,
    epoch: u64,
    nonce: Vec<u8>,

    proof: FrameProof,
}

// struct Payload {
//     signature
// }
