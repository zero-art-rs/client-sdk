use crate::zero_art_proto::{Frame, FrameTbs, GroupOperation, IdentifiedInvite, Invite, ProtectedInviteData,
    UnidentifiedInvite, group_operation::Operation, invite,
};

#[derive(Default)]
pub struct FrameTbsBuilder(FrameTbs);
impl FrameTbsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn epoch(mut self, epoch: u64) -> Self {
        self.0.epoch = epoch;
        self
    }

    pub fn group_operation(mut self, group_operation: GroupOperation) -> Self {
        self.0.group_operation = Some(group_operation);
        self
    }

    pub fn protected_payload(mut self, protected_payload: Vec<u8>) -> Self {
        self.0.protected_payload = protected_payload;
        self
    }

    pub fn nonce(mut self, nonce: Vec<u8>) -> Self {
        self.0.nonce = nonce;
        self
    }

    pub fn build(self) -> FrameTbs {
        self.0
    }
}

#[derive(Default)]
pub struct FrameBuilder(Frame);
impl FrameBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn frame(mut self, frame: FrameTbs) -> Self {
        self.0.frame = Some(frame);
        self
    }

    pub fn proof(mut self, proof: Vec<u8>) -> Self {
        self.0.proof = proof;
        self
    }

    pub fn build(self) -> Frame {
        self.0
    }
}

#[derive(Default)]
pub struct GroupOperationBuilder(GroupOperation);
impl GroupOperationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn operation(mut self, operation: Operation) -> Self {
        self.0.operation = Some(operation);
        self
    }

    pub fn build(self) -> GroupOperation {
        self.0
    }
}

#[derive(Default)]
pub struct IdentifiedInviteBuilder(IdentifiedInvite);
impl IdentifiedInviteBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity_public_key(mut self, identity_public_key: Vec<u8>) -> Self {
        self.0.identity_public_key = identity_public_key;
        self
    }

    pub fn ephemeral_public_key(mut self, ephemeral_public_key: Vec<u8>) -> Self {
        self.0.ephemeral_public_key = ephemeral_public_key;
        self
    }

    pub fn spk_public_key(mut self, spk_public_key: Vec<u8>) -> Self {
        self.0.spk_public_key = spk_public_key;
        self
    }

    pub fn protected_invite_data(mut self, protected_invite_data: Vec<u8>) -> Self {
        self.0.protected_invite_data = protected_invite_data;
        self
    }

    pub fn build(self) -> IdentifiedInvite {
        self.0
    }
}

#[derive(Default)]
pub struct UnidentifiedInviteBuilder(UnidentifiedInvite);
impl UnidentifiedInviteBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity_public_key(mut self, identity_public_key: Vec<u8>) -> Self {
        self.0.identity_public_key = identity_public_key;
        self
    }

    pub fn ephemeral_public_key(mut self, ephemeral_public_key: Vec<u8>) -> Self {
        self.0.ephemeral_public_key = ephemeral_public_key;
        self
    }

    pub fn private_key(mut self, private_key: Vec<u8>) -> Self {
        self.0.private_key = private_key;
        self
    }

    pub fn protected_invite_data(mut self, protected_invite_data: Vec<u8>) -> Self {
        self.0.protected_invite_data = protected_invite_data;
        self
    }

    pub fn build(self) -> UnidentifiedInvite {
        self.0
    }
}

#[derive(Default)]
pub struct InviteBuilder(Invite);
impl InviteBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn invite(mut self, invite: invite::Invite) -> Self {
        self.0.invite = Some(invite);
        self
    }

    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.0.signature = signature;
        self
    }

    pub fn build(self) -> Invite {
        self.0
    }
}

#[derive(Default)]
pub struct ProtectedInviteDataBuilder(ProtectedInviteData);
impl ProtectedInviteDataBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // TODO: Replace String with &str or AsRef<str>
    pub fn group_id(mut self, group_id: String) -> Self {
        self.0.group_id = group_id;
        self
    }

    pub fn epoch(mut self, epoch: u64) -> Self {
        self.0.epoch = epoch;
        self
    }

    pub fn build(self) -> ProtectedInviteData {
        self.0
    }
}
