use chrono::{DateTime, Utc};
use prost::Message;

use crate::{
    models::{errors::Error, payload::Payload},
    zero_art_proto,
};

#[derive(Debug, Clone, Default)]
pub struct ProtectedPayload {
    pub protected_payload_tbs: ProtectedPayloadTbs,
    pub signature: Vec<u8>,
}

impl TryFrom<zero_art_proto::ProtectedPayload> for ProtectedPayload {
    type Error = Error;

    fn try_from(value: zero_art_proto::ProtectedPayload) -> Result<Self, Self::Error> {
        let protected_payload_tbs = value
            .payload
            .ok_or(Error::RequiredFieldAbsent)?
            .try_into()?;
        Ok(Self {
            protected_payload_tbs,
            signature: value.signature,
        })
    }
}

impl From<ProtectedPayload> for zero_art_proto::ProtectedPayload {
    fn from(value: ProtectedPayload) -> Self {
        let payload = value.protected_payload_tbs.into();
        Self {
            payload: Some(payload),
            signature: value.signature,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProtectedPayloadTbs {
    pub seq_num: u64,
    pub created: DateTime<Utc>,
    pub payloads: Vec<Payload>,
    pub sender: Sender,
}

impl ProtectedPayloadTbs {
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let inner: zero_art_proto::ProtectedPayloadTbs = self.clone().into();
        inner.encode_to_vec()
    }

    pub fn decode(data: Vec<u8>) -> Result<Self, Error> {
        zero_art_proto::ProtectedPayloadTbs::decode(&data[..])?.try_into()
    }
}

impl TryFrom<zero_art_proto::ProtectedPayloadTbs> for ProtectedPayloadTbs {
    type Error = Error;

    fn try_from(value: zero_art_proto::ProtectedPayloadTbs) -> Result<Self, Self::Error> {
        let timestamp_proto = value.created.ok_or(Error::RequiredFieldAbsent)?;
        let created =
            DateTime::from_timestamp(timestamp_proto.seconds, timestamp_proto.nanos as u32)
                .ok_or(Error::RequiredFieldAbsent)?;
        let sender = value.sender.ok_or(Error::RequiredFieldAbsent)?.into();
        let payloads = value
            .payload
            .into_iter()
            .map(Payload::try_from)
            .collect::<Result<Vec<Payload>, Self::Error>>()?;

        Ok(Self {
            seq_num: value.seq_num,
            created,
            payloads,
            sender,
        })
    }
}

impl From<ProtectedPayloadTbs> for zero_art_proto::ProtectedPayloadTbs {
    fn from(value: ProtectedPayloadTbs) -> Self {
        let created = prost_types::Timestamp {
            seconds: value.created.timestamp(),
            nanos: value.created.timestamp_subsec_nanos() as i32,
        };
        let payload = value
            .payloads
            .into_iter()
            .map(zero_art_proto::Payload::from)
            .collect::<Vec<zero_art_proto::Payload>>();
        let sender = value.sender.into();
        Self {
            seq_num: value.seq_num,
            created: Some(created),
            payload,
            sender: Some(sender),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Sender {
    UserId(String),
    LeafId(String),
}

impl Default for Sender {
    fn default() -> Self {
        Sender::UserId(String::default())
    }
}

impl From<zero_art_proto::protected_payload_tbs::Sender> for Sender {
    fn from(value: zero_art_proto::protected_payload_tbs::Sender) -> Self {
        match value {
            zero_art_proto::protected_payload_tbs::Sender::UserId(id) => Sender::UserId(id),
            zero_art_proto::protected_payload_tbs::Sender::LeafId(id) => Sender::LeafId(id),
        }
    }
}

impl From<Sender> for zero_art_proto::protected_payload_tbs::Sender {
    fn from(value: Sender) -> Self {
        match value {
            Sender::UserId(id) => zero_art_proto::protected_payload_tbs::Sender::UserId(id),
            Sender::LeafId(id) => zero_art_proto::protected_payload_tbs::Sender::LeafId(id),
        }
    }
}
