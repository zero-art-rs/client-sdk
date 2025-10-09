use ark_ec::{AffineRepr, CurveGroup};
use chrono::{DateTime, Utc};
use cortado::{self, CortadoAffine, Fr as ScalarField};
use prost::Message;
use sha3::Digest;
use zrt_crypto::schnorr;

use crate::{
    error::{Error, Result},
    models::payload::Payload,
    zero_art_proto,
};

#[derive(Debug, Clone, Default)]
pub struct ProtectedPayload {
    protected_payload_tbs: ProtectedPayloadTbs,
    signature: Vec<u8>,
}

impl ProtectedPayload {
    pub fn new(protected_payload_tbs: ProtectedPayloadTbs, signature: Vec<u8>) -> Self {
        Self {
            protected_payload_tbs,
            signature,
        }
    }

    // Getters
    pub fn protected_payload_tbs(&self) -> &ProtectedPayloadTbs {
        &self.protected_payload_tbs
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    // Verify signature
    pub fn verify<D: Digest>(&self, public_key: CortadoAffine) -> Result<()> {
        Ok(schnorr::verify(
            &self.signature,
            &vec![public_key],
            &D::digest(self.protected_payload_tbs.encode_to_vec()),
        )?)
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let inner: zero_art_proto::ProtectedPayload = self.clone().into();
        inner.encode_to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::ProtectedPayload::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::ProtectedPayload> for ProtectedPayload {
    type Error = Error;

    fn try_from(value: zero_art_proto::ProtectedPayload) -> Result<Self> {
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
    seq_num: u64,
    created: DateTime<Utc>,
    payloads: Vec<Payload>,
    sender: Sender,
}

impl ProtectedPayloadTbs {
    pub fn new(
        seq_num: u64,
        created: DateTime<Utc>,
        payloads: Vec<Payload>,
        sender: Sender,
    ) -> Self {
        Self {
            seq_num,
            created,
            payloads,
            sender,
        }
    }

    // Getters
    pub fn seq_num(&self) -> u64 {
        self.seq_num
    }

    // TODO: Check if DateTime<Utc> implements Copy
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    // Sign payload and return ProtectedPayload
    pub fn sign<D: Digest>(self, secret_key: ScalarField) -> Result<ProtectedPayload> {
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();
        let signature = schnorr::sign(
            &vec![secret_key],
            &vec![public_key],
            &D::digest(self.encode_to_vec()),
        )?;
        Ok(ProtectedPayload {
            protected_payload_tbs: self,
            signature,
        })
    }

    // Serialization
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let inner: zero_art_proto::ProtectedPayloadTbs = self.clone().into();
        inner.encode_to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        zero_art_proto::ProtectedPayloadTbs::decode(data)?.try_into()
    }
}

impl TryFrom<zero_art_proto::ProtectedPayloadTbs> for ProtectedPayloadTbs {
    type Error = Error;

    fn try_from(value: zero_art_proto::ProtectedPayloadTbs) -> Result<Self> {
        let timestamp_proto = value.created.ok_or(Error::RequiredFieldAbsent)?;
        let created =
            DateTime::from_timestamp(timestamp_proto.seconds, timestamp_proto.nanos as u32)
                .ok_or(Error::RequiredFieldAbsent)?;
        let sender = value.sender.ok_or(Error::RequiredFieldAbsent)?.into();
        let payloads = value
            .payload
            .into_iter()
            .map(Payload::try_from)
            .collect::<Result<Vec<Payload>>>()?;

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
        Sender::UserId(String::new())
    }
}

impl From<zero_art_proto::protected_payload_tbs::Sender> for Sender {
    fn from(value: zero_art_proto::protected_payload_tbs::Sender) -> Self {
        match value {
            // TODO: Remove expect
            zero_art_proto::protected_payload_tbs::Sender::UserId(id) => Sender::UserId(id),
            zero_art_proto::protected_payload_tbs::Sender::LeafId(id) => Sender::LeafId(id),
        }
    }
}

impl From<Sender> for zero_art_proto::protected_payload_tbs::Sender {
    fn from(value: Sender) -> Self {
        match value {
            Sender::UserId(id) => {
                zero_art_proto::protected_payload_tbs::Sender::UserId(id.to_string())
            }
            Sender::LeafId(id) => zero_art_proto::protected_payload_tbs::Sender::LeafId(id),
        }
    }
}
