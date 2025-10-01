use ark_ec::CurveGroup;
use sha3::Sha3_256;
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::LeafIter,
};

use crate::{
    error::{Error, Result},
    group_context::GroupContext,
    models::{
        self,
        group_info::{GroupInfo, public_key_to_id},
        payload::{GroupActionPayload, Payload},
    },
};

impl GroupContext {
    pub fn process_frame(
        &mut self,
        frame: models::frame::Frame,
    ) -> Result<Vec<models::payload::Payload>> {
        // Validate that frame belong to this group
        let group_id = frame.frame_tbs().group_id();
        if group_id != self.group_info().id() {
            return Err(Error::InvalidGroup);
        }

        let epoch = frame.frame_tbs().epoch();
        if frame.frame_tbs().group_operation().is_none() {
            if self.group_info().members().len() == 0 {
                return Err(Error::InvalidInput);
            }

            if self.epoch() != epoch {
                return Err(Error::InvalidEpoch);
            }

            let tk = self.state.art.get_root_key()?;
            let tree_public_key = (tk.generator * tk.key).into_affine();

            frame.verify_schnorr::<Sha3_256>(tree_public_key)?;

            let protected_payload =
                models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                    frame.frame_tbs().protected_payload(),
                    &frame.frame_tbs().associated_data::<Sha3_256>()?,
                )?)?;

            let sender = match protected_payload.protected_payload_tbs().sender() {
                models::protected_payload::Sender::UserId(id) => self
                    .group_info()
                    .members()
                    .get(id)
                    .ok_or(Error::InvalidSender)?,
                _ => unimplemented!(),
            };

            protected_payload.verify::<Sha3_256>(sender.public_key())?;

            if sender.public_key() == self.identity_key_pair.public_key {
                return Ok(vec![]);
            }

            return Ok(protected_payload
                .protected_payload_tbs()
                .payloads()
                .to_vec());
        }

        match frame.frame_tbs().group_operation().unwrap() {
            models::frame::GroupOperation::Init(_) => {
                return Ok(vec![]);
            }
            models::frame::GroupOperation::AddMember(changes) => {
                if self.group_info().members().len() == 0 {
                    let protected_payload =
                        models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                            frame.frame_tbs().protected_payload(),
                            &frame.frame_tbs().associated_data::<Sha3_256>()?,
                        )?)?;

                    let group_infos = protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .iter()
                        .filter_map(|payload| match payload {
                            Payload::Action(GroupActionPayload::InviteMember(group_info)) => {
                                Some(group_info.clone())
                            }
                            _ => None,
                        })
                        .collect::<Vec<GroupInfo>>();

                    if group_infos.is_empty() {
                        return Err(Error::InvalidInput);
                    }

                    let mut group_info = group_infos[0].clone();
                    for user in self.state.group_info.members().iter() {
                        group_info
                            .members_mut()
                            .insert(user.id().to_string(), user.clone());
                    }

                    self.state.group_info = group_info;

                    return Ok(protected_payload
                        .protected_payload_tbs()
                        .payloads()
                        .to_vec());
                }

                if self.state.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.state.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self.state.verifier_artefacts(&changes)?;
                let owner_leaf_public_key = self.state.owner_public_key()?;

                frame.verify_art::<Sha3_256>(verifier_artefacts, owner_leaf_public_key)?;

                self.state.update_art(&changes)?;

                // TODO: Implement rollback mechanism, because after tree update there can be unrecoverable errors
                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => self
                        .group_info()
                        .members()
                        .get(id)
                        .ok_or(Error::InvalidInput)?,
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;
                self.state.is_last_sender = false;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            models::frame::GroupOperation::KeyUpdate(changes) => {
                if self.state.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.state.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self.state.verifier_artefacts(&changes)?;

                let old_leaf_public_key = self.state.art.get_node(&changes.node_index)?.public_key;

                frame.verify_art::<Sha3_256>(verifier_artefacts, old_leaf_public_key)?;

                self.state.update_art(&changes)?;

                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let new_users: Vec<models::group_info::User> = protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .iter()
                    .filter_map(|payload| match payload {
                        models::payload::Payload::Action(
                            models::payload::GroupActionPayload::JoinGroup(user),
                        ) => Some(user.clone()),
                        _ => None,
                    })
                    .collect();

                let mut group_info = self.group_info().clone();
                for user in new_users {
                    group_info
                        .members_mut()
                        .replace(&public_key_to_id(old_leaf_public_key), user);
                }

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => {
                        group_info.members().get(&id).ok_or(Error::InvalidInput)?
                    }
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;

                self.state.group_info = group_info;

                self.state.is_last_sender = false;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            models::frame::GroupOperation::RemoveMember(changes) => {
                if self.state.epoch >= frame.frame_tbs().epoch() {
                    return Ok(vec![]);
                }
                if self.state.epoch + 1 != frame.frame_tbs().epoch() {
                    return Err(Error::InvalidEpoch);
                }

                let verifier_artefacts = self.state.verifier_artefacts(&changes)?;
                let owner_leaf_public_key = self.state.owner_public_key()?;

                frame.verify_art::<Sha3_256>(verifier_artefacts, owner_leaf_public_key)?;

                let leaf_public_key = self
                    .state
                    .art
                    .get_node(&changes.node_index)
                    .map_err(|_| Error::InvalidInput)?
                    .public_key;

                let leaves_users = self.state.map_leaves_to_users();

                self.state.update_art(&changes)?;

                let user_to_delete = leaves_users.get(&leaf_public_key);
                if let Some(user_id) = user_to_delete {
                    self.state.group_info.members_mut().remove(user_id);
                };

                let protected_payload =
                    models::protected_payload::ProtectedPayload::decode(&self.state.decrypt(
                        frame.frame_tbs().protected_payload(),
                        &frame.frame_tbs().associated_data::<Sha3_256>()?,
                    )?)?;

                let sender = match protected_payload.protected_payload_tbs().sender() {
                    models::protected_payload::Sender::UserId(id) => self
                        .group_info()
                        .members()
                        .get(id)
                        .ok_or(Error::InvalidInput)?,
                    _ => unimplemented!(),
                };

                protected_payload.verify::<Sha3_256>(sender.public_key())?;
                self.state.is_last_sender = false;

                return Ok(protected_payload
                    .protected_payload_tbs()
                    .payloads()
                    .to_vec());
            }
            _ => unimplemented!(),
        }
    }
}
