use cortado::CortadoAffine;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafIter, PrivateART, PublicART},
};

use crate::{
    error::{Error, Result},
    models::frame::{Frame, GroupOperation},
    utils::{decrypt, derive_stage_key, deserialize},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Validator {
    base_art: PublicART<CortadoAffine>,
    current_art: PublicART<CortadoAffine>,
    changes: Vec<BranchChanges<CortadoAffine>>,
    closed: bool,
    epoch: u64,
}

impl Validator {
    pub fn new(base_art: PublicART<CortadoAffine>, epoch: u64) -> Self {
        Self {
            current_art: base_art.clone(),
            base_art,
            changes: vec![],
            closed: true,
            epoch,
        }
    }

    pub fn validate(&mut self, frame: &Frame) -> Result<()> {
        let frame_epoch = frame.frame_tbs().epoch();

        if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
            return Err(Error::InvalidEpoch);
        }

        let is_next_epoch = frame_epoch == self.epoch + 1;

        // If frame don't have group operation then it is just payload frame that should have current epoch
        if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
            return frame.verify_schnorr::<Sha3_256>(self.current_art.get_root().public_key);
        }

        let group_operation = frame
            .frame_tbs()
            .group_operation()
            .ok_or(Error::InvalidEpoch)?;

        match group_operation {
            GroupOperation::AddMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    (
                        self.current_art
                            .compute_artefacts_for_verification(changes)?,
                        group_owner_leaf_public_key(&self.current_art),
                    )
                } else {
                    (
                        self.base_art.compute_artefacts_for_verification(changes)?,
                        group_owner_leaf_public_key(&self.base_art),
                    )
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                self.apply_changes(changes, is_next_epoch)?;

                self.closed = true;

                Ok(())
            }
            GroupOperation::KeyUpdate(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    (
                        self.current_art
                            .compute_artefacts_for_verification(changes)?,
                        self.current_art.get_node(&changes.node_index)?.public_key,
                    )
                } else {
                    (
                        self.base_art.compute_artefacts_for_verification(changes)?,
                        self.base_art.get_node(&changes.node_index)?.public_key,
                    )
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(())
            }
            GroupOperation::RemoveMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    (
                        self.current_art
                            .compute_artefacts_for_verification(changes)?,
                        group_owner_leaf_public_key(&self.current_art),
                    )
                } else {
                    (
                        self.base_art.compute_artefacts_for_verification(changes)?,
                        group_owner_leaf_public_key(&self.base_art),
                    )
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
                self.apply_changes(changes, is_next_epoch)?;

                self.closed = false;

                Ok(())
            }
            GroupOperation::Init(_) => {
                if frame_epoch != 0 {
                    return Err(Error::InvalidEpoch);
                }

                let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
                frame.verify_schnorr::<Sha3_256>(owner_public_key)
            }
            GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.current_art.get_node(node_index)?.public_key;
                frame.verify_schnorr::<Sha3_256>(public_key)
            }
            GroupOperation::DropGroup(_) => unimplemented!(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }

    fn apply_changes(
        &mut self,
        changes: &BranchChanges<CortadoAffine>,
        is_next_epoch: bool,
    ) -> Result<()> {
        if !is_next_epoch {
            let mut current_art = self.base_art.clone();
            current_art.merge_all(&vec![self.changes.clone(), vec![changes.clone()]].concat())?;

            self.current_art = current_art;

            self.changes.push(changes.clone());

            return Ok(());
        }

        let base_art = self.current_art.clone();
        let mut current_art = self.current_art.clone();
        current_art.update_public_art(changes)?;

        self.base_art = base_art;
        self.current_art = current_art;

        self.changes = vec![changes.clone()];

        Ok(())
    }
}

fn group_owner_leaf_public_key<A: ARTPublicView<CortadoAffine>>(art: &A) -> CortadoAffine {
    LeafIter::new(art.get_root())
        .next()
        .expect("ART can't be empty")
        .get_public_key()
}

#[derive(Debug)]
enum ARTOperation {
    Init,
    LeaveGroup,
    DropGroup,
    AddMember {
        member_public_key: CortadoAffine,
    },
    KeyUpdate {
        old_public_key: CortadoAffine,
        new_public_key: CortadoAffine,
    },
    RemoveMember {
        member_public_key: CortadoAffine,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyedValidator {
    base_art: PrivateART<CortadoAffine>,
    base_stk: [u8; 32],
    current_art: PrivateART<CortadoAffine>,
    current_stk: [u8; 32],
    changes: Vec<BranchChanges<CortadoAffine>>,
    closed: bool,
    epoch: u64,
}
impl KeyedValidator {
    pub fn new(base_art: PrivateART<CortadoAffine>, base_stk: [u8; 32], epoch: u64) -> Self {
        Self {
            current_art: base_art.clone(),
            current_stk: base_stk,
            base_art,
            base_stk,
            changes: vec![],
            closed: true,
            epoch,
        }
    }

    // pub fn validate(&mut self, frame: &Frame) -> Result<(Vec<u8>, Option<ARTOperation>)> {
    //     let frame_epoch = frame.frame_tbs().epoch();

    //     if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
    //         return Err(Error::InvalidEpoch);
    //     }

    //     let is_next_epoch = frame_epoch == self.epoch + 1;

    //     // If frame don't have group operation then it is just payload frame that should have current epoch
    //     if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
    //         frame.verify_schnorr::<Sha3_256>(self.current_art.get_root().public_key)?;

    //         let protected_payload = decrypt(
    //             &self.current_stk,
    //             frame.frame_tbs().protected_payload(),
    //             &frame.frame_tbs().associated_data::<Sha3_256>()?,
    //         )?;

    //         return Ok((protected_payload, None));
    //     }

    //     let group_operation = frame
    //         .frame_tbs()
    //         .group_operation()
    //         .ok_or(Error::InvalidEpoch)?;

    //     match group_operation {
    //         GroupOperation::AddMember(changes) => {
    //             if !is_next_epoch && self.closed {
    //                 return Err(Error::InvalidEpoch);
    //             }

    //             let (verifier_artefacts, public_key) = if is_next_epoch {
    //                 (
    //                     self.current_art
    //                         .compute_artefacts_for_verification(changes)?,
    //                     group_owner_leaf_public_key(&self.current_art),
    //                 )
    //             } else {
    //                 (
    //                     self.base_art.compute_artefacts_for_verification(changes)?,
    //                     group_owner_leaf_public_key(&self.base_art),
    //                 )
    //             };

    //             frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
    //             self.apply_changes(changes, is_next_epoch)?;

    //             self.closed = true;

    //             Ok(())
    //         }
    //         GroupOperation::KeyUpdate(changes) => {
    //             if !is_next_epoch && self.closed {
    //                 return Err(Error::InvalidEpoch);
    //             }

    //             let (verifier_artefacts, public_key) = if is_next_epoch {
    //                 (
    //                     self.current_art
    //                         .compute_artefacts_for_verification(changes)?,
    //                     self.current_art.get_node(&changes.node_index)?.public_key,
    //                 )
    //             } else {
    //                 (
    //                     self.base_art.compute_artefacts_for_verification(changes)?,
    //                     self.base_art.get_node(&changes.node_index)?.public_key,
    //                 )
    //             };

    //             frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
    //             self.apply_changes(changes, is_next_epoch)?;

    //             self.closed = false;

    //             Ok(())
    //         }
    //         GroupOperation::RemoveMember(changes) => {
    //             if !is_next_epoch && self.closed {
    //                 return Err(Error::InvalidEpoch);
    //             }

    //             let (verifier_artefacts, public_key) = if is_next_epoch {
    //                 (
    //                     self.current_art
    //                         .compute_artefacts_for_verification(changes)?,
    //                     group_owner_leaf_public_key(&self.current_art),
    //                 )
    //             } else {
    //                 (
    //                     self.base_art.compute_artefacts_for_verification(changes)?,
    //                     group_owner_leaf_public_key(&self.base_art),
    //                 )
    //             };

    //             frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
    //             self.apply_changes(changes, is_next_epoch)?;

    //             self.closed = false;

    //             Ok(())
    //         }
    //         GroupOperation::Init(_) => {
    //             if frame_epoch != 0 {
    //                 return Err(Error::InvalidEpoch);
    //             }

    //             let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
    //             frame.verify_schnorr::<Sha3_256>(owner_public_key)
    //         }
    //         GroupOperation::LeaveGroup(node_index) => {
    //             if is_next_epoch {
    //                 return Err(Error::InvalidEpoch);
    //             }

    //             let public_key = self.current_art.get_node(node_index)?.public_key;
    //             frame.verify_schnorr::<Sha3_256>(public_key)
    //         }
    //         GroupOperation::DropGroup(_) => unimplemented!(),
    //     }
    // }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }

    fn apply_changes(
        &mut self,
        changes: &BranchChanges<CortadoAffine>,
        is_next_epoch: bool,
    ) -> Result<[u8; 32]> {
        if !is_next_epoch {
            // Derive stk for frame decryption
            let mut temp_art = self.base_art.clone();
            temp_art.update_private_art(changes)?;
            let temp_stk = derive_stage_key(&self.base_stk, temp_art.get_root_key()?.key)?;
            
            // Derive current stk and art
            let mut current_art = self.base_art.clone();
            current_art.merge_for_observer(&vec![self.changes.clone(), vec![changes.clone()]].concat())?;
            let current_stk = derive_stage_key(&self.base_stk, current_art.get_root_key()?.key)?;

            // Update validator state
            self.current_art = current_art;
            self.current_stk = current_stk;
            self.changes.push(changes.clone());

            return Ok(temp_stk);
        }

        // Derive current stk and art
        let mut current_art = self.current_art.clone();
        current_art.update_private_art(changes)?;
        let current_stk = derive_stage_key(&self.current_stk, current_art.get_root_key()?.key)?;

        // Advance base
        self.base_art = self.current_art.clone();
        self.base_stk = self.current_stk;

        // Advance current
        self.current_art = current_art;
        self.current_stk = current_stk;

        self.changes = vec![changes.clone()];

        Ok(self.current_stk)
    }
}
