use cortado::CortadoAffine;
use sha3::Sha3_256;
use zrt_art::{
    traits::{ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafIter, PrivateART, PublicART},
};
use serde::{Serialize, Deserialize};

use crate::{
    error::{Error, Result},
    models::frame::{Frame, GroupOperation},
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
    pub fn new(base: PublicART<CortadoAffine>, epoch: u64) -> Self {
        Self {
            current_art: base.clone(),
            base_art: base,
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

        let group_operation = frame.frame_tbs().group_operation().ok_or(Error::InvalidEpoch)?;

        match group_operation {
            GroupOperation::AddMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    (self.current_art.compute_artefacts_for_verification(changes)?, group_owner_leaf_public_key(&self.current_art))
                } else {
                    (self.base_art.compute_artefacts_for_verification(changes)?, group_owner_leaf_public_key(&self.base_art))
                };
                
                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;

                if is_next_epoch {
                    let base_art = self.current_art.clone();
                    let mut current_art = self.current_art.clone();
                    current_art.update_public_art(changes)?;

                    self.base_art = base_art;
                    self.current_art = current_art;

                    self.changes = vec![];
                } else {
                    self.current_art.merge(&vec![changes.clone()])?;
                }
                
                self.closed = true;
                self.changes.push(changes.clone());

                Ok(())
            },
            GroupOperation::KeyUpdate(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                let (verifier_artefacts, public_key) = if is_next_epoch {
                    (self.current_art.compute_artefacts_for_verification(changes)?, self.current_art.get_node(&changes.node_index)?.public_key)
                } else {
                    (self.base_art.compute_artefacts_for_verification(changes)?, self.base_art.get_node(&changes.node_index)?.public_key)
                };

                frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;

                if !is_next_epoch {
                    self.current_art.merge(&vec![changes.clone()])?;
                    
                }

                let base_art = self.current_art.clone();
                let mut current_art = self.current_art.clone();
                current_art.update_public_art(changes)?;

                self.base_art = base_art;
                self.current_art = current_art;
                self.closed = false;
                
                Ok(())
            },
            GroupOperation::RemoveMember(changes) => {
                if !is_next_epoch && self.closed {
                    return Err(Error::InvalidEpoch);
                }

                Ok(())
            },
            GroupOperation::Init(_) => Ok(()),
            GroupOperation::LeaveGroup(node_index) => {
                if is_next_epoch {
                    return Err(Error::InvalidEpoch);
                }

                let public_key = self.current_art.get_node(node_index)?.public_key;
                frame.verify_schnorr::<Sha3_256>(public_key)
            }
            GroupOperation::DropGroup(_) => Ok(())
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self).map_err(|e| e.into())
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        postcard::from_bytes(value).map_err(|e| e.into())
    }
}

fn group_owner_leaf_public_key(art: &PublicART<CortadoAffine>) -> CortadoAffine {
        LeafIter::new(art.get_root())
            .next()
            .expect("ART can't be empty")
            .get_public_key()
}

pub struct KeyedValidator {
    base_art: PrivateART<CortadoAffine>,
    base_stk: [u8; 32],
    current_art: PrivateART<CortadoAffine>,
    current_stk: [u8; 32],
    changes: Vec<BranchChanges<CortadoAffine>>,
    closed: bool,
    epoch: u64,
}
