use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zrt_art::types::{BranchChanges, PrivateART};

use crate::{bounded_map::BoundedMap, core::{traits::KeyedValidator, types::{ChangesID, StageKey}}};
use cortado::{self, CortadoAffine, Fr as ScalarField};


#[derive(Debug, Serialize, Deserialize, Clone)]
struct Participant {
    id: ChangesID,
    branch: BranchChanges<CortadoAffine>,
    art: PrivateART<CortadoAffine>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinearKeyedValidator {
    base_art: PrivateART<CortadoAffine>,
    base_stk: StageKey,

    upstream_art: PrivateART<CortadoAffine>,
    upstream_stk: StageKey,

    changes: HashMap<ChangesID, BranchChanges<CortadoAffine>>,

    epoch: u64,

    participant: Option<Participant>,
    participation_leafs: BoundedMap<ChangesID, ScalarField>,
}

// impl KeyedValidator for LinearKeyedValidator {

// }

// impl LinearKeyedValidator {
//     pub fn new(base_art: PrivateART<CortadoAffine>, base_stk: StageKey, epoch: u64) -> Self {
//         Self {
//             upstream_art: base_art.clone(),
//             upstream_stk: base_stk,
//             base_art,
//             base_stk,
//             changes: HashMap::new(),
//             epoch,
//             participant: None,
//             participation_leafs: BoundedMap::with_capacity(8),
//         }
//     }

//     pub fn validate(
//         &mut self,
//         frame: &Frame,
//     ) -> Result<(
//         Option<ARTOperation>,
//         impl Fn(&[u8], &[u8]) -> Result<Vec<u8>> + 'static,
//     )> {
//         let frame_epoch = frame.frame_tbs().epoch();

//         if frame_epoch != self.epoch && frame_epoch != self.epoch + 1 {
//             return Err(Error::InvalidEpoch);
//         }

//         let is_next_epoch = frame_epoch == self.epoch + 1;

//         // If frame don't have group operation then it is just payload frame that should have current epoch
//         if frame.frame_tbs().group_operation().is_none() && !is_next_epoch {
//             frame.verify_schnorr::<Sha3_256>(self.upstream_art.get_root().get_public_key())?;
//             return Ok((None, decrypt_factory(self.upstream_stk)));
//         }

//         if matches!(
//             frame.frame_tbs().group_operation(),
//             Some(GroupOperation::Init(_))
//         ) && frame_epoch != 0
//         {
//             return Err(Error::InvalidEpoch);
//         }

//         let group_operation = frame
//             .frame_tbs()
//             .group_operation()
//             .ok_or(Error::InvalidEpoch)?;

//         match group_operation {
//             GroupOperation::AddMember(changes) => {
//                 println!("IsNextEpoch: {}", is_next_epoch);

//                 if !is_next_epoch {
//                     return Err(Error::InvalidEpoch);
//                 }

//                 let (verifier_artefacts, public_key) = if is_next_epoch {
//                     let verifier_artefacts = self
//                         .upstream_art
//                         .compute_artefacts_for_verification(changes)?;
//                     let public_key = group_owner_leaf_public_key(&self.upstream_art);
//                     (verifier_artefacts, public_key)
//                 } else {
//                     let verifier_artefacts =
//                         self.base_art.compute_artefacts_for_verification(changes)?;
//                     let public_key = group_owner_leaf_public_key(&self.base_art);
//                     (verifier_artefacts, public_key)
//                 };

//                 frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
//                 let operation = ARTOperation::AddMember {
//                     member_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
//                 };

//                 Ok((
//                     Some(operation),
//                     decrypt_factory(self.apply_changes(changes)?),
//                 ))
//             }
//             GroupOperation::KeyUpdate(changes) => {
//                 let (verifier_artefacts, public_key) = if is_next_epoch {
//                     let verifier_artefacts = self
//                         .upstream_art
//                         .compute_artefacts_for_verification(changes)?;
//                     let public_key = self
//                         .upstream_art
//                         .get_node(&changes.node_index)?
//                         .get_public_key();
//                     (verifier_artefacts, public_key)
//                 } else {
//                     let verifier_artefacts =
//                         self.base_art.compute_artefacts_for_verification(changes)?;
//                     let public_key = self
//                         .base_art
//                         .get_node(&changes.node_index)?
//                         .get_public_key();
//                     (verifier_artefacts, public_key)
//                 };

//                 frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
//                 let operation = ARTOperation::KeyUpdate {
//                     old_public_key: public_key,
//                     new_public_key: *changes.public_keys.last().ok_or(Error::InvalidInput)?,
//                 };

//                 let stage_key = if is_next_epoch {
//                     self.apply_changes(changes)?
//                 } else {
//                     self.merge_changes(changes)?
//                 };

//                 Ok((Some(operation), decrypt_factory(stage_key)))
//             }
//             GroupOperation::RemoveMember(changes) => {
//                 if self.upstream_art.node_index == changes.node_index {
//                     return Err(Error::UserRemovedFromGroup);
//                 }

//                 let (verifier_artefacts, public_key) = if is_next_epoch {
//                     let verifier_artefacts = self
//                         .upstream_art
//                         .compute_artefacts_for_verification(changes)?;
//                     let public_key = if LeafStatus::Active
//                         != self
//                             .upstream_art
//                             .get_node(&changes.node_index)?
//                             .get_status()
//                             .ok_or(Error::InvalidInput)?
//                     {
//                         (CortadoAffine::generator() * self.upstream_art.get_root_key()?.key)
//                             .into_affine()
//                     } else {
//                         group_owner_leaf_public_key(&self.upstream_art)
//                     };
//                     (verifier_artefacts, public_key)
//                 } else {
//                     let verifier_artefacts =
//                         self.base_art.compute_artefacts_for_verification(changes)?;
//                     let public_key = if LeafStatus::Active
//                         != self
//                             .base_art
//                             .get_node(&changes.node_index)?
//                             .get_status()
//                             .ok_or(Error::InvalidInput)?
//                     {
//                         (CortadoAffine::generator() * self.base_art.get_root_key()?.key)
//                             .into_affine()
//                     } else {
//                         group_owner_leaf_public_key(&self.base_art)
//                     };
//                     (verifier_artefacts, public_key)
//                 };

//                 frame.verify_art::<Sha3_256>(verifier_artefacts, public_key)?;
//                 let operation = ARTOperation::RemoveMember {
//                     member_public_key: public_key,
//                 };

//                 let stage_key = if is_next_epoch {
//                     self.apply_changes(changes)?
//                 } else {
//                     self.merge_changes(changes)?
//                 };

//                 Ok((Some(operation), decrypt_factory(stage_key)))
//             }
//             GroupOperation::Init(_) => {
//                 if frame_epoch != 0 {
//                     return Err(Error::InvalidEpoch);
//                 }

//                 let owner_public_key: CortadoAffine = deserialize(frame.frame_tbs().nonce())?;
//                 frame.verify_schnorr::<Sha3_256>(owner_public_key)?;
//                 Ok((Some(ARTOperation::Init), decrypt_factory(self.upstream_stk)))
//             }
//             GroupOperation::LeaveGroup(node_index) => {
//                 if is_next_epoch {
//                     return Err(Error::InvalidEpoch);
//                 }

//                 let public_key = self.upstream_art.get_node(node_index)?.get_public_key();
//                 frame.verify_schnorr::<Sha3_256>(public_key)?;
//                 Ok((
//                     Some(ARTOperation::LeaveGroup),
//                     decrypt_factory(self.upstream_stk),
//                 ))
//             }
//             GroupOperation::DropGroup(_) => unimplemented!(),
//         }
//     }

//     pub fn serialize(&self) -> Result<Vec<u8>> {
//         postcard::to_allocvec(&self).map_err(|e| e.into())
//     }

//     pub fn deserialize(value: &[u8]) -> Result<Self> {
//         postcard::from_bytes(value).map_err(|e| e.into())
//     }

//     fn merge_changes_and_participate(
//         &mut self,
//         changes_id: ChangesID,
//         changes: BranchChanges<CortadoAffine>,
//         secret_key: ScalarField,
//     ) -> Result<StageKey> {
//         let mut upstream_art = self.base_art.clone();
//         let (tree_key, _, _) = upstream_art.update_key(&secret_key)?;
//         let branch_stk = derive_stage_key(&self.base_stk, tree_key.key)?;

//         let participant = Participant {
//             id: changes_id,
//             branch: changes.clone(),
//             art: upstream_art.clone(),
//         };

//         upstream_art.merge_for_participant(
//             changes.clone(),
//             &self
//                 .changes
//                 .values()
//                 .cloned()
//                 .collect::<Vec<BranchChanges<CortadoAffine>>>(),
//             self.base_art.clone(),
//         )?;
//         let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;

//         self.upstream_art = upstream_art;
//         self.upstream_stk = upstream_stk;

//         self.participant = Some(participant);
//         self.changes.insert(changes_id, changes);

//         Ok(branch_stk)
//     }

//     fn merge_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
//         // Should never panic
//         let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
//             .try_into()
//             .unwrap();

//         if self.changes.contains_key(&changes_id) {
//             return Err(Error::InvalidInput);
//         }

//         if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
//             return self.merge_changes_and_participate(changes_id, changes.clone(), secret_key);
//         }

//         // Derive branch stk to decrypt payload
//         let mut branch_art = self.base_art.clone();
//         branch_art.update_private_art(changes)?;
//         let branch_stk = derive_stage_key(&self.base_stk, branch_art.get_root_key()?.key)?;

//         let upstream_art = if let Some(participant) = &self.participant {
//             // Derive upstream art and stk to advance epoch and encrypt new payloads
//             let mut upstream_art = participant.art.clone();
//             let target_changes = self
//                 .changes
//                 .iter()
//                 .filter(|&(&id, _)| (id != participant.id))
//                 .map(|(_, c)| c.clone())
//                 .chain(std::iter::once(changes.clone()))
//                 .collect::<Vec<_>>();

//             upstream_art.merge_for_participant(
//                 participant.branch.clone(),
//                 &target_changes,
//                 self.base_art.clone(),
//             )?;

//             upstream_art
//         } else {
//             let mut upstream_art = self.base_art.clone();
//             upstream_art
//                 .merge_for_observer(&self.changes.clone().into_values().collect::<Vec<_>>())?;

//             upstream_art
//         };

//         let upstream_stk = derive_stage_key(&self.base_stk, upstream_art.get_root_key()?.key)?;

//         self.upstream_art = upstream_art;
//         self.upstream_stk = upstream_stk;

//         self.changes.insert(changes_id, changes.clone());

//         Ok(branch_stk)
//     }

//     fn apply_changes(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<StageKey> {
//         // Should never panic
//         let changes_id: ChangesID = Sha3_256::digest(changes.serialize()?).to_vec()[..8]
//             .try_into()
//             .unwrap();

//         if self.changes.contains_key(&changes_id) {
//             return Err(Error::InvalidInput);
//         }

//         // Derive current stk and art
//         let mut upstream_art = self.upstream_art.clone();

//         let participant = if let Some(&secret_key) = self.participation_leafs.get(&changes_id) {
//             upstream_art.update_key(&secret_key)?;

//             let participant = Participant {
//                 id: changes_id,
//                 branch: changes.clone(),
//                 art: upstream_art.clone(),
//             };
//             Some(participant)
//         } else {
//             upstream_art.update_private_art(changes)?;
//             None
//         };

//         let upstream_stk = derive_stage_key(&self.upstream_stk, upstream_art.get_root_key()?.key)?;

//         // Advance base
//         self.base_art = self.upstream_art.clone();
//         self.base_stk = self.upstream_stk;

//         // Advance current
//         self.upstream_art = upstream_art;
//         self.upstream_stk = upstream_stk;

//         self.participant = participant;
//         self.changes = HashMap::new();
//         self.changes.insert(changes_id, changes.clone());
//         self.epoch += 1;

//         Ok(self.upstream_stk)
//     }

//     pub fn add_member(
//         &self,
//         secret_key: ScalarField,
//     ) -> Result<(
//         BranchChanges<CortadoAffine>,
//         StageKey,
//         impl Fn(&[u8]) -> Result<ARTProof> + 'static,
//     )> {
//         if self.public_key() != group_owner_leaf_public_key(&self.upstream_art) {
//             return Err(Error::Forbidden);
//         }

//         let mut temporary_art = self.upstream_art.clone();
//         let (tree_key, changes, prover_artefacts) =
//             temporary_art.append_or_replace_node(&secret_key)?;
//         let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

//         let current_secret_key = self.upstream_art.secret_key;
//         let prove = move |associated_data: &[u8]| {
//             get_proof_system()
//                 .prove(
//                     prover_artefacts.clone(),
//                     &[current_secret_key],
//                     associated_data,
//                 )
//                 .map_err(|e| e.into())
//         };

//         Ok((changes, stk, prove))
//     }

//     pub fn remove_member(
//         &self,
//         public_key: &CortadoAffine,
//         vanishing_secret_key: ScalarField,
//     ) -> Result<(
//         BranchChanges<CortadoAffine>,
//         StageKey,
//         impl Fn(&[u8]) -> Result<ARTProof> + 'static,
//     )> {
//         if self.public_key() != group_owner_leaf_public_key(&self.upstream_art) {
//             return Err(Error::Forbidden);
//         }

//         let mut temporary_art = self.upstream_art.clone();
//         let (tree_key, changes, prover_artefacts) = temporary_art.make_blank(
//             &self.upstream_art.get_path_to_leaf(public_key)?,
//             &vanishing_secret_key,
//         )?;
//         let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

//         let current_secret_key = self.upstream_art.secret_key;
//         let prove = move |associated_data: &[u8]| {
//             get_proof_system()
//                 .prove(
//                     prover_artefacts.clone(),
//                     &[current_secret_key],
//                     associated_data,
//                 )
//                 .map_err(|e| e.into())
//         };

//         Ok((changes, stage_key, prove))
//     }

//     pub fn update_key(
//         &mut self,
//     ) -> Result<(
//         BranchChanges<CortadoAffine>,
//         StageKey,
//         impl Fn(&[u8]) -> Result<ARTProof> + 'static,
//     )> {
//         let secret_key = derive_leaf_key(&self.upstream_stk, self.upstream_art.secret_key)?;

//         let mut temporary_art = self.upstream_art.clone();
//         let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
//         let stage_key = derive_stage_key(&self.upstream_stk, tree_key.key)?;

//         let current_secret_key = self.upstream_art.secret_key;
//         let prove = move |associated_data: &[u8]| {
//             get_proof_system()
//                 .prove(
//                     prover_artefacts.clone(),
//                     &[current_secret_key],
//                     associated_data,
//                 )
//                 .map_err(|e| e.into())
//         };

//         let changes_id = compute_changes_id(&changes)?;
//         self.participation_leafs.insert(changes_id, secret_key);

//         Ok((changes, stage_key, prove))
//     }

//     pub fn update_key_with(
//         &mut self,
//         secret_key: ScalarField,
//     ) -> Result<(
//         BranchChanges<CortadoAffine>,
//         impl Fn(&[u8], &[u8]) -> Result<Vec<u8>> + 'static,
//         impl Fn(&[u8]) -> Result<ARTProof> + 'static,
//     )> {
//         let mut temporary_art = self.upstream_art.clone();
//         let (tree_key, changes, prover_artefacts) = temporary_art.update_key(&secret_key)?;
//         let stk = derive_stage_key(&self.upstream_stk, tree_key.key)?;

//         let current_secret_key = self.upstream_art.secret_key;
//         let prove = move |associated_data: &[u8]| {
//             get_proof_system()
//                 .prove(
//                     prover_artefacts.clone(),
//                     &[current_secret_key],
//                     associated_data,
//                 )
//                 .map_err(|e| e.into())
//         };

//         let encrypt = move |plaintext: &[u8], associated_data: &[u8]| {
//             encrypt(&stk, plaintext, associated_data)
//         };

//         let changes_id = compute_changes_id(&changes)?;
//         self.participation_leafs.insert(changes_id, secret_key);

//         Ok((changes, encrypt, prove))
//     }

//     pub fn public_key(&self) -> CortadoAffine {
//         (CortadoAffine::generator() * self.upstream_art.secret_key).into_affine()
//     }

//     pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
//         encrypt(&self.upstream_stk, plaintext, associated_data)
//     }

//     pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
//         decrypt(&self.upstream_stk, ciphertext, associated_data)
//     }

//     pub fn epoch(&self) -> u64 {
//         self.epoch
//     }

//     pub fn is_participant(&self) -> bool {
//         self.participant.is_some()
//     }
// }

