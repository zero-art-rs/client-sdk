use ark_ec::AffineRepr;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use zrt_art::{
    traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
    types::{BranchChanges, LeafIter, PrivateART, ProverArtefacts, PublicART, VerifierArtefacts},
};

use crate::{
    error::{Error, Result},
    models::group_info::GroupInfo,
    utils::{decrypt, encrypt},
};

#[derive(Debug, Clone)]
pub struct GroupState {
    pub art: PrivateART<CortadoAffine>,
    pub stk: [u8; 32],
    pub epoch: u64,
    pub group_info: GroupInfo,
    pub is_last_sender: bool,
}

impl GroupState {
    pub fn into_parts(
        self,
    ) -> (
        ScalarField,
        PublicART<CortadoAffine>,
        [u8; 32],
        u64,
        GroupInfo,
        bool,
    ) {
        (
            self.art.secret_key,
            PublicART {
                root: self.art.root,
                generator: CortadoAffine::generator(),
            },
            self.stk,
            self.epoch,
            self.group_info,
            self.is_last_sender,
        )
    }

    pub fn to_parts(
        &self,
    ) -> (
        ScalarField,
        PublicART<CortadoAffine>,
        [u8; 32],
        u64,
        GroupInfo,
        bool,
    ) {
        (
            self.art.secret_key,
            PublicART {
                root: self.art.root.clone(),
                generator: CortadoAffine::generator(),
            },
            self.stk,
            self.epoch,
            self.group_info.clone(),
            self.is_last_sender,
        )
    }

    pub fn from_parts(
        leaf_secret: ScalarField,
        art: PublicART<CortadoAffine>,
        stk: [u8; 32],
        epoch: u64,
        group_info: GroupInfo,
        is_last_sender: bool,
    ) -> Result<Self> {
        Ok(Self {
            art: PrivateART::from_public_art_and_secret(art, leaf_secret)?,
            stk,
            epoch,
            group_info,
            is_last_sender,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        encrypt(&self.stk, plaintext, associated_data)
    }

    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        decrypt(&self.stk, ciphertext, associated_data)
    }

    pub fn update_art(&mut self, changes: &BranchChanges<CortadoAffine>) -> Result<()> {
        self.art.update_private_art(changes)?;
        self.advance_epoch()?;
        Ok(())
    }

    pub fn append_leaf(
        &mut self,
        leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.append_or_replace_node(leaf_secret)?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    pub fn update_key(
        &mut self,
        leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.update_key(leaf_secret)?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    pub fn make_blank(
        &mut self,
        leaf_public_key: &CortadoAffine,
        temporary_leaf_secret: &ScalarField,
    ) -> Result<(BranchChanges<CortadoAffine>, ProverArtefacts<CortadoAffine>)> {
        let (_, changes, prover_artefacts) = self.art.make_blank(
            &self.art.get_path_to_leaf(leaf_public_key)?,
            temporary_leaf_secret,
        )?;
        self.advance_epoch()?;
        Ok((changes, prover_artefacts))
    }

    fn advance_epoch(&mut self) -> Result<()> {
        let tk = self.art.get_root_key()?;
        // Recompute stk: stk(i+1) = HKDF( "stage-key-derivation", stk(i) || tk(i+1) )
        let stk = crate::utils::derive_stage_key(&self.stk, tk.key)?;
        self.stk = stk;

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }

    pub fn verifier_artefacts(
        &self,
        changes: &BranchChanges<CortadoAffine>,
    ) -> Result<VerifierArtefacts<CortadoAffine>> {
        Ok(self.art.compute_artefacts_for_verification(changes)?)
    }

    pub fn owner_public_key(&self) -> Result<CortadoAffine> {
        Ok(self
            .iter_leafs()
            .next()
            .ok_or(Error::InvalidInput)?
            .get_public_key())
    }

    pub fn iter_leafs(&self) -> LeafIter<'_, CortadoAffine> {
        LeafIter::new(self.art.get_root())
    }
}
