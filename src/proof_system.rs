use std::sync::Mutex;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use bulletproofs::PedersenGens;
use bulletproofs::r1cs::R1CSError;
use cortado::{self, CortadoAffine, Fr as ScalarField};
use curve25519_dalek::scalar::Scalar;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;
use zrt_art::types::{ProverArtefacts, VerifierArtefacts};
use zrt_zk::art::{ARTProof, art_prove, art_verify};

use once_cell::sync::OnceCell;

static PROOF_SYSTEM: OnceCell<ProofSystem> = OnceCell::new();

pub fn set_proof_system(ps: ProofSystem) -> Result<(), ProofSystem> {
    PROOF_SYSTEM.set(ps)
}

pub fn get_proof_system() -> &'static ProofSystem {
    PROOF_SYSTEM.get_or_init(|| ProofSystem::default())
}

pub struct ProofSystem {
    basis: PedersenBasis<
        ark_ec::short_weierstrass::Affine<cortado::Parameters>,
        ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>,
    >,
    rng: Mutex<StdRng>,
}

impl Default for ProofSystem {
    fn default() -> Self {
        let g_1 = CortadoAffine::generator();
        let h_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            g_1,
            h_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );

        let rng = StdRng::from_rng(thread_rng()).expect("Can't create rng from thread_rng");

        Self {
            basis,
            rng: Mutex::new(rng),
        }
    }
}

impl ProofSystem {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: Mutex::new(StdRng::from_seed(seed)),
            ..Self::default()
        }
    }

    pub fn prove(
        &self,
        artefacts: ProverArtefacts<CortadoAffine>,
        aux_secret_keys: &[ScalarField],
        associated_data: &[u8],
    ) -> Result<ARTProof, R1CSError> {
        let k = artefacts.co_path.len();

        let blinding_vector: Vec<Scalar> = {
            let mut rng = self.rng.lock().unwrap();
            (0..k + 1).map(|_| Scalar::random(&mut *rng)).collect()
        };

        let aux_public_keys = aux_secret_keys
            .iter()
            .map(|sk| (CortadoAffine::generator() * sk).into_affine())
            .collect::<Vec<_>>();

        art_prove(
            self.basis.clone(),
            associated_data,
            aux_public_keys,
            artefacts.path.clone(),
            artefacts.co_path.clone(),
            artefacts.secrets.clone(),
            aux_secret_keys.to_vec(),
            blinding_vector,
        )
    }

    pub fn verify(
        &self,
        artefacts: VerifierArtefacts<CortadoAffine>,
        aux_public_keys: &[CortadoAffine],
        associated_data: &[u8],
        proof: ARTProof,
    ) -> Result<(), R1CSError> {
        art_verify(
            self.basis.clone(),
            associated_data,
            aux_public_keys.to_vec(),
            artefacts.path.clone(),
            artefacts.co_path.clone(),
            proof,
        )
    }
}
