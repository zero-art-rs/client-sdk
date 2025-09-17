use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng, thread_rng};
use cortado::{self, CortadoAffine, Fr as ScalarField};

pub struct SecretsFactory {
    rng: StdRng,
}

impl Default for SecretsFactory {
    fn default() -> Self {
        Self {
            rng: StdRng::from_rng(thread_rng()).expect("Can't create rng from thread_rng"),
        }
    }
}

impl SecretsFactory {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            rng: StdRng::from_seed(seed),
        }
    }

    pub fn generate_secret(&mut self) -> ScalarField {
        ScalarField::rand(&mut self.rng)
    }

    pub fn generate_secret_with_public_key(&mut self) -> (CortadoAffine, ScalarField) {
        let secret_key = self.generate_secret();
        let public_key = (CortadoAffine::generator() * secret_key).into_affine();
        (public_key, secret_key)
    }
}
