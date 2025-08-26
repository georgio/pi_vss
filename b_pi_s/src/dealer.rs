use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::{batch_decompress_ristretto_points, compute_d_powers_from_point_commitments},
};
use rand::{CryptoRng, RngCore};

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rayon::prelude::*;

pub struct Dealer {
    pub t: usize,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secrets: Option<Vec<Scalar>>,
}

impl Dealer {
    pub fn new(n: usize, t: usize, public_keys: &[CompressedRistretto]) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(pks) => Ok(Self {
                t,
                public_keys: pks,
                secrets: None,
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Vec<Scalar> {
        self.secrets.clone().unwrap()
    }

    pub fn deal_secrets<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        x_pows: &Vec<Vec<Scalar>>,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Vec<CompressedRistretto>>, (Scalar, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        // number of secrets to share
        let k = secrets.len();

        let (mut f_polynomials, f_evals) = self.generate_shares(&x_pows, k, secrets);

        let (d, z) = self.generate_proof(rng, hasher, buf, x_pows, k, &mut f_polynomials, &f_evals);

        (f_evals, (d, z))
    }

    pub fn generate_shares(
        &self,
        x_pows: &Vec<Vec<Scalar>>,
        k: usize,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Polynomial>, Vec<Vec<CompressedRistretto>>) {
        // This contains k * f_polynomial
        let f_polynomials = Polynomial::sample_n_set_f0(k, self.t, secrets).unwrap();
        // evals is vec[vec[k]; n]
        let f_evals = Polynomial::evaluate_many_range_precomp(
            x_pows,
            &f_polynomials,
            1,
            self.public_keys.len(),
        );

        let encrypted_shares = f_evals
            .par_iter()
            .zip(self.public_keys.par_iter())
            .map(|(fk, pub_key)| {
                fk.par_iter()
                    .map(|f_eval| (f_eval * pub_key).compress())
                    .collect()
            })
            .collect();

        (f_polynomials, encrypted_shares)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        x_pows: &Vec<Vec<Scalar>>,
        k: usize,
        f_polynomials: &Vec<Polynomial>,
        f_evals: &Vec<Vec<CompressedRistretto>>,
    ) -> (Scalar, Polynomial)
    where
        R: CryptoRng,
    {
        let mut r = Polynomial::sample(self.t, rng);
        let r_evals = r.evaluate_range_precomp(x_pows, 1, self.public_keys.len());

        let commitments: Vec<CompressedRistretto> = f_evals
            .clone()
            .into_par_iter()
            .flatten()
            .chain(
                r_evals
                    .par_iter()
                    .zip(self.public_keys.par_iter())
                    .map(|(r_eval, pub_key)| (r_eval * pub_key).compress()),
            )
            .collect();

        let d_vals = compute_d_powers_from_point_commitments(hasher, buf, &commitments, k);

        // z == r += ( ∑ d_j * f_j )
        r.compute_z(f_polynomials, &d_vals);

        (d_vals[0], r)
    }
}
