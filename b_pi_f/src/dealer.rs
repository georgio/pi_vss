use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::{batch_decompress_ristretto_points, compute_d_powers_from_point_commitments},
};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity};

pub struct Dealer {
    pub t: usize,
    // [g1...gk]
    pub g: Vec<RistrettoPoint>,
    pub g0: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        g: Vec<RistrettoPoint>,
        g0: RistrettoPoint,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
    ) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(pks) => Ok(Self {
                t,
                public_keys: pks,
                secret: None,
                g: g.clone(),
                g0: g0.clone(),
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        x_pows: &Vec<Vec<Scalar>>,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Vec<Scalar>>, (Vec<CompressedRistretto>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let k = secrets.len();
        let (f_polynomials, f_evals) = self.generate_shares(x_pows, k, secrets);

        let mut c_buf: Vec<CompressedRistretto> = Vec::with_capacity(self.public_keys.len());

        let z = self.generate_proof(
            rng,
            hasher,
            buf,
            &mut c_buf,
            x_pows,
            k,
            &f_polynomials,
            &f_evals,
        );
        (f_evals, (c_buf, z))
    }

    pub fn generate_shares(
        &self,
        x_pows: &Vec<Vec<Scalar>>,
        k: usize,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Polynomial>, Vec<Vec<Scalar>>) {
        let f_polynomials = Polynomial::sample_n_set_f0(k, self.t, secrets).unwrap();

        let f_evals = Polynomial::evaluate_many_range_precomp(
            x_pows,
            &f_polynomials,
            1,
            self.public_keys.len(),
        );
        (f_polynomials, f_evals)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        c_buf: &mut Vec<CompressedRistretto>,
        x_pows: &Vec<Vec<Scalar>>,
        k: usize,
        f_polynomials: &Vec<Polynomial>,
        f_evals: &Vec<Vec<Scalar>>,
    ) -> Polynomial
    where
        R: CryptoRng,
    {
        let mut r = Polynomial::sample(self.t, rng);
        let r_evals = r.evaluate_range_precomp(x_pows, 1, self.public_keys.len());

        f_evals
            .par_iter()
            .zip(r_evals.par_iter())
            .map(|(fi, ri)| {
                (fi.par_iter()
                    .zip(self.g.par_iter())
                    .map(|(fi_k, gk)| fi_k * gk)
                    .reduce(|| RistrettoPoint::identity(), |acc, prod| acc + prod)
                    + self.g0 * ri)
                    .compress()
            })
            .collect_into_vec(c_buf);

        // [d, d^2, ..., d^k]
        let d_vals = compute_d_powers_from_point_commitments(hasher, buf, &c_buf, k);

        // z == r +=  d * f
        // if self.g1 == self.g0 * d {
        //     panic!("g1 == g0^d");
        // } else {
        r.compute_z(f_polynomials, &d_vals);
        r
        // }
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
