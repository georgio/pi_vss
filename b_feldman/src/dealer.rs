use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    secret_sharing::generate_shares_batched,
    utils::batch_decompress_ristretto_points,
};

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity};

use rayon::prelude::*;

pub struct Dealer {
    pub t: usize,
    // [g1...gk]
    pub g: Vec<RistrettoPoint>,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        g: Vec<RistrettoPoint>,
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
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn deal_secret(
        &mut self,
        x_pows: &Vec<Vec<Scalar>>,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Vec<Scalar>>, Vec<CompressedRistretto>) {
        let (f_polynomials, f_evals) =
            generate_shares_batched(self.public_keys.len(), self.t, x_pows, secrets);

        let mut c_buf: Vec<CompressedRistretto> = vec![CompressedRistretto::identity(); self.t + 1];

        self.generate_proof(&mut c_buf, &f_polynomials);
        (f_evals, c_buf)
    }

    pub fn generate_proof(
        &self,
        c_buf: &mut Vec<CompressedRistretto>,
        f_polynomials: &Vec<Polynomial>,
    ) {
        c_buf.par_iter_mut().enumerate().for_each(|(t, c)| {
            *c = f_polynomials
                .par_iter()
                .zip(self.g.par_iter())
                .map(|(fk, gk)| gk * fk.coef_at_unchecked(t))
                .reduce(|| RistrettoPoint::identity(), |acc, prod| acc + prod)
                .compress()
        });
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
