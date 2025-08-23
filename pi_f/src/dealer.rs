use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::{
        batch_decompress_ristretto_points, compute_d_from_hash_commitments,
        compute_d_from_point_commitments,
    },
};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

use zeroize::Zeroize;

pub struct Dealer {
    pub t: usize,
    pub g1: RistrettoPoint,
    pub g2: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        g1: RistrettoPoint,
        g2: RistrettoPoint,
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
                g1: g1.clone(),
                g2: g2.clone(),
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
        secret: &Scalar,
    ) -> (Vec<Scalar>, (Vec<CompressedRistretto>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let (f_polynomial, f_evals) = self.generate_shares(rng, x_pows, secret);

        let mut c_buf: Vec<CompressedRistretto> = Vec::with_capacity(self.public_keys.len());

        let z = self.generate_proof(rng, hasher, buf, &mut c_buf, x_pows, f_polynomial, &f_evals);

        (f_evals, (c_buf, z))

        // let (f, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        // self.secret = Some(*secret);

        // let (f_evals, r_evals) = f.evaluate_two_range(&r, 1, self.public_keys.len());

        // let c_vals: Vec<CompressedRistretto> = f_evals
        //     .par_iter()
        //     .zip(r_evals.par_iter())
        //     .map(|(fi, ri)| (self.g1 * fi + self.g2 * ri).compress())
        //     .collect();

        // let flat_vec: Vec<u8> = c_vals.iter().flat_map(|x| x.to_bytes()).collect();

        // hasher.update(&flat_vec);

        // hasher.finalize_xof().fill(buf);

        // let d = Scalar::from_bytes_mod_order_wide(buf);
        // buf.zeroize();
        // hasher.reset();

        // let mut z = f.clone();
        // z.mul_sum(&d, &r);

        // (f_evals, (c_vals, z))
    }

    pub fn generate_shares<R>(
        &self,
        rng: &mut R,
        x_pows: &Vec<Vec<Scalar>>,
        secret: &Scalar,
    ) -> (Polynomial, Vec<Scalar>)
    where
        R: CryptoRng,
    {
        let f_polynomial = Polynomial::sample_set_f0(self.t, rng, secret);
        let f_evals = f_polynomial.evaluate_range_precomp(x_pows, 1, self.public_keys.len());
        (f_polynomial, f_evals)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        c_buf: &mut Vec<CompressedRistretto>,
        x_pows: &Vec<Vec<Scalar>>,
        f_polynomial: Polynomial,
        f_evals: &Vec<Scalar>,
    ) -> Polynomial
    where
        R: CryptoRng,
    {
        let mut r = Polynomial::sample(self.t, rng);
        let r_evals = r.evaluate_range_precomp(x_pows, 1, self.public_keys.len());

        f_evals
            .par_iter()
            .zip(r_evals.par_iter())
            .map(|(fi, ri)| (self.g1 * fi + self.g2 * ri).compress())
            .collect_into_vec(c_buf);

        let d = compute_d_from_point_commitments(hasher, buf, &c_buf);

        // z == r +=  d * f
        r.compute_z(&[f_polynomial], &[d]);

        r
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
