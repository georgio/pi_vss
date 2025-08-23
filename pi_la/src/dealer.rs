use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::batch_decompress_ristretto_points,
};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

use zeroize::Zeroize;

pub struct Dealer {
    pub t: usize,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
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
                secret: None,
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn deal_secret_v2<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secret: &Scalar,
    ) -> (Vec<Scalar>, (Vec<Vec<u8>>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let (f_polynomial, f_evals) = self.generate_shares(rng, secret);
        let (c_vals, z) = self.generate_proof(rng, hasher, buf, f_polynomial, &f_evals);

        (f_evals, (c_vals, z))
    }

    pub fn generate_shares<R>(&self, rng: &mut R, secret: &Scalar) -> (Polynomial, Vec<Scalar>)
    where
        R: CryptoRng,
    {
        let f_polynomial = Polynomial::sample_set_f0(self.t, rng, secret);
        let f_evals = f_polynomial.evaluate_range(1, self.public_keys.len());
        (f_polynomial, f_evals)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        mut f_polynomial: Polynomial,
        f_evals: &Vec<Scalar>,
    ) -> (Vec<Vec<u8>>, Polynomial)
    where
        R: CryptoRng,
    {
        let mut r = Polynomial::sample(self.t, rng);
        let r_evals = r.evaluate_range(1, self.public_keys.len());

        let c_vals: Vec<Vec<u8>> = f_evals
            .par_iter()
            .zip(r_evals.par_iter())
            .map_init(
                || (Hasher::new(), vec![0u8; 64]),
                |(l_hasher, l_buf), (fi, ri)| {
                    l_hasher.update(fi.as_bytes());

                    l_hasher.update(ri.as_bytes());
                    l_hasher.finalize_xof().fill(l_buf);
                    l_hasher.reset();

                    let out = l_buf.clone();
                    l_buf.zeroize();
                    out
                },
            )
            .collect();

        let flat_vec: Vec<u8> = c_vals.clone().into_iter().flatten().collect();

        hasher.update(&flat_vec);
        hasher.finalize_xof().fill(buf);

        let d = Scalar::from_bytes_mod_order_wide(buf);
        buf.zeroize();
        hasher.reset();

        f_polynomial.mul_sum(&d, &r);

        (c_vals, f_polynomial)
    }

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secret: &Scalar,
    ) -> (Vec<Scalar>, (Vec<[u8; 64]>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let (mut f, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        self.secret = Some(*secret);

        let (f_evals, r_evals) = f.evaluate_two_range(&r, 1, self.public_keys.len());

        let c_vals: Vec<[u8; 64]> = f_evals
            .par_iter()
            .zip(r_evals.par_iter())
            .map_init(
                || (Hasher::new(), [0u8; 64]),
                |(l_hasher, l_buf), (fi, ri)| {
                    l_hasher.update(fi.as_bytes());

                    l_hasher.update(ri.as_bytes());
                    l_hasher.finalize_xof().fill(l_buf);
                    l_hasher.reset();

                    let out = l_buf.clone();
                    l_buf.zeroize();
                    out
                },
            )
            .collect();

        let flat_vec: Vec<u8> = c_vals.clone().into_iter().flatten().collect();

        hasher.update(&flat_vec);
        hasher.finalize_xof().fill(buf);

        let d = Scalar::from_bytes_mod_order_wide(buf);
        buf.zeroize();
        hasher.reset();

        f.mul_sum(&d, &r);

        (f_evals, (c_vals, f))
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
