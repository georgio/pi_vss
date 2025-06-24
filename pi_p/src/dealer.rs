use crate::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::batch_decompress_ristretto_points,
};
use rayon::prelude::*;

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand_chacha::rand_core::CryptoRngCore;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator};
use zeroize::Zeroize;

pub struct Dealer {
    pub t: usize,
    pub g1: RistrettoPoint,
    pub g2: RistrettoPoint,
    pub g3: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        g1: RistrettoPoint,
        g2: RistrettoPoint,
        g3: RistrettoPoint,
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
                g3: g3.clone(),
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
        secret: &Scalar,
    ) -> (
        (Vec<Scalar>, Vec<Scalar>),
        (Vec<CompressedRistretto>, Polynomial),
    )
    where
        R: CryptoRngCore + ?Sized,
    {
        let (f, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        self.secret = Some(*secret);

        // Step 3
        let mut g: Vec<Scalar> = vec![Scalar::ZERO; self.public_keys.len()];
        g.iter_mut().for_each(|g_val| *g_val = Scalar::random(rng));

        let (f_evals, r_evals) = f.evaluate_two_range(&r, 1, self.public_keys.len());

        let c_vals: Vec<CompressedRistretto> = f_evals
            .par_iter()
            .zip(r_evals.par_iter().zip(g.par_iter()))
            .map(|(fi, (ri, gi))| (self.g1 * fi + self.g2 * ri + self.g3 * gi).compress())
            .collect();

        let flat_vec: Vec<u8> = c_vals.iter().flat_map(|x| x.to_bytes()).collect();

        hasher.update(&flat_vec);

        hasher.finalize_xof().fill(buf);

        let d = Scalar::from_bytes_mod_order_wide(buf);
        buf.zeroize();
        hasher.reset();

        if self.g1 == self.g2 * d {
            panic!("g1 == g2^d");
        } else {
            let mut z = f.clone();
            z.mul_sum(&d, &r);

            ((f_evals, g), (c_vals, z))
        }
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
