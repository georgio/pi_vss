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

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secret: &Scalar,
    ) -> (Vec<Scalar>, (Vec<Vec<u8>>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let (f, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        self.secret = Some(*secret);

        let (f_evals, r_evals) = f.evaluate_two_range(&r, 1, self.public_keys.len());

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

        let mut z = f.clone();
        z.mul_sum(&d, &r);

        (f_evals, (c_vals, z))
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
