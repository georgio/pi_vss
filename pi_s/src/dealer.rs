use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
};

use blake3::Hasher;
use common::utils::batch_decompress_ristretto_points;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use zeroize::Zeroize;

pub struct Dealer {
    t: usize,
    public_keys: Vec<RistrettoPoint>,
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
                public_keys: pks.par_iter().map(|pk| *pk).collect(),
                secret: None,
            }),
            Err(x) => Err(x),
        }
    }

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secret: &Scalar,
    ) -> (Vec<CompressedRistretto>, (Scalar, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        let (mut z, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        self.secret = Some(*secret);

        let (encrypted_shares, r_vals) = z.evaluate_multiply_two(&r, &self.public_keys);
        encrypted_shares.iter().chain(r_vals.iter()).for_each(|x| {
            hasher.update(x.as_bytes());
        });

        hasher.finalize_xof().fill(buf);

        let d = Scalar::from_bytes_mod_order_wide(buf);

        hasher.reset();
        buf.zeroize();

        z.mul_sum(&d, &r);

        (encrypted_shares, (d, z))
    }
}
