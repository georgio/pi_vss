use crate::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::batch_decompress_ristretto_points,
};

use blake3::Hasher;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroize;

pub struct Dealer {
    pub t: usize,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
        pk0: &RistrettoPoint,
    ) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(mut pks) => {
                pks.insert(0, *pk0);
                Ok(Self {
                    t,
                    public_keys: pks,
                    secret: None,
                })
            }
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
    ) -> (Vec<CompressedRistretto>, (Scalar, Polynomial))
    where
        R: CryptoRngCore + ?Sized,
    {
        let (mut z, r) = Polynomial::sample_two_set_f0(self.t, secret, rng);
        self.secret = Some(*secret);

        let (encrypted_shares, r_vals) = z.evaluate_multiply_two(&r, &self.public_keys);

        encrypted_shares.iter().chain(r_vals.iter()).for_each(|x| {
            hasher.update(x.as_bytes());
        });

        hasher.finalize_xof().fill(buf);

        let d = Scalar::from_bytes_mod_order_wide(buf);

        buf.zeroize();
        hasher.reset();

        z.mul_sum(&d, &r);

        (encrypted_shares, (d, z))
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
