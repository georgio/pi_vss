use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub fn random_scalar<R>(rng: &mut R) -> Scalar
where
    R: CryptoRng + RngCore,
{
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
    bytes.zeroize();
    scalar
}

pub fn random_point<R>(rng: &mut R) -> RistrettoPoint
where
    R: CryptoRng + RngCore,
{
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let point = RistrettoPoint::from_uniform_bytes(&bytes);
    bytes.zeroize();
    point
}
