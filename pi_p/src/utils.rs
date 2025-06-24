use blake3::Hasher;
use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
};
use curve25519_dalek::{
    Scalar,
    ristretto::{CompressedRistretto, RistrettoPoint},
};
use rayon::prelude::*;
use zeroize::Zeroize;

pub fn precompute_lambda(n: usize, t: usize) -> Vec<Scalar> {
    (1..=n)
        .into_par_iter()
        .map(|i| {
            let zq_i = Scalar::from(i as u64);
            let mut lambda_i = Scalar::ONE;
            for j in 1..=(t + 1) {
                if j != i {
                    let zq_j = Scalar::from(j as u64);

                    lambda_i *= zq_j * ((zq_j - zq_i).invert());
                }
            }
            lambda_i
        })
        .collect()
}

pub fn verify_encrypted_shares_standalone(
    encrypted_shares: &(Vec<CompressedRistretto>, Vec<RistrettoPoint>),
    public_keys: &Vec<RistrettoPoint>,
    proof: (&Scalar, &Polynomial),
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
) -> Result<bool, Error> {
    if encrypted_shares.0.len() == encrypted_shares.1.len() {
        if public_keys.len() == encrypted_shares.0.len() {
            let (d, z) = (proof.0, proof.1);
            let shares: Vec<CompressedRistretto> = z
                .evaluate_multiply(public_keys, 1)
                .1
                .par_iter()
                .zip(encrypted_shares.1.par_iter())
                .map(|(x, enc_share)| (x - (enc_share * d)).compress())
                .collect();

            let flat_vec: Vec<u8> = encrypted_shares
                .0
                .iter()
                .chain(shares.iter())
                .flat_map(|x| x.to_bytes())
                .collect();

            hasher.update(&flat_vec);

            hasher.finalize_xof().fill(buf);

            let reconstructed_d = Scalar::from_bytes_mod_order_wide(buf);

            buf.zeroize();
            hasher.reset();
            Ok(*d == reconstructed_d)
        } else {
            Err(CountMismatch(
                public_keys.len(),
                "public_keys",
                encrypted_shares.0.len(),
                "encrypted_shares",
            )
            .into())
        }
    } else {
        Err(CountMismatch(
            encrypted_shares.0.len(),
            "encrypted_shares.0",
            encrypted_shares.1.len(),
            "encrypted_shares.1",
        )
        .into())
    }
}
