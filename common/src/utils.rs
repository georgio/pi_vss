use std::ops::Mul;

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rayon::prelude::*;

use crate::error::{Error, ErrorKind::PointDecompressionError};

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

pub fn compute_lagrange_bases(qualified_set: &Vec<usize>) -> Vec<Scalar> {
    qualified_set
        .par_iter()
        .map(|i| compute_lagrange_basis(*i, qualified_set))
        .collect()
}

pub fn compute_lagrange_basis(i: usize, qualified_set: &Vec<usize>) -> Scalar {
    let zq_i = Scalar::from(i as u64);

    qualified_set
        .par_iter()
        .map(|j| {
            if i == *j {
                Scalar::ONE
            } else {
                let zq_j = Scalar::from(*j as u64);
                zq_j * ((zq_j - zq_i).invert())
            }
        })
        .reduce(|| Scalar::ONE, Scalar::mul)
}

pub fn decompress_ristretto_point(
    compressed_point: CompressedRistretto,
) -> Result<RistrettoPoint, Error> {
    match compressed_point.decompress() {
        Some(decompressed_point) => Ok(decompressed_point),
        None => Err(Error::from_kind(PointDecompressionError(format!(
            "{compressed_point:?}",
        )))),
    }
}

pub fn batch_decompress_ristretto_points(
    compressed_points: &[CompressedRistretto],
) -> Result<Vec<RistrettoPoint>, Error> {
    compressed_points
        .par_iter()
        .map(|compressed_point| decompress_ristretto_point(*compressed_point))
        .collect()
}
