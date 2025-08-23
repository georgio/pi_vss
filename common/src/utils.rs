use std::ops::Mul;

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rayon::prelude::*;
use zeroize::Zeroize;

use crate::error::{Error, ErrorKind::PointDecompressionError};

pub fn pointwise_op_in_place(
    op: fn(Scalar, Scalar) -> Scalar,
    a: &mut Vec<Scalar>,
    b: &Vec<Scalar>,
) {
    a.par_iter_mut().zip(b.par_iter()).for_each(|(a_i, b_i)| {
        *a_i = op(*a_i, *b_i);
    });
}

pub fn compute_d_from_hash_commitments(
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
    commitments: &[[u8; 64]],
) -> Scalar {
    commitments.iter().for_each(|c| {
        hasher.update(c);
    });

    hasher.finalize_xof().fill(buf);
    hasher.reset();

    let d = Scalar::from_bytes_mod_order_wide(buf);
    buf.zeroize();
    d
}

pub fn compute_d_from_point_commitments(
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
    commitments: &[CompressedRistretto],
) -> Scalar {
    commitments.iter().for_each(|c| {
        hasher.update(c.as_bytes());
    });

    hasher.finalize_xof().fill(buf);
    hasher.reset();

    let d = Scalar::from_bytes_mod_order_wide(buf);
    buf.zeroize();
    d
}

pub fn compute_d_powers_from_hash_commitments(
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
    commitments: &[[u8; 64]],
    k: usize,
) -> Vec<Scalar> {
    let d = compute_d_from_hash_commitments(hasher, buf, commitments);

    let mut d_vals: Vec<Scalar> = Vec::with_capacity(k);
    // [d^1,
    d_vals.push(d);

    // d^2, d^3, ... d^k]
    for i in 1..k {
        d_vals.push(d_vals[i - 1] * d);
    }
    //
    d_vals
}

pub fn compute_d_powers_from_point_commitments(
    hasher: &mut Hasher,
    buf: &mut [u8; 64],
    commitments: &[CompressedRistretto],
    k: usize,
) -> Vec<Scalar> {
    let d = compute_d_from_point_commitments(hasher, buf, commitments);

    let mut d_vals: Vec<Scalar> = Vec::with_capacity(k);
    // [d^1,
    d_vals.push(d);

    // d^2, d^3, ... d^k]
    for i in 1..k {
        d_vals.push(d_vals[i - 1] * d);
    }
    //
    d_vals
}

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
