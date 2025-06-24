use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

use crate::random::random_scalar;

#[derive(Clone)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub fn coef_at(&self, index: usize) -> Option<Scalar> {
        if index < self.coefficients.len() - 1 {
            Some(self.coefficients[index])
        } else {
            None
        }
    }
    pub fn sample<R>(degree: usize, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Polynomial {
            coefficients: (0..=degree).map(|_| random_scalar(rng)).collect(),
        }
    }

    pub fn sample_set_f0<R>(degree: usize, rng: &mut R, f0: &Scalar) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut coefs: Vec<Scalar> = (0..=degree).map(|_| random_scalar(rng)).collect();
        coefs[0] = *f0;

        Polynomial {
            coefficients: coefs,
        }
    }

    pub fn sample_two<R>(degree: usize, rng: &mut R) -> (Self, Self)
    where
        R: CryptoRng + RngCore,
    {
        let (coefs_1, coefs_2) = (0..=degree)
            .map(|_| (random_scalar(rng), random_scalar(rng)))
            .collect();

        (
            Polynomial {
                coefficients: coefs_1,
            },
            Polynomial {
                coefficients: coefs_2,
            },
        )
    }
    pub fn sample_two_set_f0<R>(degree: usize, f0: &Scalar, rng: &mut R) -> (Self, Self)
    where
        R: CryptoRng + RngCore,
    {
        let (mut coefs_1, coefs_2): (Vec<Scalar>, Vec<Scalar>) = (0..=degree)
            .map(|_| (random_scalar(rng), random_scalar(rng)))
            .collect();

        coefs_1[0] = *f0;

        (
            Polynomial {
                coefficients: coefs_1,
            },
            Polynomial {
                coefficients: coefs_2,
            },
        )
    }
    pub fn evaluate(&self, x: usize) -> Scalar {
        let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from(x as u64)];

        for i in 2..self.coefficients.len() {
            x_powers.push(x_powers[1] * x_powers[i - 1]);
        }

        self.coefficients
            .par_iter()
            .zip(x_powers)
            .map(|(coef, x_pow)| coef * x_pow)
            .sum()
    }

    pub fn evaluate_multiply(
        &self,
        points: &Vec<RistrettoPoint>,
        x_0: usize,
    ) -> (Vec<Scalar>, Vec<RistrettoPoint>) {
        points
            .par_iter()
            .enumerate()
            .map(|(i, point)| {
                // (i = 0 => 1st party (x = x_0))
                // for pvss x_0 == 1; for ppvss x_0 == 0
                // i is the index of the party
                // i+1 here means start evaluating at x=1
                // x_powers[0] <= constant term multiplier
                // x_powers[1] = x(^1)
                let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from((i + x_0) as u64)];

                // x_powers[2] = x_powers[1] * x_powers[2-1] == x_powers[1] * x_powers[1] = x * x = x^2
                // x_powers[3] = x_powers[1] * x_powers[3-1] == x_powers[1] * x_powers[2] = x * x^2 == x^3
                // ...
                // i+1 here means start evaluating at till x = 32
                for j in 2..self.coefficients.len() {
                    x_powers.push(x_powers[1] * x_powers[j - 1]);
                }

                let f_val = self
                    .coefficients
                    .iter()
                    .zip(x_powers)
                    .fold(Scalar::ZERO, |acc_f, (coef_f, x_pow)| {
                        acc_f + coef_f * x_pow
                    });

                (f_val, (f_val * point))
            })
            .unzip()
    }

    pub fn evaluate_multiply_two_ppvss(
        &self,
        other: &Self,
        points: &Vec<RistrettoPoint>,
    ) -> (Vec<CompressedRistretto>, Vec<CompressedRistretto>) {
        points
            .par_iter()
            .enumerate()
            .map(|(i, point)| {
                // i is the index of the party
                // i here means start evaluating at x=0
                // x_powers[0] <= constant term multiplier
                // x_powers[1] = x(^1)

                let mut x_powers: Vec<Scalar> = Vec::with_capacity(self.coefficients.len());
                x_powers.push(Scalar::ONE);
                x_powers.push(Scalar::from((i) as u64));

                // x_powers[2] = x_powers[1] * x_powers[2-1] == x_powers[1] * x_powers[1] = x * x = x^2
                // x_powers[3] = x_powers[1] * x_powers[3-1] == x_powers[1] * x_powers[2] = x * x^2 == x^3
                // ...
                // i+1 here means start evaluating at till x = 32
                for j in 2..self.coefficients.len() {
                    x_powers.push(x_powers[1] * x_powers[j - 1]);
                }

                let (f_val, r_val) = self
                    .coefficients
                    .par_iter()
                    .zip(other.coefficients.par_iter())
                    .zip(x_powers)
                    .map(|((coef_f, coef_r), x_pow)| (coef_f * x_pow, coef_r * x_pow))
                    .reduce(
                        || (Scalar::ZERO, Scalar::ZERO),
                        |(mut acc_f, mut acc_r), (fval, rval)| {
                            acc_f += fval;
                            acc_r += rval;
                            (acc_f, acc_r)
                        },
                    );

                ((f_val * point).compress(), (r_val * point).compress())
            })
            .collect()
    }

    pub fn evaluate_multiply_two(
        &self,
        other: &Self,
        points: &Vec<RistrettoPoint>,
    ) -> (Vec<CompressedRistretto>, Vec<CompressedRistretto>) {
        points
            .par_iter()
            .enumerate()
            .map(|(i, point)| {
                // i is the index of the party
                // i+1 here means start evaluating at x=1
                // x_powers[0] <= constant term multiplier
                // x_powers[1] = x(^1)
                let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from((i + 1) as u64)];

                // x_powers[2] = x_powers[1] * x_powers[2-1] == x_powers[1] * x_powers[1] = x * x = x^2
                // x_powers[3] = x_powers[1] * x_powers[3-1] == x_powers[1] * x_powers[2] = x * x^2 == x^3
                // ...
                // i+1 here means start evaluating at till x = 32
                for j in 2..self.coefficients.len() {
                    x_powers.push(x_powers[1] * x_powers[j - 1]);
                }

                let (f_val, r_val) = self
                    .coefficients
                    .iter()
                    .zip(other.coefficients.iter())
                    .zip(x_powers)
                    .fold(
                        (Scalar::ZERO, Scalar::ZERO),
                        |(acc_f, acc_r), ((coef_f, coef_r), x_pow)| {
                            (acc_f + coef_f * x_pow, acc_r + coef_r * x_pow)
                        },
                    );

                ((f_val * point).compress(), (r_val * point).compress())
            })
            .collect()
    }

    pub fn sum(&self, p: &Polynomial) -> Self {
        Self {
            coefficients: self
                .coefficients
                .par_iter()
                .zip(p.coefficients.par_iter())
                .map(|(a, b)| a + b)
                .collect(),
        }
    }

    pub fn coef_op(&self, f: fn(Scalar, Scalar) -> Scalar, x: &Scalar) -> Self {
        Self {
            coefficients: self
                .coefficients
                .par_iter()
                .map(|coef| f(*coef, *x))
                .collect(),
        }
    }

    pub fn mul_with_point_compress(&self, point: &RistrettoPoint) -> Vec<CompressedRistretto> {
        self.coefficients
            .par_iter()
            .map(|coef| (coef * point).compress())
            .collect()
    }

    pub fn coef_op_in_place(&mut self, f: fn(Scalar, Scalar) -> Scalar, x: &Scalar) {
        self.coefficients
            .par_iter_mut()
            .for_each(|coef| *coef = f(*coef, *x));
    }

    pub fn mul_sum(&mut self, mul_val: &Scalar, p2: &Self) {
        self.coefficients
            .par_iter_mut()
            .zip(p2.coefficients.par_iter())
            .for_each(|(p1_coef, p2_coef)| {
                *p1_coef *= mul_val;
                *p1_coef += p2_coef
            });
    }
}
impl std::fmt::Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.coefficients
                .par_iter()
                .map(|coef| format!("{:x?}", coef.as_bytes()))
                .collect::<Vec<String>>()
                .join(",")
        )
    }
}
