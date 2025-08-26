use blake3::Hasher;
use common::{
    error::ErrorKind::PointDecompressionError,
    polynomial::Polynomial,
    precompute::XPowTable,
    random::{random_scalar, random_scalars},
    utils::{compute_lagrange_bases, compute_lagrange_basis},
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;

fn add_mul(c: &mut Criterion) {
    let a1 = random_scalar(&mut rand::rng());
    let a2 = random_scalar(&mut rand::rng());
    c.bench_function("Add", |b| b.iter(|| a1 + a2));
    c.bench_function("Mul", |b| b.iter(|| a1 * a2));
}

fn sample_bench(c: &mut Criterion) {
    // let n = 64;
    let t = 31;
    let k = 10000;

    // let polynomials = Polynomial::sample_n(k, t);

    let f0_vals = random_scalars(&mut rand::rng(), k);

    c.bench_function(&format!("poly sampling: k = {}", k), |b| {
        b.iter_batched(
            || f0_vals.clone(),
            |f0_vals| {
                (0..k)
                    .into_par_iter()
                    .zip(f0_vals)
                    .map_init(
                        || rand::rng(),
                        |mut rng, (_, f0)| {
                            let mut coefs: Vec<Scalar> =
                                (0..=t).map(|_| random_scalar(&mut rng)).collect();
                            coefs[0] = f0;

                            Polynomial::from_coefficients(coefs)
                        },
                    )
                    .collect::<Vec<Polynomial>>()
            },
            BatchSize::PerIteration,
        )
    });
    c.bench_function(&format!("poly samplingv2: k = {}", k), |b| {
        b.iter_batched(
            || f0_vals.clone(),
            |mut f0_vals| {
                (0..k)
                    .into_par_iter()
                    .zip(f0_vals)
                    .map_init(
                        || rand::rng(),
                        |mut rng, (_, f0)| {
                            let mut coefs: Vec<Scalar> =
                                (0..=t).map(|_| random_scalar(&mut rng)).collect();
                            coefs[0] = f0;

                            Polynomial::from_coefficients(coefs)
                        },
                    )
                    .collect::<Vec<Polynomial>>()
            },
            BatchSize::PerIteration,
        )
    });
    // c.bench_function(&format!("scalar sampling: t = {}", t), |b| {
    //     b.iter_batched(
    //         || rand::rng(),
    //         |mut rng| {
    //             random_scalars(&mut rng, t);
    //         },
    //         BatchSize::PerIteration,
    //     )
    // });
    // c.bench_function(&format!("scalar sampling: t = {}, 1x64", t), |b| {
    //     b.iter_batched(
    //         || rand::rng(),
    //         |mut rng| {
    //             for i in 0..t {
    //                 random_scalar(&mut rng);
    //             }
    //         },
    //         BatchSize::PerIteration,
    //     )
    // });
}

fn eval_bench(c: &mut Criterion) {
    let n = 64;
    let t = 31;
    let k = 10000;

    let polynomials = Polynomial::sample_n(k, t);
    c.bench_function(&format!("evaluation_precomp: t = {}", t), |b| {
        b.iter(|| {
            (1..=n)
                .into_par_iter()
                .map(|i| {
                    let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from(i as u64)];

                    for i in 2..t {
                        x_powers.push(x_powers[1] * x_powers[i - 1]);
                    }

                    polynomials
                        .par_iter()
                        .map(|polynomial| {
                            polynomial
                                .coef_ref()
                                .iter()
                                .zip(&x_powers)
                                .map(|(coef, x_pow)| coef * x_pow)
                                .sum()
                        })
                        .collect::<Vec<Scalar>>()
                })
                .collect::<Vec<Vec<Scalar>>>()
        })
    });
}

fn eval_bench_one(c: &mut Criterion) {
    let n = 2048;
    let t = 1023;

    let poly = Polynomial::sample(t, &mut rand::rng());

    let xpows = XPowTable::new();
    let pows = &xpows.n2048_t1023;

    // c.bench_function(&format!("evaluation: t = {}", t), |b| {
    //     b.iter(|| {
    //         (1..=512)
    //             .into_par_iter()
    //             .map(|i| {
    //                 let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from(i as u64)];

    //                 for i in 2..poly.coefficients.len() {
    //                     x_powers.push(x_powers[1] * x_powers[i - 1]);
    //                 }

    //                 poly.coefficients
    //                     .par_iter()
    //                     .zip(x_powers)
    //                     .map(|(coef, x_pow)| coef * x_pow)
    //                     .sum::<Scalar>()
    //             })
    //             .collect::<Vec<Scalar>>()
    //     })
    // });

    c.bench_function(&format!("evaluation: t = {}", t), |b| {
        b.iter(|| {
            poly.evaluate_range(1, n);
        })
    });

    c.bench_function(&format!("evaluation(1): t = {}", t), |b| {
        b.iter(|| {
            poly.evaluate(1);
        })
    });
    // c.bench_function(&format!("evaluation(1000): t = {}", t), |b| {
    //     b.iter(|| {
    //         poly.evaluate(1000);
    //     })
    // });
    // c.bench_function(&format!("evaluation(2000): t = {}", t), |b| {
    //     b.iter(|| {
    //         poly.evaluate(2000);
    //     })
    // });

    c.bench_function(&format!("evaluation_precomp: t = {}", t), |b| {
        b.iter(|| {
            poly.evaluate_range_precomp(pows, 1, n);
        })
    });
    c.bench_function(&format!("evaluation_precomp_1: t = {}", t), |b| {
        b.iter(|| {
            poly.evaluate_range_precomp(pows, 1, 1);
        })
    });
}

fn lagrange_basis_bench(c: &mut Criterion) {
    // for t in [8, 127, 255] {
    let t = 255;
    let qualified_set: Vec<usize> = (1..=(t + 1)).into_iter().map(|x| x as usize).collect();
    c.bench_function(&format!("Lagrange Basis Computation: t = {}", t), |b| {
        b.iter(|| {
            for _ in 0..(t + 1) {
                compute_lagrange_basis(1, &qualified_set);
            }
        })
    });
    c.bench_function(&format!("Lagrange Basis Computation: t = {}", t), |b| {
        b.iter(|| compute_lagrange_bases(&qualified_set))
    });
    // }
}

fn ristretto_point_bench(c: &mut Criterion) {
    let mut rng = rand::rng();
    let x = random_scalar(&mut rng);
    let G: RistrettoPoint = RistrettoPoint::mul_base(&random_scalar(&mut rng));

    let gx = G * x;
    let gx_compressed = gx.compress();

    c.bench_function("Basepoint Multiplication", |b| {
        b.iter(|| RistrettoPoint::mul_base(&x))
    });

    c.bench_function("Random Point Multiplication", |b| b.iter(|| G * x));

    c.bench_function("Point Compression", |b| b.iter(|| gx.compress()));
    c.bench_function("Point Decompression", |b| {
        b.iter(|| gx_compressed.decompress().unwrap())
    });
    c.bench_function("Point Decompression Handled", |b| {
        b.iter(|| match gx_compressed.decompress() {
            Some(point) => Ok(point),
            None => Err(PointDecompressionError),
        })
    });
}

fn hasher_bench(c: &mut Criterion) {
    c.bench_function("Buf Zeroize", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let mut buf: [u8; 64] = [0u8; 64];
                rng.fill_bytes(&mut buf);
                buf
            },
            |mut buf| {
                buf.zeroize();
            },
            BatchSize::PerIteration,
        )
    });
    c.bench_function("Hasher Reset", |b| {
        b.iter_batched(
            || {
                let mut rng = rand::rng();
                let mut buf: [u8; 64] = [0u8; 64];
                rng.fill_bytes(&mut buf);
                let mut hasher = Hasher::new();
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher.update(&buf);
                hasher
            },
            |mut hasher| {
                hasher.reset();
            },
            BatchSize::PerIteration,
        )
    });
    c.bench_function("Hasher Reset", |b| b.iter(|| Hasher::new()));
}

criterion_group!(
    benches,
    // lagrange_basis_bench,
    // ristretto_point_bench,
    // hasher_bench
    // eval_bench,
    // sample_bench
    eval_bench_one
);
criterion_main!(benches);
