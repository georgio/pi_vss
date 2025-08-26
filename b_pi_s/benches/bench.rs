use std::ops::{Add, Mul};

use b_pi_s::{dealer::Dealer, party::generate_parties};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

use common::{
    polynomial::Polynomial,
    precompute::gen_powers,
    random::{random_point, random_scalar, random_scalars},
    utils::compute_lagrange_bases,
};

use blake3::Hasher;

use rayon::prelude::*;
use zeroize::Zeroize;

fn d(c: &mut Criterion) {
    for k in [5, 1000, 10000] {
        c.bench_function(&format!("d computation, k = {}", k), |b| {
            b.iter_batched(
                || random_scalar(&mut rand::rng()),
                |d| {
                    let mut d_vals = Vec::with_capacity(k);
                    // [d^1,
                    d_vals.push(d);
                    // d^2, d^3, ... d^k]
                    for i in 1..k {
                        d_vals.push(d_vals[i - 1] * d);
                    }
                },
                BatchSize::PerIteration,
            )
        });
    }
}

fn vss_proof(c: &mut Criterion) {
    let mut rng = rand::rng();
    let mut hasher = blake3::Hasher::new();
    let mut buf: [u8; 64] = [0u8; 64];

    let n = 512;
    let t = 255;
    let k = 10;

    let xpows = gen_powers(n, t);

    let G: RistrettoPoint = random_point(&mut rng);

    let mut parties = generate_parties(&G, &mut rng, n, t);

    let public_keys: Vec<CompressedRistretto> =
        parties.iter().map(|party| party.public_key.0).collect();

    let mut dealer = Dealer::new(n, t, &public_keys).unwrap();

    let mut secrets = random_scalars(&mut rng, k);

    let (mut f_polynomials, f_evals) = dealer.generate_shares(&xpows, k, &secrets);

    // end sharing

    let mut buf = [0u8; 64];
    let mut c_buf = vec![[0u8; 64]; n];

    let eval_bytes: Vec<Vec<u8>> = f_evals
        .par_iter()
        .flat_map(|f_eval| f_eval.par_iter().map(|eval| eval.as_bytes().to_vec()))
        .collect();

    // end pre-proof setup

    //begin proof

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Polynomial Sampling v1 (r)",
            k, n, t
        ),
        |b| b.iter(|| Polynomial::sample(t, &mut rng)),
    );

    let mut r = Polynomial::sample(t, &mut rng);

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Polynomial Evaluation (r)",
            k, n, t
        ),
        |b| b.iter(|| Polynomial::evaluate_range(&r, 1, n)),
    );

    let r_evals = Polynomial::evaluate_range(&r, 1, n);

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Generate Commitments (Hash (fi, ri))",
            k, n, t
        ),
        |b| {
            b.iter_batched(
                || vec![[0u8; 64]; n],
                |_| {
                    c_buf
                        .par_iter_mut()
                        .zip(eval_bytes.par_iter().zip(r_evals.par_iter()))
                        .for_each_init(
                            || Hasher::new(),
                            |l_hasher, (l_buf, (fi, ri))| {
                                l_hasher.update_rayon(&fi);
                                fi.len();
                                l_hasher.update(ri.as_bytes());
                                l_hasher.finalize_xof().fill(l_buf);
                                l_hasher.reset();
                            },
                        )
                },
                BatchSize::PerIteration,
            )
        },
    );

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Alloc + Hash Commitments + Construct d",
            k, n, t
        ),
        |b| {
            b.iter(|| {
                let flat_vec: Vec<u8> = c_buf.clone().into_iter().flatten().collect();

                hasher.update(&flat_vec);
                hasher.finalize_xof().fill(&mut buf);

                let d = Scalar::from_bytes_mod_order_wide(&mut buf);
                buf.zeroize();
                hasher.reset();
            })
        },
    );

    let flat_vec: Vec<u8> = c_buf.clone().into_iter().flatten().collect();

    hasher.update(&flat_vec);
    hasher.finalize_xof().fill(&mut buf);

    let d = Scalar::from_bytes_mod_order_wide(&mut buf);
    buf.zeroize();
    hasher.reset();

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Compute Powers of d",
            k, n, t
        ),
        |b| {
            b.iter(|| {
                let mut d_vals = Vec::with_capacity(k);
                // [d^1,
                d_vals.push(d);
                // d^2, d^3, ... d^k]
                for i in 1..k {
                    d_vals.push(d_vals[i - 1] * d);
                }
            })
        },
    );
    let mut d_vals = Vec::with_capacity(k);
    // [d^1,
    d_vals.push(d);
    // d^2, d^3, ... d^k]
    for i in 1..k {
        d_vals.push(d_vals[i - 1] * d);
    }

    let mut f_clone_v1 = f_polynomials.clone();
    let mut f_clone_v2 = f_polynomials.clone();

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | (d_j * f_j) v1",
            k, n, t
        ),
        |b| {
            b.iter_batched(
                || f_clone_v1.clone(),
                |mut f_polynomials| {
                    // d_j * f_j
                    f_polynomials
                        .par_iter_mut()
                        .zip(d_vals.par_iter())
                        .for_each(|(poly, d_val)| {
                            poly.coef_op_in_place(Scalar::mul, d_val);
                        });
                },
                BatchSize::PerIteration,
            )
        },
    );
    f_clone_v1
        .par_iter_mut()
        .zip(d_vals.par_iter())
        .for_each(|(poly, d_val)| {
            poly.coef_op_in_place(Scalar::mul, d_val);
        });

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | z = r + ( ∑ d_j * f_j ) v1",
            k, n, t
        ),
        |b| {
            b.iter_batched(
                || (f_clone_v1.clone(), r.clone()),
                |(f_poly_clone, mut r)| {
                    r.coef_mut().par_iter_mut().enumerate().for_each(|(i, ri)| {
                        *ri += f_poly_clone
                            .par_iter()
                            .map(|f| f.coef_ref()[i])
                            .sum::<Scalar>()
                    });
                },
                BatchSize::PerIteration,
            )
        },
    );

    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | z = r + ( ∑ d_j * f_j ) v2",
            k, n, t
        ),
        |b| {
            b.iter_batched(
                || r.clone(),
                |mut r| {
                    r.coef_mut().par_iter_mut().enumerate().for_each(|(i, ri)| {
                        *ri += f_clone_v2
                            .par_iter()
                            .zip(d_vals.par_iter())
                            .map(|(f, d)| f.coef_ref()[i] * d)
                            .sum::<Scalar>()
                    });
                },
                BatchSize::PerIteration,
            )
        },
    );

    f_polynomials
        .par_iter_mut()
        .zip(d_vals.par_iter())
        .for_each(|(poly, d_val)| {
            poly.coef_op_in_place(Scalar::mul, d_val);
        });

    let rc = r.clone();
    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | // z = r + ( ∑ d_j * f_j )",
            k, n, t
        ),
        |b| {
            b.iter_batched(
                || rc.clone(),
                |mut r| {
                    r.fold_op_into(Scalar::add, &f_polynomials);
                },
                BatchSize::PerIteration,
            )
        },
    );

    // reset
    let mut buf = [0u8; 64];
    let mut c_buf = vec![[0u8; 64]; n];

    let eval_bytes: Vec<Vec<u8>> = f_evals
        .par_iter()
        .flat_map(|f_eval| f_eval.par_iter().map(|eval| eval.as_bytes().to_vec()))
        .collect();
    c.bench_function(
        &format!(
            "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Dealer: Generate Proof",
            k, n, t
        ),
        |b| {
            b.iter(|| {
                let mut r = Polynomial::sample(t, &mut rng);
                let r_evals = Polynomial::evaluate_range(&r, 1, n);

                c_buf
                    .par_iter_mut()
                    .zip(eval_bytes.par_iter().zip(r_evals.par_iter()))
                    .for_each_init(
                        || Hasher::new(),
                        |l_hasher, (l_buf, (fi, ri))| {
                            l_hasher.update_rayon(&fi);
                            fi.len();
                            l_hasher.update(ri.as_bytes());
                            l_hasher.finalize_xof().fill(l_buf);
                            l_hasher.reset();
                        },
                    );

                let flat_vec: Vec<u8> = c_buf.clone().into_iter().flatten().collect();

                hasher.update(&flat_vec);
                hasher.finalize_xof().fill(&mut buf);

                let d = Scalar::from_bytes_mod_order_wide(&mut buf);
                buf.zeroize();
                hasher.reset();

                let mut d_vals = Vec::with_capacity(k);
                // [d^1,
                d_vals.push(d);
                // d^2, d^3, ... d^k]
                for i in 1..k {
                    d_vals.push(d_vals[i - 1] * d);
                }

                // z = r + ( ∑ d_j * f_j )
                r.coef_mut().par_iter_mut().enumerate().for_each(|(i, ri)| {
                    *ri += f_polynomials
                        .par_iter()
                        .zip(d_vals.par_iter())
                        .map(|(f, d)| f.coef_ref()[i] * d)
                        .sum::<Scalar>()
                });
            })
        },
    );
}

fn VSS(c: &mut Criterion) {
    // for k in [1, 100, 500] {
    for k in [10] {
        for (n, t) in [
            // (16, 7),
            // (32, 15),
            // (64, 31),
            // (128, 63),
            // (256, 127),
            (512, 255),
            // (1024, 511),
            // (2048, 1023),
            // (4096, 2047),
        ] {
            let mut rng = rand::rng();
            let mut hasher = blake3::Hasher::new();
            let mut buf: [u8; 64] = [0u8; 64];

            let G: RistrettoPoint = random_point(&mut rng);
            let xpows = gen_powers(n, t);

            let mut parties = generate_parties(&G, &mut rng, n, t);

            let public_keys: Vec<CompressedRistretto> =
                parties.iter().map(|party| party.public_key.0).collect();

            let mut dealer = Dealer::new(n, t, &public_keys).unwrap();

            for party in &mut parties {
                let public_keys: Vec<CompressedRistretto> = public_keys
                    .iter()
                    .filter(|pk| &party.public_key.0 != *pk)
                    .copied()
                    .collect();

                party.ingest_public_keys(&public_keys).unwrap();
            }

            let mut secrets = random_scalars(&mut rng, k);

            // c.bench_function(
            //     &format!(
            //         "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Dealer: Deal Secret (v2)",
            //         k, n, t
            //     ),
            //     |b| {
            //         b.iter_batched(
            //             || (blake3::Hasher::new(), [0u8; 64]),
            //             |(mut hasher, mut buf)| {
            //                 dealer.deal_secrets_v2(&mut rng, &mut hasher, &mut buf, &secrets)
            //             },
            //             BatchSize::PerIteration,
            //         )
            //     },
            // );

            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Dealer: Generate Shares",
                    k, n, t
                ),
                |b| b.iter(|| dealer.generate_shares(&xpows, k, &secrets)),
            );

            let (f_polynomials, f_evals) = dealer.generate_shares(&xpows, k, &secrets);

            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Dealer: Generate Proof",
                    k, n, t
                ),
                |b| {
                    b.iter_batched(
                        || {
                            (
                                blake3::Hasher::new(),
                                [0u8; 64],
                                vec![[0u8; 64]; dealer.public_keys.len()],
                            )
                        },
                        |(mut hasher, mut buf, mut c_buf)| {
                            dealer.generate_proof(
                                &mut rng,
                                &mut hasher,
                                &mut buf,
                                &mut c_buf,
                                &xpows,
                                k,
                                &f_polynomials,
                                &f_evals,
                            )
                        },
                        BatchSize::PerIteration,
                    )
                },
            );

            let (shares, (c_vals, z)) =
                dealer.deal_secrets(&mut rng, &mut hasher, &mut buf, &xpows, &mut secrets);

            for p in &mut parties {
                p.ingest_shares(&shares).unwrap();
                p.ingest_dealer_proof((&c_vals, &z)).unwrap();

                assert!(
                    p.verify_shares(&mut hasher, &mut buf, &xpows).unwrap(),
                    "share verification failure"
                );
            }

            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Party: Verify Shares",
                    k, n, t
                ),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64], parties[0].clone()),
                        |(mut hasher, mut buf, mut p0)| {
                            assert!(p0.verify_shares(&mut hasher, &mut buf, &xpows).unwrap())
                        },
                        BatchSize::PerIteration,
                    )
                },
            );

            for p in &mut parties {
                assert!(
                    p.verify_shares(&mut hasher, &mut buf, &xpows).unwrap(),
                    "share verification failure"
                );
                p.select_qualified_set(&mut rng).unwrap();

                let indices: Vec<usize> = p
                    .qualified_set
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|(index, _)| *index)
                    .collect();

                let lagrange_bases = compute_lagrange_bases(&indices);

                let sec = p.reconstruct_secrets(&lagrange_bases).unwrap();
                assert!(sec == secrets);
            }

            parties[0].select_qualified_set(&mut rng).unwrap();

            let indices: Vec<usize> = parties[0]
                .qualified_set
                .as_ref()
                .unwrap()
                .iter()
                .map(|(index, _)| *index)
                .collect();

            let lagrange_bases = compute_lagrange_bases(&indices);

            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_LA VSS | Party: Reconstruct Secrets",
                    k, n, t
                ),
                |b| {
                    b.iter(|| {
                        parties[0].reconstruct_secrets(&lagrange_bases).unwrap();
                    })
                },
            );
        }
    }
}

// criterion_group!(benches, d, VSS);
// criterion_group!(benches, d);
criterion_group!(benches, VSS);
// criterion_group!(benches, add_mul);
// criterion_group!(benches, vss_proof);
criterion_main!(benches);
