use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};
use pi_la::{dealer::Dealer, party::generate_parties};

use common::{
    precompute::gen_powers,
    random::{random_point, random_scalar},
    utils::compute_lagrange_bases,
};
use rayon::prelude::*;

fn pvss(c: &mut Criterion) {
    for (n, t) in [
        // (32, 15),
        (64, 31),
        // (128, 63),
        // (256, 127),
        // (512, 255),
        // (1024, 511),
        // (2048, 1023),
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

        let secret = random_scalar(&mut rng);

        // c.bench_function(
        //     &format!("(n: {}, t: {}) | Pi_LA VSS | Dealer: Deal Secret", n, t),
        //     |b| {
        //         b.iter_batched(
        //             || (blake3::Hasher::new(), [0u8; 64]),
        //             |(mut hasher, mut buf)| {
        //                 dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &secret)
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );
        // c.bench_function(
        //     &format!("(n: {}, t: {}) | Pi_LA VSS | Dealer: Deal Secret_v2", n, t),
        //     |b| {
        //         b.iter_batched(
        //             || (blake3::Hasher::new(), [0u8; 64]),
        //             |(mut hasher, mut buf)| {
        //                 dealer.deal_secret_v2(&mut rng, &mut hasher, &mut buf, &secret)
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );
        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_LA VSS | Dealer: Generate Shares", n, t),
            |b| {
                b.iter_batched(
                    || random_scalar(&mut rand::rng()),
                    |secret| dealer.generate_shares(&mut rng, &xpows, &secret),
                    BatchSize::PerIteration,
                )
            },
        );

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_LA VSS | Dealer: Generate Proof", n, t),
            |b| {
                b.iter_batched(
                    || {
                        (
                            blake3::Hasher::new(),
                            [0u8; 64],
                            vec![[0u8; 64]; dealer.public_keys.len()],
                            dealer.generate_shares(&mut rand::rng(), &xpows, &secret),
                        )
                    },
                    |(mut hasher, mut buf, mut c_buf, (f_polynomial, f_evals))| {
                        dealer.generate_proof(
                            &mut rng,
                            &mut hasher,
                            &mut buf,
                            &mut c_buf,
                            &xpows,
                            f_polynomial,
                            &f_evals,
                        );
                    },
                    BatchSize::PerIteration,
                )
            },
        );
        // c.bench_function(
        //     &format!(
        //         "(n: {}, t: {}) | Pi_LA VSS | Dealer: Generate Proof (1k)",
        //         n, t
        //     ),
        //     |b| {
        //         b.iter_batched(
        //             || dealer.generate_shares(&mut rand::rng(), &xpows, &secret),
        //             |(f_polynomial, f_evals)| {
        //                 (0..1000).into_par_iter().for_each(|_| {
        //                     dealer.generate_proof(
        //                         &mut rand::rng(),
        //                         &mut blake3::Hasher::new(),
        //                         &mut [0u8; 64],
        //                         f_polynomial.clone(),
        //                         &f_evals,
        //                     );
        //                 });
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );
        // c.bench_function(
        //     &format!(
        //         "(n: {}, t: {}) | Pi_LA VSS | Dealer: Generate Proof (10k)",
        //         n, t
        //     ),
        //     |b| {
        //         b.iter_batched(
        //             || dealer.generate_shares(&mut rand::rng(), &xpows, &secret),
        //             |(f_polynomial, f_evals)| {
        //                 (0..10000).into_par_iter().for_each(|_| {
        //                     dealer.generate_proof(
        //                         &mut rand::rng(),
        //                         &mut blake3::Hasher::new(),
        //                         &mut [0u8; 64],
        //                         f_polynomial.clone(),
        //                         &f_evals,
        //                     );
        //                 });
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );

        let (shares, (c_vals, z)) =
            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secret);
        for p in &mut parties {
            p.ingest_shares(&shares).unwrap();
            p.ingest_dealer_proof((&c_vals, &z)).unwrap();

            assert!(
                p.verify_shares(&mut hasher, &mut buf, &xpows).unwrap(),
                "share verification failure"
            );
        }

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_LA VSS | Party: Verify Shares", n, t),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        assert!(
                            parties[0]
                                .verify_shares(&mut hasher, &mut buf, &xpows)
                                .unwrap()
                        )
                    },
                    BatchSize::PerIteration,
                )
            },
        );

        // c.bench_function(
        //     &format!(
        //         "(n: {}, t: {}) | Pi_LA VSS | Party: Verify Shares (1k)",
        //         n, t
        //     ),
        //     |b| {
        //         b.iter_batched(
        //             || (blake3::Hasher::new(), [0u8; 64]),
        //             |(mut hasher, mut buf)| {
        //                 (0..1000).into_par_iter().for_each(|_| {
        //                     assert!(
        //                         parties[0]
        //                             .clone()
        //                             .verify_shares(&mut hasher.clone(), &mut buf.clone())
        //                             .unwrap()
        //                     )
        //                 });
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );
        // c.bench_function(
        //     &format!(
        //         "(n: {}, t: {}) | Pi_LA VSS | Party: Verify Shares (10k)",
        //         n, t
        //     ),
        //     |b| {
        //         b.iter_batched(
        //             || (parties[0].clone(), blake3::Hasher::new(), [0u8; 64]),
        //             |(mut p, mut hasher, mut buf)| {
        //                 (0..10000).into_par_iter().for_each(|_| {
        //                     assert!(
        //                         p.clone()
        //                             .verify_shares(&mut hasher.clone(), &mut buf.clone())
        //                             .unwrap()
        //                     )
        //                 });
        //             },
        //             BatchSize::PerIteration,
        //         )
        //     },
        // );

        // for p in &mut parties {
        //     p.select_qualified_set(&mut rng).unwrap();

        //     let indices: Vec<usize> = p
        //         .qualified_set
        //         .as_ref()
        //         .unwrap()
        //         .iter()
        //         .map(|(index, _)| *index)
        //         .collect();

        //     let lagrange_bases = compute_lagrange_bases(&indices);

        //     let sec = p.reconstruct_secret(&lagrange_bases).unwrap();
        //     assert!(sec == secret);
        // }

        // parties[0].select_qualified_set(&mut rng).unwrap();

        // let indices: Vec<usize> = parties[0]
        //     .qualified_set
        //     .as_ref()
        //     .unwrap()
        //     .iter()
        //     .map(|(index, _)| *index)
        //     .collect();

        // let lagrange_bases = compute_lagrange_bases(&indices);

        // c.bench_function(
        //     &format!(
        //         "(n: {}, t: {}) | Pi_LA VSS | Party: Reconstruct Secret",
        //         n, t
        //     ),
        //     |b| {
        //         b.iter(|| {
        //             parties[0].reconstruct_secret(&lagrange_bases).unwrap();
        //         })
        //     },
        // );
    }
}

criterion_group!(benches, pvss);
criterion_main!(benches);
