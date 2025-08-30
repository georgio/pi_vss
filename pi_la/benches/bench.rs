use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};
use pi_la::{dealer::Dealer, party::generate_parties};

use common::{
    BENCH_N_T,
    precompute::gen_powers,
    random::{random_point, random_scalar},
    secret_sharing::generate_shares,
    utils::ingest_public_keys,
};

fn vss(c: &mut Criterion) {
    for (n, t) in BENCH_N_T {
        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let g: RistrettoPoint = random_point(&mut rng);
        let xpows = gen_powers(n, t);

        let mut parties = generate_parties(&g, &mut rng, n, t);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(n, t, &public_keys).unwrap();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.public_keys = Some(
                ingest_public_keys(n, &party.public_key.1, party.index, &public_keys).unwrap(),
            );
        }

        let secret = random_scalar(&mut rng);

        let (f_polynomial, f_evals) = generate_shares(&mut rng, n, t, &xpows, &secret);

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_LA VSS | Dealer: Generate Proof", n, t),
            |b| {
                b.iter_batched(
                    || {
                        (
                            blake3::Hasher::new(),
                            [0u8; 64],
                            vec![[0u8; 64]; dealer.public_keys.len()],
                            f_polynomial.clone(),
                        )
                    },
                    |(mut hasher, mut buf, mut c_buf, f_poly)| {
                        dealer.generate_proof(
                            &mut rng,
                            &mut hasher,
                            &mut buf,
                            &mut c_buf,
                            &xpows,
                            f_poly,
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
    }
}

criterion_group!(benches, vss);
criterion_main!(benches);
