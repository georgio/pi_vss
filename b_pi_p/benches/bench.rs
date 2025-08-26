use b_pi_p::{dealer::Dealer, party::generate_parties};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};

use common::{
    precompute::gen_powers,
    random::{random_point, random_points, random_scalars},
    utils::compute_lagrange_bases,
};

fn pvss(c: &mut Criterion) {
    for k in [10, 100, 1000] {
        for (n, t) in [
            (64, 31),
            (128, 63),
            (256, 127),
            (512, 255),
            (1024, 511),
            (2048, 1023),
        ] {
            let mut rng = rand::rng();
            let mut hasher = blake3::Hasher::new();
            let mut buf: [u8; 64] = [0u8; 64];

            let generator: RistrettoPoint = random_point(&mut rng);
            let g: Vec<RistrettoPoint> = random_points(&mut rng, k);
            let g2: RistrettoPoint = random_point(&mut rng);
            let g3: RistrettoPoint = random_point(&mut rng);

            let xpows = gen_powers(n, t);

            let mut parties = generate_parties(&generator, &g, &g2, &g3, &mut rng, n, t);

            let public_keys: Vec<CompressedRistretto> =
                parties.iter().map(|party| party.public_key.0).collect();

            let mut dealer = Dealer::new(g, g2, g3, n, t, &public_keys).unwrap();

            for party in &mut parties {
                let public_keys: Vec<CompressedRistretto> = public_keys
                    .iter()
                    .filter(|pk| &party.public_key.0 != *pk)
                    .copied()
                    .collect();

                party.ingest_public_keys(&public_keys).unwrap();
            }

            let secrets = random_scalars(&mut rng, k);

            let (shares, (g, c_vals, z)) =
                dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secrets);

            c.bench_function(
                &format!("(n: {}, t: {}) | Pi_P PVSS | Dealer: Deal Secret", n, t),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64]),
                        |(mut hasher, mut buf)| {
                            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secrets)
                        },
                        BatchSize::PerIteration,
                    )
                },
            );

            for p in &mut parties {
                p.ingest_shares((&shares, &g)).unwrap();
                p.ingest_dealer_proof((&c_vals, &z)).unwrap();

                assert!(
                    p.verify_shares(&mut hasher, &mut buf, &xpows).unwrap(),
                    "share verification failure"
                );
            }

            c.bench_function(
                &format!("(n: {}, t: {}) | Pi_P PVSS | Party: Verify Shares", n, t),
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

            for p in &mut parties {
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
                assert!(secrets == sec, "Invalid Reconstructed Secret");
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
                    "(n: {}, t: {}) | Pi_P PVSS | Party: Reconstruct Secret",
                    n, t
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

criterion_group!(benches, pvss);
criterion_main!(benches);
