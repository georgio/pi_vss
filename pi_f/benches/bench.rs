use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};
use pi_f::{dealer::Dealer, party::generate_parties};

use common::{
    BENCH_N_T,
    precompute::gen_powers,
    random::{random_point, random_scalar},
    utils::ingest_public_keys,
};

fn pvss(c: &mut Criterion) {
    for (n, t) in BENCH_N_T {
        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let g: RistrettoPoint = random_point(&mut rng);
        let g1: RistrettoPoint = random_point(&mut rng);
        let g2: RistrettoPoint = random_point(&mut rng);

        let xpows = gen_powers(n, t);

        let mut parties = generate_parties(&g, &g1, &g2, &mut rng, n, t);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(g1, g2, n, t, &public_keys).unwrap();

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

        let (shares, (c_vals, z)) =
            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secret);

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_P PVSS | Dealer: Deal Secret", n, t),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secret)
                    },
                    BatchSize::PerIteration,
                )
            },
        );

        for p in &mut parties {
            p.ingest_shares(&shares).unwrap();
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
    }
}

criterion_group!(benches, pvss);
criterion_main!(benches);
