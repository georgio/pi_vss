use b_pi_s::{dealer::Dealer, party::generate_parties};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};

use common::{
    BENCH_K, BENCH_N_T,
    precompute::gen_powers,
    random::{random_point, random_scalars},
    secret_sharing::{
        generate_encrypted_shares_batched, reconstruct_secrets_exponent, select_qualified_set,
    },
    utils::{compute_lagrange_bases, ingest_public_keys},
};

use blake3::Hasher;

fn pvss(c: &mut Criterion) {
    // for k in BENCH_K {
    for k in [10] {
        for (n, t) in BENCH_N_T {
            let mut rng = rand::rng();
            let mut hasher = Hasher::new();
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

            let secrets = random_scalars(&mut rng, k);

            let (f_polynomials, f_evals) = generate_encrypted_shares_batched(
                t,
                &xpows,
                &parties[0].public_keys.as_ref().unwrap(),
                &secrets,
            );

            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_S PVSS | Dealer: Generate Proof",
                    k, n, t
                ),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64]),
                        |(mut hasher, mut buf)| {
                            dealer.generate_proof(
                                &mut rng,
                                &mut hasher,
                                &mut buf,
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
                dealer.deal_secrets(&mut rng, &mut hasher, &mut buf, &xpows, &secrets);

            for p in &mut parties {
                p.ingest_dealer_proof((&c_vals, &z)).unwrap();

                p.ingest_encrypted_shares(&shares).unwrap();

                let verif_result = p
                    .verify_encrypted_shares(&mut hasher, &mut buf, &xpows)
                    .unwrap();

                assert!(verif_result, "share verification failure");
            }
            c.bench_function(
                &format!(
                    "(k: {}, n: {}, t: {}) | B_Pi_S PVSS | Party: Verify Shares",
                    k, n, t
                ),
                |b| {
                    b.iter_batched(
                        || (blake3::Hasher::new(), [0u8; 64], parties[0].clone()),
                        |(mut hasher, mut buf, mut p0)| {
                            assert!(
                                p0.verify_encrypted_shares(&mut hasher, &mut buf, &xpows)
                                    .unwrap()
                            )
                        },
                        BatchSize::PerIteration,
                    )
                },
            );

            for p in &mut parties {
                assert!(
                    p.verify_encrypted_shares(&mut hasher, &mut buf, &xpows)
                        .unwrap(),
                    "share verification failure"
                );
            }
        }
    }
}

criterion_group!(benches, pvss);
criterion_main!(benches);
