use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};
use pi_s::{
    dealer::Dealer,
    error::ErrorKind::PointDecompressionError,
    utils::{generate_parties, precompute_lambda},
};

use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;

fn pvss(c: &mut Criterion) {
    for (n, t) in [
        (64, 31),
        (128, 63),
        (256, 127),
        (512, 255),
        (1024, 511),
        (2048, 1023),
    ] {
        let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut buf: [u8; 64] = [0u8; 64];

        let G: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));

        let lambdas = precompute_lambda(n, t);

        let pk0 = RistrettoPoint::random(&mut rng);

        let mut parties = generate_parties(&G, &mut rng, n, t, &pk0);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(n, t, &public_keys, &pk0).unwrap();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.ingest_public_keys(&public_keys).unwrap();
        }

        let secret = Scalar::random(&mut rng);
        let (encrypted_shares, (d, z)) =
            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &secret);

        c.bench_function(
            &format!("(n: {}, t: {}) | Pi_S PPVSS | Dealer: Deal Secret", n, t),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &secret)
                    },
                    BatchSize::PerIteration,
                )
            },
        );

        for p in &mut parties {
            p.ingest_encrypted_shares(&encrypted_shares).unwrap();
            p.ingest_dealer_proof(d, z.clone()).unwrap();

            // let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

            // assert!(res, "encrypted share verification failure");
        }

        c.bench_function(
            &format!(
                "(n: {}, t: {}) | Pi_S PPVSS | Party: Verify Encrypted Shares",
                n, t
            ),
            |b| {
                b.iter_batched(
                    || (blake3::Hasher::new(), [0u8; 64]),
                    |(mut hasher, mut buf)| {
                        assert!(parties[0]
                            .verify_encrypted_shares(&mut hasher, &mut buf)
                            .unwrap())
                    },
                    BatchSize::PerIteration,
                )
            },
        );

        //     let (decrypted_shares, share_proofs): (Vec<CompressedRistretto>, Vec<(Scalar, Scalar)>) =
        //         parties
        //             .iter_mut()
        //             .map(|p| {
        //                 p.decrypt_share().unwrap();
        //                 p.dleq_share(&G, &mut rng, &mut hasher, &mut buf).unwrap();
        //                 (
        //                     p.decrypted_share.unwrap().compress(),
        //                     p.share_proof.unwrap(),
        //                 )
        //             })
        //             .collect();

        //     c.bench_function(
        //         &format!("(n: {}, t: {}) | Pi_S PPVSS | Party: Decrypt Share", n, t),
        //         |b| b.iter(|| parties[0].decrypt_share().unwrap()),
        //     );

        //     c.bench_function(
        //         &format!("(n: {}, t: {}) | Pi_S PPVSS |  Party: Generate Proof", n, t),
        //         |b| {
        //             b.iter_batched(
        //                 || (blake3::Hasher::new(), [0u8; 64]),
        //                 |(mut hasher, mut buf)| {
        //                     parties[0]
        //                         .dleq_share(&G, &mut rng, &mut hasher, &mut buf)
        //                         .unwrap()
        //                 },
        //                 BatchSize::PerIteration,
        //             )
        //         },
        //     );

        //     for p in &mut parties {
        //         let (mut decrypted_shares, mut share_proofs) =
        //             (decrypted_shares.clone(), share_proofs.clone());

        //         decrypted_shares.remove(p.index - 1);
        //         share_proofs.remove(p.index - 1);
        //         p.ingest_decrypted_shares_and_proofs(&decrypted_shares, share_proofs)
        //             .unwrap();
        //     }

        //     c.bench_function(
        //         &format!("(n: {}, t: {}) | Pi_S PPVSS | Party: Verify Decrypted Shares", n, t),
        //         |b| {
        //             b.iter(|| {
        //                 parties[0].verify_decrypted_shares(&G).unwrap();
        //             })
        //         },
        //     );

        //     c.bench_function(
        //         &format!(
        //             "(n: {}, t: {}) | Pi_S PPVSS | Party: Reconstruct Secret - Pessimistic",
        //             n, t
        //         ),
        //         |b| {
        //             b.iter(|| {
        //                 parties[0].reconstruct_secret_pessimistic(&lambdas).unwrap();
        //             })
        //         },
        //     );
        //     c.bench_function(
        //         &format!(
        //             "(n: {}, t: {}) | Pi_S PPVSS | Party: Reconstruct Secret - Optimistic",
        //             n, t
        //         ),
        //         |b| {
        //             b.iter(|| {
        //                 parties[0]
        //                     .reconstruct_secret_optimistic(&dealer.publish_f0())
        //                     .unwrap();
        //             })
        //         },
        //     );
    }
}

fn ristretto_point_bench(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
    let x = Scalar::random(&mut rng);
    let G: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));

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

criterion_group!(benches, pvss, ristretto_point_bench,);
criterion_main!(benches);
