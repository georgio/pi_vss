use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto, scalar::Scalar};
use pi_p::{
    dealer::Dealer,
    utils::{generate_parties, precompute_lambda},
};
use rand::{SeedableRng, thread_rng};
use rand_chacha::ChaChaRng;

fn main() {
    // const N: usize = 33;
    // const T: usize = 16;

    // let mut rng = ChaChaRng::from_rng(thread_rng()).unwrap();
    // let mut hasher = blake3::Hasher::new();
    // let mut buf = [0u8; 64];

    // let G: RistrettoPoint = RistrettoPoint::mul_base(&Scalar::random(&mut rng));
    // let lambdas = precompute_lambda(N, T);

    // let pk0 = RistrettoPoint::random(&mut rng);

    // let mut parties = generate_parties(&G, &mut rng, N, T, &pk0);

    // let public_keys: Vec<CompressedRistretto> =
    //     parties.iter().map(|party| party.public_key.0).collect();

    // let mut dealer = Dealer::new(N, T, &public_keys, &pk0).unwrap();

    // for party in &mut parties {
    //     let public_keys: Vec<CompressedRistretto> = public_keys
    //         .iter()
    //         .filter(|pk| &party.public_key.0 != *pk)
    //         .copied()
    //         .collect();

    //     party.ingest_public_keys(&public_keys).unwrap();
    // }

    // let secret = Scalar::random(&mut rng);

    // let (encrypted_shares, (d, z)) = dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &secret);

    // for p in &mut parties {
    //     p.ingest_encrypted_shares(&encrypted_shares).unwrap();
    //     p.ingest_dealer_proof(d, z.clone()).unwrap();

    //     let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

    //     assert!(res, "encrypted share verification failure");
    // }

    // let (decrypted_shares, share_proofs): (Vec<CompressedRistretto>, Vec<(Scalar, Scalar)>) =
    //     parties
    //         .iter_mut()
    //         .map(|p| {
    //             p.decrypt_share().unwrap();
    //             p.dleq_share(&G, &mut rng, &mut hasher, &mut buf).unwrap();
    //             (
    //                 p.decrypted_share.unwrap().compress(),
    //                 p.share_proof.unwrap(),
    //             )
    //         })
    //         .collect();

    // let mut reconstructed_secrets: Vec<RistrettoPoint> = vec![];
    // for p in &mut parties {
    //     let (mut decrypted_shares, mut share_proofs) =
    //         (decrypted_shares.clone(), share_proofs.clone());

    //     decrypted_shares.remove(p.index - 1);
    //     share_proofs.remove(p.index - 1);
    //     p.ingest_decrypted_shares_and_proofs(&decrypted_shares, share_proofs)
    //         .unwrap();

    //     p.verify_decrypted_shares(&G).unwrap();

    //     reconstructed_secrets.push(p.reconstruct_secret_pessimistic(&lambdas).unwrap());
    // }
}
