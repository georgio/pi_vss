// use b_pi_s::{dealer::Dealer, party::generate_parties};
// use common::{
//     random::{random_point, random_scalars},
//     utils::compute_lagrange_bases,
// };
// use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};

// use rayon::prelude::*;

// fn main() {
//     const N: usize = 128;
//     const T: usize = 63;
//     const K: usize = 5;

//     let mut rng = rand::rng();
//     let mut hasher = blake3::Hasher::new();
//     let mut buf = [0u8; 64];

//     let G: RistrettoPoint = random_point(&mut rng);

//     let mut parties = generate_parties(&G, &mut rng, N, T);

//     let public_keys: Vec<CompressedRistretto> =
//         parties.iter().map(|party| party.public_key.0).collect();

//     let mut dealer = Dealer::new(N, T, &public_keys).unwrap();

//     for party in &mut parties {
//         let public_keys: Vec<CompressedRistretto> = public_keys
//             .iter()
//             .filter(|pk| &party.public_key.0 != *pk)
//             .copied()
//             .collect();

//         party.public_keys = Some(
//     ingest_public_keys(n, &party.public_key.1, party.index, &public_keys).unwrap(),
// );
//     }

//     let secrets = random_scalars(&mut rng, 5);

//     let (shares, (c_vals, z)) = dealer.deal_secrets_v2(&mut rng, &mut hasher, &mut buf, &secrets);

//     for p in &mut parties {
//         p.ingest_dealer_proof((&c_vals, &z)).unwrap();

//         p.ingest_share(&shares[p.index - 1]);
//         // assert!(
//         //     p.verify_share(&mut hasher, &mut buf).unwrap(),
//         //     "share verification failure"
//         // );

//         p.ingest_shares(&shares).unwrap();

//         assert!(
//             p.verify_shares(&mut hasher, &mut buf).unwrap(),
//             "others share verification failure"
//         );

//         p.qualified_set =
// Some(select_qualified_set(&mut rng, p.t, &p.shares, &p.validated_shares).unwrap());

//         let indices: Vec<usize> = p
//             .qualified_set
//             .as_ref()
//             .unwrap()
//             .iter()
//             .map(|(index, _)| *index)
//             .collect();

//         let lagrange_bases = compute_lagrange_bases(&indices);

//         let sec = reconstruct_secrets(&p.qualified_set, &lagrange_bases).unwrap();

//         assert!(secrets == sec, "Invalid Reconstructed Secret");
//     }
// }

fn main() {
    // const N: usize = 32;
    // const T: usize = 15;
    // const K: usize = 5;

    // let mut rng = rand::rng();
    // let mut hasher = blake3::Hasher::new();
    // let mut buf = [0u8; 64];

    // let G: RistrettoPoint = random_point(&mut rng);

    // let mut parties = generate_parties(&G, &mut rng, N, T);

    // let public_keys: Vec<CompressedRistretto> =
    //     parties.iter().map(|party| party.public_key.0).collect();

    // let mut dealer = Dealer::new(N, T, &public_keys).unwrap();

    // for party in &mut parties {
    //     let public_keys: Vec<CompressedRistretto> = public_keys
    //         .iter()
    //         .filter(|pk| &party.public_key.0 != *pk)
    //         .copied()
    //         .collect();

    //     party.public_keys = Some(
    //     ingest_public_keys(n, &party.public_key.1, party.index, &public_keys).unwrap(),
    // );
    // }

    // let secrets = random_scalars(&mut rng, 5);

    // // number of secrets to share
    // let k = secrets.len();

    // let (mut f_polynomials, f_evals) = dealer.generate_shares(k, &secrets);

    // let eval_bytes: Vec<Vec<u8>> = f_evals
    //     .par_iter()
    //     .flat_map(|f_eval| f_eval.par_iter().map(|eval| eval.as_bytes().to_vec()))
    //     .collect();

    // let mut c_buf = vec![[0u8; 64]; dealer.public_keys.len()];

    // dealer.deal_secrets(&mut rng, &mut hasher, &mut buf, &secrets);
    // let z = dealer.generate_proof_debug(
    //     &mut rng,
    //     &mut hasher,
    //     &mut buf,
    //     &mut c_buf,
    //     k,
    //     &mut f_polynomials,
    //     &f_evals,
    //     &eval_bytes,
    // );

    // dealer.deal_secrets_debug2(&mut rng, &mut hasher, &mut buf, &secrets);
}
