pub mod dealer;
pub mod party;

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

    use crate::{dealer::Dealer, party::generate_parties};

    use common::{precompute::gen_powers, utils::compute_lagrange_bases};

    #[test]
    fn end_to_end() {
        const N: usize = 128;
        const T: usize = 63;

        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64];

        let G: RistrettoPoint = RistrettoPoint::mul_base(&common::random::random_scalar(&mut rng));
        let xpows = gen_powers(N, T);

        let mut parties = generate_parties(&G, &mut rng, N, T);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(N, T, &public_keys).unwrap();

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.ingest_public_keys(&public_keys).unwrap();
        }

        let secret = common::random::random_scalar(&mut rng);
        let (encrypted_shares, (d, z)) =
            dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secret);

        for p in &mut parties {
            p.ingest_encrypted_shares(&encrypted_shares).unwrap();
            p.ingest_dealer_proof(d, z.clone()).unwrap();

            let res = p.verify_encrypted_shares(&mut hasher, &mut buf).unwrap();

            assert!(res, "encrypted share verification failure");
        }

        let (decrypted_shares, share_proofs): (Vec<CompressedRistretto>, Vec<(Scalar, Scalar)>) =
            parties
                .iter_mut()
                .map(|p| {
                    p.decrypt_share().unwrap();
                    p.dleq_share(&G, &mut rng, &mut hasher, &mut buf).unwrap();

                    (
                        p.decrypted_share.unwrap().compress(),
                        p.share_proof.unwrap(),
                    )
                })
                .collect();

        let mut reconstructed_secrets: Vec<RistrettoPoint> = vec![];
        for p in &mut parties {
            let (mut decrypted_shares, mut share_proofs) =
                (decrypted_shares.clone(), share_proofs.clone());

            decrypted_shares.remove(p.index - 1);
            share_proofs.remove(p.index - 1);
            p.ingest_decrypted_shares_and_proofs(&decrypted_shares, share_proofs)
                .unwrap();

            assert!(p.verify_decrypted_shares(&G).unwrap());

            p.select_qualified_set(&mut rng).unwrap();

            let indices: Vec<usize> = p
                .qualified_set
                .as_ref()
                .unwrap()
                .iter()
                .map(|(index, _)| *index)
                .collect();

            let lagrange_bases = compute_lagrange_bases(&indices);

            reconstructed_secrets.push(p.reconstruct_secret(&lagrange_bases).unwrap());
        }
        reconstructed_secrets
            .iter()
            .for_each(|secret| assert_eq!(G * dealer.secret.unwrap(), *secret));
    }
}
