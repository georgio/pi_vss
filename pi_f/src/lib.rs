pub mod dealer;
pub mod party;

#[cfg(test)]

mod tests {
    use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};

    use crate::{dealer::Dealer, party::generate_parties};

    use common::{
        random::{random_point, random_scalar},
        utils::compute_lagrange_bases,
    };

    #[test]
    fn end_to_end() {
        const N: usize = 128;
        const T: usize = 63;

        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64];

        let G: RistrettoPoint = random_point(&mut rng);
        let g1: RistrettoPoint = random_point(&mut rng);
        let g2: RistrettoPoint = random_point(&mut rng);

        let mut parties = generate_parties(&G, &g1, &g2, &mut rng, N, T);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(g1, g2, N, T, &public_keys).unwrap();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.ingest_public_keys(&public_keys).unwrap();
        }

        let secret = random_scalar(&mut rng);

        let (shares, (c_vals, z)) = dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &secret);

        for p in &mut parties {
            p.ingest_dealer_proof((&c_vals, &z)).unwrap();

            p.ingest_share(&shares[p.index - 1]);
            assert!(
                p.verify_share(&mut hasher, &mut buf).unwrap(),
                "share verification failure"
            );

            p.ingest_shares(&shares).unwrap();

            assert!(
                p.verify_shares(&mut hasher, &mut buf).unwrap(),
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

            let sec = p.reconstruct_secret(&lagrange_bases).unwrap();

            assert!(secret == sec, "Invalid Reconstructed Secret");
        }
    }
}
