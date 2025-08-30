pub mod dealer;
pub mod party;

#[cfg(test)]

mod tests {
    use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};

    use crate::{dealer::Dealer, party::generate_parties};

    use common::{
        precompute::gen_powers,
        random::{random_point, random_points, random_scalars},
        secret_sharing::{reconstruct_secrets, select_qualified_set},
        utils::{compute_lagrange_bases, ingest_public_keys},
    };

    #[test]
    fn end_to_end() {
        const N: usize = 16;
        const T: usize = 7;
        const K: usize = 3;

        let mut rng = rand::rng();

        let generator: RistrettoPoint = random_point(&mut rng);
        let g: Vec<RistrettoPoint> = random_points(&mut rng, K);

        let xpows = gen_powers(N, T);

        let mut parties = generate_parties(&generator, &g, &mut rng, N, T);

        let public_keys: Vec<CompressedRistretto> =
            parties.iter().map(|party| party.public_key.0).collect();

        let mut dealer = Dealer::new(g, N, T, &public_keys).unwrap();

        for party in &mut parties {
            let public_keys: Vec<CompressedRistretto> = public_keys
                .iter()
                .filter(|pk| &party.public_key.0 != *pk)
                .copied()
                .collect();

            party.public_keys = Some(
                ingest_public_keys(N, &party.public_key.1, party.index, &public_keys).unwrap(),
            );
        }

        let secrets = random_scalars(&mut rng, K);

        let (shares, c_vals) = dealer.deal_secret(&xpows, &secrets);

        for p in &mut parties {
            // if p.index == 1 {
            p.ingest_dealer_proof(&c_vals).unwrap();

            p.ingest_share(&shares[p.index - 1]);
            assert!(
                p.verify_share().unwrap(),
                "individual share verification failure"
            );
            println!("pass own share: {}", p.index);

            p.ingest_shares(&shares).unwrap();

            assert!(p.verify_shares().unwrap(), "share verification failure");

            p.qualified_set =
                Some(select_qualified_set(&mut rng, p.t, &p.shares, &p.validated_shares).unwrap());

            let indices: Vec<usize> = p
                .qualified_set
                .as_ref()
                .unwrap()
                .iter()
                .map(|(index, _)| *index)
                .collect();

            let lagrange_bases = compute_lagrange_bases(&indices);

            let sec = reconstruct_secrets(&p.qualified_set, &lagrange_bases).unwrap();

            assert!(secrets == sec, "Invalid Reconstructed Secret");
        }
    }
}
