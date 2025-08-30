use common::{
    precompute::gen_powers,
    random::{random_point, random_scalar},
    secret_sharing::{reconstruct_secret, select_qualified_set},
    utils::{compute_lagrange_bases, ingest_public_keys},
};
use curve25519_dalek::{RistrettoPoint, ristretto::CompressedRistretto};
use pi_la::{dealer::Dealer, party::generate_parties};

fn main() {
    const N: usize = 128;
    const T: usize = 63;

    let mut rng = rand::rng();
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64];

    let g: RistrettoPoint = random_point(&mut rng);

    let xpows = gen_powers(N, T);

    let mut parties = generate_parties(&g, &mut rng, N, T);

    let public_keys: Vec<CompressedRistretto> =
        parties.iter().map(|party| party.public_key.0).collect();

    let mut dealer = Dealer::new(N, T, &public_keys).unwrap();

    for party in &mut parties {
        let public_keys: Vec<CompressedRistretto> = public_keys
            .iter()
            .filter(|pk| &party.public_key.0 != *pk)
            .copied()
            .collect();

        party.public_keys =
            Some(ingest_public_keys(N, &party.public_key.1, party.index, &public_keys).unwrap());
    }

    let secret = random_scalar(&mut rng);

    let (shares, (c_vals, z)) =
        dealer.deal_secret(&mut rng, &mut hasher, &mut buf, &xpows, &secret);

    for p in &mut parties {
        p.ingest_dealer_proof((&c_vals, &z)).unwrap();

        p.ingest_share(&shares[p.index - 1]);
        assert!(
            p.verify_share(&mut hasher, &mut buf, &xpows).unwrap(),
            "share verification failure"
        );

        p.ingest_shares(&shares).unwrap();

        assert!(
            p.verify_shares(&mut hasher, &mut buf, &xpows).unwrap(),
            "others share verification failure"
        );

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

        let sec = reconstruct_secret(&p.qualified_set, &lagrange_bases).unwrap();

        assert!(secret == sec, "Invalid Reconstructed Secret");
    }
}
