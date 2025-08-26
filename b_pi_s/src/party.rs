use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity};
use rand::{CryptoRng, RngCore, seq::SliceRandom};
use zeroize::Zeroize;

use common::{
    error::{
        Error,
        ErrorKind::{
            CountMismatch, InsufficientShares, InvalidPararmeterSet, InvalidProof,
            UninitializedValue,
        },
    },
    polynomial::Polynomial,
    random::random_scalar,
    utils::{
        batch_decompress_batched_ristretto_points, batch_decompress_ristretto_points,
        compute_d_powers,
    },
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct Party {
    pub private_key: Scalar,
    pub public_key: (CompressedRistretto, RistrettoPoint),
    pub index: usize,
    pub n: usize,
    pub t: usize,
    pub public_keys: Option<Vec<RistrettoPoint>>,
    pub dealer_proof: Option<(Scalar, Polynomial)>,
    pub validated_shares: Vec<usize>,
    pub encrypted_share: Option<Vec<RistrettoPoint>>,
    pub decrypted_share: Option<Vec<RistrettoPoint>>,
    pub encrypted_shares: Option<(Vec<Vec<CompressedRistretto>>, Vec<Vec<RistrettoPoint>>)>,
    pub decrypted_shares: Option<Vec<Vec<RistrettoPoint>>>,
    pub share: Option<Vec<Scalar>>,
    pub share_proof: Option<Vec<(Scalar, Scalar)>>,
    pub share_proofs: Option<Vec<Vec<(Scalar, Scalar)>>>,
    pub shares: Option<Vec<Vec<Scalar>>>,
    pub qualified_set: Option<Vec<(usize, Vec<RistrettoPoint>)>>,
}

impl Party {
    pub fn new<R>(
        g: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let private_key = random_scalar(rng);
        let public_key = g * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                private_key,
                public_key: (public_key.compress(), public_key),
                index,
                n,
                t,
                dealer_proof: None,
                share: None,
                public_keys: None,
                validated_shares: vec![],
                encrypted_shares: None,
                decrypted_shares: None,
                encrypted_share: None,
                decrypted_share: None,
                share_proof: None,
                share_proofs: None,
                shares: None,
                qualified_set: None,
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn ingest_share(&mut self, share: &Vec<Scalar>) {
        self.share = Some(share.clone());
    }

    pub fn ingest_public_keys(&mut self, public_keys: &[CompressedRistretto]) -> Result<(), Error> {
        if public_keys.len() == self.n - 1 {
            match batch_decompress_ristretto_points(public_keys) {
                Ok(mut pks) => {
                    pks.insert(
                        self.index - 1,
                        self.public_key.1.compress().decompress().unwrap(),
                    );
                    self.public_keys = Some(pks);
                    Ok(())
                }
                Err(x) => Err(x),
            }
        } else {
            Err(CountMismatch(self.n, "parties", public_keys.len(), "public_keys").into())
        }
    }

    pub fn ingest_dealer_proof(&mut self, proof: (&Scalar, &Polynomial)) -> Result<(), Error> {
        if proof.1.len() != self.t + 1 {
            Err(InvalidProof(format!("z len: {}, t: {}", proof.1.len(), self.t)).into())
        } else {
            self.dealer_proof = Some((proof.0.clone(), proof.1.clone()));
            Ok(())
        }
    }

    pub fn verify_encrypted_shares(
        &mut self,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        x_pows: &Vec<Vec<Scalar>>,
    ) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((d, z)) => match (&self.encrypted_shares, &self.public_keys) {
                (Some(encrypted_shares), Some(public_keys)) => {
                    hasher.reset();
                    buf.zeroize();
                    let k = encrypted_shares.0[0].len();

                    let d_vals = compute_d_powers(k, d);

                    let z_evals = z.evaluate_range_precomp(x_pows, 1, public_keys.len());

                    let suite: Vec<CompressedRistretto> = z_evals
                        .iter()
                        .zip(public_keys.iter().zip(encrypted_shares.1.iter()))
                        .map(|(z_eval, (public_key, encrypted_shares_i))| {
                            ((z_eval * public_key)
                                - d_vals
                                    .iter()
                                    .zip(encrypted_shares_i)
                                    .map(|(d_val, encrypted_shares_i_k)| {
                                        encrypted_shares_i_k * d_val
                                    })
                                    // .reduce(|| RistrettoPoint::identity(), |acc, x| acc + x))
                                    .fold(RistrettoPoint::identity(), |acc, x| acc + x))
                            .compress()
                        })
                        .collect();

                    encrypted_shares
                        .0
                        .iter()
                        .flatten()
                        .chain(suite.iter())
                        .for_each(|x| {
                            hasher.update(x.as_bytes());
                        });

                    hasher.finalize_xof().fill(buf);
                    hasher.reset();

                    let d_comp = Scalar::from_bytes_mod_order_wide(buf);
                    buf.zeroize();

                    Ok(*d == d_comp)
                }
                (Some(_), None) => Err(UninitializedValue("party.public_keys").into()),
                (None, Some(_)) => Err(UninitializedValue("party.encrypted_shares").into()),
                (None, None) => {
                    Err(UninitializedValue("party.{encrypted_shares, public_keys}").into())
                }
            },
            None => Err(UninitializedValue("party.dealer_proof").into()),
        }
    }

    pub fn decrypt_shares(&mut self) -> Result<(), Error> {
        let inv_private_key = self.private_key.invert();
        match &self.encrypted_share {
            Some(encrypted_share) => {
                self.decrypted_share = Some(
                    encrypted_share
                        .par_iter()
                        .map(|enc_share| enc_share * inv_private_key)
                        .collect(),
                );
                Ok(())
            }
            None => Err(UninitializedValue("party.encrypted_share").into()),
        }
    }

    pub fn dleq_share<R>(
        &mut self,
        g: &RistrettoPoint,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<(), Error>
    where
        R: CryptoRng + RngCore,
    {
        match (&self.decrypted_share, &self.encrypted_share) {
            (Some(decrypted_shares), Some(encrypted_shares)) => {
                self.share_proof = Some(
                    decrypted_shares
                        .iter()
                        .zip(encrypted_shares)
                        .map(|(decrypted_share, encrypted_share)| {
                            let r = common::random::random_scalar(rng);
                            let c1 = (g * &r).compress();
                            let c2 = (decrypted_share * r).compress();

                            hasher.update(self.public_key.0.as_bytes());
                            hasher.update(encrypted_share.compress().as_bytes());
                            hasher.update(c1.as_bytes());
                            hasher.update(c2.as_bytes());

                            hasher.finalize_xof().fill(buf);

                            let d = Scalar::from_bytes_mod_order_wide(buf);
                            let z = r + d * self.private_key;
                            hasher.reset();
                            buf.zeroize();

                            (d, z)
                        })
                        .collect(),
                );

                Ok(())
            }
            (None, Some(_)) => Err(UninitializedValue("party.decrypted_share").into()),
            (Some(_), None) => Err(UninitializedValue("party.encrypted_shares").into()),
            (None, None) => {
                Err(UninitializedValue("party.{decrypted_share, encrypted_shares}").into())
            }
        }
    }

    pub fn ingest_encrypted_shares(
        &mut self,
        encrypted_shares: &Vec<Vec<CompressedRistretto>>,
    ) -> Result<(), Error> {
        if encrypted_shares.len() == self.n {
            match batch_decompress_batched_ristretto_points(encrypted_shares) {
                Ok(enc_shares) => {
                    self.encrypted_share = Some(enc_shares[self.index - 1].clone());
                    self.encrypted_shares = Some((encrypted_shares.to_vec(), enc_shares));
                    Ok(())
                }
                Err(x) => Err(x),
            }
        } else {
            Err(CountMismatch(
                self.n,
                "parties",
                encrypted_shares.len(),
                "encrypted shares",
            )
            .into())
        }
    }

    pub fn ingest_decrypted_shares_and_proofs(
        &mut self,
        decrypted_shares: &Vec<Vec<CompressedRistretto>>,
        proofs: Vec<Vec<(Scalar, Scalar)>>,
    ) -> Result<(), Error> {
        if decrypted_shares.len() == self.n - 1 {
            if proofs.len() == decrypted_shares.len() {
                match batch_decompress_batched_ristretto_points(decrypted_shares) {
                    Ok(mut dec_shares) => match (&self.decrypted_share, &self.share_proof) {
                        (Some(own_dec_share), Some(own_proof)) => {
                            dec_shares.insert(self.index - 1, own_dec_share.clone());
                            self.decrypted_shares = Some(dec_shares);
                            let mut proofs = proofs;
                            proofs.insert(self.index - 1, own_proof.clone());
                            self.share_proofs = Some(proofs);
                            Ok(())
                        }
                        (None, Some(_)) => Err(UninitializedValue("party.decrypted_share").into()),
                        (Some(_), None) => Err(UninitializedValue("party.share_proof").into()),
                        (None, None) => {
                            Err(UninitializedValue("party.{decrypted_share, share_proof}").into())
                        }
                    },
                    Err(x) => Err(x),
                }
            } else {
                Err(CountMismatch(self.n, "parties", proofs.len(), "proofs").into())
            }
        } else {
            Err(CountMismatch(
                self.n,
                "parties",
                decrypted_shares.len(),
                "decrypted shares",
            )
            .into())
        }
    }

    pub fn verify_decrypted_shares(&mut self, g: &RistrettoPoint) -> Result<bool, Error> {
        match (&self.public_keys, &self.encrypted_shares) {
            (Some(public_keys), Some(enc_shares)) => {
                match (&self.decrypted_shares, &self.share_proofs) {
                    (Some(dec_shares), Some(proofs)) => {
                        self.validated_shares = dec_shares
                            .par_iter()
                            .zip(
                                proofs
                                    .par_iter()
                                    .zip(public_keys.par_iter().zip(enc_shares.1.par_iter())),
                            )
                            .enumerate()
                            .map(|(i, (dec_share, (proof, (public_key, enc_share))))| {
                                if dec_share
                                    .par_iter()
                                    .zip(proof.par_iter().zip(enc_share.par_iter()))
                                    .map_init(
                                        || (blake3::Hasher::new(), [0u8; 64]),
                                        |(hasher, buf), (dec_share_k, ((d, z), enc_share_k))| {
                                            let num1 = g * z;
                                            let num2 = dec_share_k * z;

                                            let denom1 = public_key * d;
                                            let denom2 = enc_share_k * d;

                                            hasher.update(public_key.compress().as_bytes());
                                            hasher.update(enc_share_k.compress().as_bytes());
                                            hasher.update((num1 - denom1).compress().as_bytes());
                                            hasher.update((num2 - denom2).compress().as_bytes());
                                            hasher.finalize_xof().fill(buf);

                                            let reconstructed_d =
                                                Scalar::from_bytes_mod_order_wide(buf);

                                            hasher.reset();
                                            buf.zeroize();

                                            *d == reconstructed_d
                                        },
                                    )
                                    .reduce(|| true, |acc, res| acc && res)
                                {
                                    Some(i)
                                } else {
                                    None
                                }
                            })
                            .filter(Option::is_some)
                            .map(|res| res.unwrap())
                            .collect();
                        Ok(self.validated_shares.len() > self.t)
                    }
                    (None, Some(_)) => Err(UninitializedValue("party.decrypted_shares").into()),
                    (Some(_), None) => Err(UninitializedValue("party.share_proofs").into()),
                    (None, None) => {
                        Err(UninitializedValue("party.{decrypted_shares, share_proofs}").into())
                    }
                }
            }
            (None, Some(_)) => Err(UninitializedValue("party.encrypted_shares").into()),
            (Some(_), None) => Err(UninitializedValue("party.public_keys").into()),
            (None, None) => Err(UninitializedValue("party.{public_keys, encrypted_shares}").into()),
        }
    }

    pub fn select_qualified_set<R>(&mut self, rng: &mut R) -> Result<(), Error>
    where
        R: CryptoRng + RngCore,
    {
        match &self.decrypted_shares {
            Some(shares) => {
                if self.validated_shares.len() > self.t {
                    let mut tmp = self.validated_shares.clone();
                    tmp.shuffle(rng);
                    self.qualified_set = Some(
                        tmp.into_iter()
                            .take(self.t + 1)
                            .map(|x| (x + 1, shares[x].clone()))
                            .collect(),
                    );
                    Ok(())
                } else {
                    Err(InsufficientShares(self.validated_shares.len(), self.t).into())
                }
            }
            None => Err(UninitializedValue("party.decrypted_shares").into()),
        }
    }
    // pub fn reconstruct_secrets(&self, lambdas: &Vec<Scalar>) -> Result<Vec<RistrettoPoint>, Error> {
    //     match &self.qualified_set {
    //         Some(qualified_set) => {
    //             let out: Vec<RistrettoPoint> = qualified_set
    //                 .par_iter()
    //                 .zip(lambdas.par_iter())
    //                 .map(|((_, poly_share), lambda)| {
    //                     poly_share
    //                         .par_iter()
    //                         .map(|share| lambda * share)
    //                         .reduce(|| RistrettoPoint::identity(), |acc, s| acc + s)
    //                 })
    //                 .collect();

    //             Ok(out)
    //         }
    //         None => Err(UninitializedValue("party.qualified_set").into()),
    //     }
    // }
    pub fn reconstruct_secrets(&self, lambdas: &Vec<Scalar>) -> Result<Vec<RistrettoPoint>, Error> {
        match &self.qualified_set {
            Some(qualified_set) => {
                let scaled_shares: Vec<Vec<RistrettoPoint>> = qualified_set
                    .par_iter()
                    .zip(lambdas.par_iter())
                    .map(|((_, poly_share), lambda)| {
                        poly_share.par_iter().map(|share| lambda * share).collect()
                    })
                    .collect();

                let mut out = vec![RistrettoPoint::identity(); scaled_shares[0].len()];

                for k in 0..(&scaled_shares[0]).len() {
                    for share in &scaled_shares {
                        out[k] += share[k];
                    }
                }

                Ok(out)
            }
            None => Err(UninitializedValue("party.qualified_set").into()),
        }
    }
}

pub fn generate_parties<R>(g: &RistrettoPoint, rng: &mut R, n: usize, t: usize) -> Vec<Party>
where
    R: CryptoRng + RngCore,
{
    (1..=n)
        .map(|i| Party::new(g, rng, n, t, i).unwrap())
        .collect()
}
