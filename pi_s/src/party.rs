use blake3::Hasher;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::{
    error::{
        Error,
        ErrorKind::{CountMismatch, InvalidPararmeterSet, InvalidProof, UninitializedValue},
    },
    polynomial::Polynomial,
    utils::{batch_decompress_ristretto_points, verify_encrypted_shares_standalone},
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct Party {
    pub private_key: Scalar,
    pub public_key: (CompressedRistretto, RistrettoPoint),
    pub index: usize,
    pub n: usize,
    pub t: usize,
    pub share_proof: Option<(Scalar, Scalar)>,
    pub encrypted_share: Option<RistrettoPoint>,
    pub decrypted_share: Option<RistrettoPoint>,

    pub dealer_proof: Option<(Scalar, Polynomial)>,

    pub public_keys: Option<Vec<RistrettoPoint>>,
    pub encrypted_shares: Option<(Vec<CompressedRistretto>, Vec<RistrettoPoint>)>,
    pub decrypted_shares: Option<Vec<RistrettoPoint>>,
    pub share_proofs: Option<Vec<(Scalar, Scalar)>>,
    pub validated_shares: Vec<usize>,
    pub pk0: RistrettoPoint,
}

impl Party {
    pub fn new<R>(
        G: &RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
        pk0: RistrettoPoint,
    ) -> Result<Self, Error>
    where
        R: CryptoRngCore + ?Sized,
    {
        let private_key = Scalar::random(rng);
        let public_key = G * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                private_key,
                public_key: (public_key.compress(), public_key),
                index,
                n,
                t,
                dealer_proof: None,
                encrypted_share: None,
                decrypted_share: None,
                share_proof: None,
                share_proofs: None,
                encrypted_shares: None,
                decrypted_shares: None,
                public_keys: None,
                validated_shares: vec![],
                pk0,
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn ingest_encrypted_shares(
        &mut self,
        encrypted_shares: &[CompressedRistretto],
    ) -> Result<(), Error> {
        if encrypted_shares.len() == self.n + 1 {
            match batch_decompress_ristretto_points(encrypted_shares) {
                Ok(enc_shares) => {
                    self.encrypted_share = Some(enc_shares[self.index]);
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

    pub fn ingest_dealer_proof(&mut self, d: Scalar, z: Polynomial) -> Result<(), Error> {
        if d == Scalar::ZERO {
            Err(InvalidProof(format!("d == {d:?}",)).into())
        } else if z.len() != self.t + 1 {
            Err(InvalidProof(format!("z len: {}, t: {}", z.len(), self.t + 1)).into())
        } else {
            self.dealer_proof = Some((d, z));
            Ok(())
        }
    }

    pub fn ingest_decrypted_shares_and_proofs(
        &mut self,
        decrypted_shares: &[CompressedRistretto],
        proofs: Vec<(Scalar, Scalar)>,
    ) -> Result<(), Error> {
        if decrypted_shares.len() == self.n - 1 {
            if proofs.len() == decrypted_shares.len() {
                match batch_decompress_ristretto_points(decrypted_shares) {
                    Ok(mut dec_shares) => match (self.decrypted_share, self.share_proof) {
                        (Some(own_dec_share), Some(own_proof)) => {
                            dec_shares.insert(self.index - 1, own_dec_share);
                            self.decrypted_shares = Some(dec_shares);
                            let mut proofs = proofs;
                            proofs.insert(self.index - 1, own_proof);
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

    pub fn verify_encrypted_shares(
        &self,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((d, z)) => match (&self.encrypted_shares, &self.public_keys) {
                (Some(encrypted_shares), Some(public_keys)) => {
                    let mut new_pub_keys = public_keys.clone();
                    new_pub_keys.insert(0, self.pk0);
                    verify_encrypted_shares_standalone(
                        encrypted_shares,
                        &new_pub_keys,
                        (d, z),
                        hasher,
                        buf,
                    )
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

    pub fn decrypt_share(&mut self) -> Result<(), Error> {
        let inv_private_key = self.private_key.invert();
        match &self.encrypted_share {
            Some(encrypted_share) => {
                self.decrypted_share = Some(encrypted_share * inv_private_key);
                Ok(())
            }
            None => Err(UninitializedValue("party.encrypted_share").into()),
        }
    }
    pub fn dleq_share<R>(
        &mut self,
        G: &RistrettoPoint,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<(), Error>
    where
        R: CryptoRngCore + ?Sized,
    {
        match (&self.decrypted_share, &self.encrypted_share) {
            (Some(decrypted_share), Some(encrypted_share)) => {
                let r = Scalar::random(rng);

                let c1 = (G * &r).compress();
                let c2 = (decrypted_share * r).compress();

                hasher.update(self.public_key.0.as_bytes());
                hasher.update(encrypted_share.compress().as_bytes());
                hasher.update(c1.as_bytes());
                hasher.update(c2.as_bytes());

                hasher.finalize_xof().fill(buf);

                let d = Scalar::from_bytes_mod_order_wide(buf);
                let z = r + d * self.private_key;

                self.share_proof = Some((d, z));
                
                hasher.reset();
                buf.zeroize();
                
                Ok(())
            }
            (None, Some(_)) => Err(UninitializedValue("party.decrypted_share").into()),
            (Some(_), None) => Err(UninitializedValue("party.encrypted_shares").into()),
            (None, None) => {
                Err(UninitializedValue("party.{decrypted_share, encrypted_shares}").into())
            }
        }
    }

    pub fn verify_decrypted_shares(&mut self, G: &RistrettoPoint) -> Result<bool, Error> {
        match (&self.public_keys, &self.encrypted_shares) {
            (Some(public_keys), Some(enc_shares)) => {
                match (&self.decrypted_shares, &self.share_proofs) {
                    (Some(dec_shares), Some(proofs)) => {
                        self.validated_shares = dec_shares
                            .par_iter()
                            .zip(
                                proofs
                                    .par_iter()
                                    .zip(public_keys.par_iter().zip(enc_shares.1.par_iter().skip(1))),
                            )
                            .enumerate()
                            .map_init(
                                ||(blake3::Hasher::new(), [0u8;64]), | (hasher, buf),
                                (i, (dec_share, ((d, z), (public_key, enc_share)))) | {
                                    let num1 = G * z;
                                    let num2 = dec_share * z;

                                    let denom1 = public_key * d;
                                    let denom2 = enc_share * d;

                                    hasher.update(public_key.compress().as_bytes());
                                    hasher.update(enc_share.compress().as_bytes());
                                    hasher.update((num1 - denom1).compress().as_bytes());
                                    hasher.update((num2 - denom2).compress().as_bytes());
                                    hasher.finalize_xof().fill(buf);

                                    let reconstructed_d = Scalar::from_bytes_mod_order_wide(buf);

                                    hasher.reset();
                                    buf.zeroize();
                                    
                                    if *d == reconstructed_d {
                                        Some(i)
                                    } else {
                                        None
                                    }
                                },
                            ).filter(Option::is_some).map(|res| res.unwrap()).collect();
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
    pub fn reconstruct_secret_pessimistic(
        &self,
        lambdas: &Vec<Scalar>,
    ) -> Result<RistrettoPoint, Error> {
        match &self.decrypted_shares {
            Some(dec_shares) => Ok(self
                .validated_shares
                .par_iter()
                .take(self.t + 1)
                .map(|share_index| lambdas[*share_index] * dec_shares[*share_index])
                .sum()),
            None => Err(UninitializedValue("party.decrypted_shares").into()),
        }
    }
    pub fn reconstruct_secret_optimistic(&self, f0: &Scalar) -> Result<bool, Error> {
        let point = self.encrypted_shares.as_ref().unwrap().1[0];
        Ok(point.compress().decompress().unwrap()
            == (self.pk0 * f0).compress().decompress().unwrap())
    }
}
