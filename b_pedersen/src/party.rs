use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand::{CryptoRng, RngCore, seq::SliceRandom};

use common::{
    error::{
        Error,
        ErrorKind::{
            CountMismatch, InsufficientShares, InvalidPararmeterSet, InvalidProof,
            PointDecompressionError, UninitializedValue,
        },
    },
    random::random_scalar,
    utils::batch_decompress_ristretto_points,
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct Party {
    pub g: Vec<RistrettoPoint>,
    pub g0: RistrettoPoint,
    pub private_key: Scalar,
    pub public_key: (CompressedRistretto, RistrettoPoint),
    pub index: usize,
    pub n: usize,
    pub t: usize,
    pub public_keys: Option<Vec<RistrettoPoint>>,
    pub dealer_proof: Option<(Vec<CompressedRistretto>, Vec<RistrettoPoint>)>,
    pub validated_shares: Vec<usize>,
    pub share: Option<(Vec<Scalar>, Scalar)>,
    pub d: Option<Scalar>,
    pub shares: Option<Vec<(Vec<Scalar>, Scalar)>>,
    pub qualified_set: Option<Vec<(usize, Vec<Scalar>)>>,
}

impl Party {
    pub fn new<R>(
        generator: &RistrettoPoint,
        g: Vec<RistrettoPoint>,
        g0: RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let private_key = random_scalar(rng);
        let public_key = generator * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                g: g.clone(),
                g0: g0.clone(),
                private_key,
                public_key: (public_key.compress(), public_key),
                index,
                n,
                t,
                dealer_proof: None,
                share: None,
                public_keys: None,
                validated_shares: vec![],
                d: None,
                shares: None,
                qualified_set: None,
            })
        } else {
            Err(InvalidPararmeterSet(n, t as isize, index).into())
        }
    }

    pub fn ingest_share(&mut self, share: (&Vec<Scalar>, &Scalar)) {
        assert!(share.0.len() == self.g.len());
        self.share = Some((share.0.clone(), share.1.clone()));
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

    pub fn ingest_dealer_proof(&mut self, proof: &Vec<CompressedRistretto>) -> Result<(), Error> {
        if proof.len() != self.t + 1 {
            Err(InvalidProof(format!("c_vals len: {}, t: {}", proof.len(), self.t + 1)).into())
        } else {
            let mut decompressed_c_vals = Vec::with_capacity(self.n);

            for c_i in proof {
                match c_i.decompress() {
                    Some(c) => decompressed_c_vals.push(c),
                    None => {
                        return Err(Error::from_kind(PointDecompressionError(format!(
                            "{c_i:?}",
                        ))));
                    }
                }
            }
            self.dealer_proof = Some((proof.clone(), decompressed_c_vals));
            Ok(())
        }
    }

    pub fn verify_share(&self) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((_, cvals)) => match &self.share {
                Some((fi, ri)) => {
                    let a = fi
                        .iter()
                        .zip(self.g.iter())
                        .map(|(fik, gk)| fik * gk)
                        .fold(self.g0 * ri, |acc, prod| acc + prod);

                    let b = cvals
                        .iter()
                        .enumerate()
                        .skip(1)
                        .map(|(t, c)| c * Scalar::from(self.index.pow(t as u32) as u64))
                        .fold(cvals[0], |acc, prod| acc + prod);

                    Ok(a == b)
                }
                None => Err(UninitializedValue("party.share").into()),
            },
            None => Err(UninitializedValue("party.dealer_proof").into()),
        }
    }

    pub fn verify_shares(&mut self) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((_, cvals)) => match &self.shares {
                Some(shares) => {
                    self.validated_shares = shares
                        .iter()
                        .enumerate()
                        .map(|(i, (fi, ri))| {
                            let a = fi
                                .iter()
                                .zip(self.g.iter())
                                .map(|(fik, gk)| fik * gk)
                                .fold(self.g0 * ri, |acc, prod| acc + prod);

                            let b = cvals
                                .iter()
                                .enumerate()
                                .skip(1)
                                .map(|(t, c)| c * Scalar::from(self.index.pow(t as u32) as u64))
                                .fold(cvals[0], |acc, prod| acc + prod);

                            if a == b {
                                println!("pass: {}", i + 1);
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
                None => Err(UninitializedValue("party.share").into()),
            },
            None => Err(UninitializedValue("party.dealer_proof").into()),
        }
    }

    pub fn ingest_shares(
        &mut self,
        shares: (&Vec<Vec<Scalar>>, &Vec<Scalar>),
    ) -> Result<(), Error> {
        if shares.0.len() == self.n && shares.1.len() == self.n {
            self.shares = Some(
                shares
                    .0
                    .clone()
                    .into_iter()
                    .zip(shares.1.clone().into_iter())
                    .collect(),
            );
            Ok(())
        } else {
            Err(CountMismatch(self.n, "parties", shares.0.len(), "ingestable shares").into())
        }
    }

    pub fn select_qualified_set<R>(&mut self, rng: &mut R) -> Result<(), Error>
    where
        R: CryptoRng + RngCore,
    {
        match &self.shares {
            Some(shares) => {
                if self.validated_shares.len() > self.t {
                    let mut tmp = self.validated_shares.clone();
                    tmp.shuffle(rng);
                    self.qualified_set = Some(
                        tmp.into_iter()
                            .take(self.t + 1)
                            .map(|x| (x + 1, shares[x].0.clone()))
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
    pub fn reconstruct_secrets(&self, lambdas: &Vec<Scalar>) -> Result<Vec<Scalar>, Error> {
        match &self.qualified_set {
            Some(qualified_set) => {
                let scaled_shares: Vec<Vec<Scalar>> = qualified_set
                    .par_iter()
                    .zip(lambdas.par_iter())
                    .map(|((_, poly_share), lambda)| {
                        poly_share.par_iter().map(|share| lambda * share).collect()
                    })
                    .collect();

                let mut out = vec![Scalar::ZERO; scaled_shares[0].len()];

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

pub fn generate_parties<R>(
    generator: &RistrettoPoint,
    g: &Vec<RistrettoPoint>,
    g0: &RistrettoPoint,
    rng: &mut R,
    n: usize,
    t: usize,
) -> Vec<Party>
where
    R: CryptoRng + RngCore,
{
    (1..=n)
        .map(|i| Party::new(generator, g.clone(), g0.clone(), rng, n, t, i).unwrap())
        .collect()
}
