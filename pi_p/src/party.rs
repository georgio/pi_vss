use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rand::{CryptoRng, RngCore, seq::SliceRandom};
use zeroize::Zeroize;

use common::{
    error::{
        Error,
        ErrorKind::{
            CountMismatch, InsufficientShares, InvalidPararmeterSet, InvalidProof,
            PointDecompressionError, UninitializedValue,
        },
    },
    polynomial::Polynomial,
    random::random_scalar,
    utils::batch_decompress_ristretto_points,
};
use rayon::prelude::*;

#[derive(Clone)]
pub struct Party {
    pub g1: RistrettoPoint,
    pub g2: RistrettoPoint,
    pub g3: RistrettoPoint,
    pub private_key: Scalar,
    pub public_key: (CompressedRistretto, RistrettoPoint),
    pub index: usize,
    pub n: usize,
    pub t: usize,
    pub public_keys: Option<Vec<RistrettoPoint>>,
    pub dealer_proof: Option<(Vec<CompressedRistretto>, Vec<RistrettoPoint>, Polynomial)>,
    pub validated_shares: Vec<usize>,
    // (f_i, gamma_i)
    pub share: Option<(Scalar, Scalar)>,
    pub d: Option<Scalar>,
    pub shares: Option<Vec<(Scalar, Scalar)>>,
    pub qualified_set: Option<Vec<(usize, Scalar)>>,
}

impl Party {
    pub fn new<R>(
        G: &RistrettoPoint,
        g1: RistrettoPoint,
        g2: RistrettoPoint,
        g3: RistrettoPoint,
        rng: &mut R,
        n: usize,
        t: usize,
        index: usize,
    ) -> Result<Self, Error>
    where
        R: CryptoRng + RngCore,
    {
        let private_key = random_scalar(rng);
        let public_key = G * &private_key;

        if index <= n && t < n && t as f32 == ((n - 1) as f32 / 2.0).floor() {
            Ok(Self {
                g1: g1.clone(),
                g2: g2.clone(),
                g3: g3.clone(),
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

    pub fn ingest_share(&mut self, share: (&Scalar, &Scalar)) {
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

    pub fn ingest_dealer_proof(
        &mut self,
        proof: (&Vec<CompressedRistretto>, &Polynomial),
    ) -> Result<(), Error> {
        if proof.1.len() != self.t + 1 {
            Err(InvalidProof(format!("z len: {}, t: {}", proof.1.len(), self.t + 1)).into())
        } else if proof.0.len() != self.n {
            Err(InvalidProof(format!("c_vals len: {}, n: {}", proof.0.len(), self.n)).into())
        } else {
            let mut decompressed_c_vals = Vec::with_capacity(self.n);

            for c_i in proof.0 {
                match c_i.decompress() {
                    Some(c) => decompressed_c_vals.push(c),
                    None => {
                        return Err(Error::from_kind(PointDecompressionError(format!(
                            "{c_i:?}",
                        ))));
                    }
                }
            }
            self.dealer_proof = Some((proof.0.clone(), decompressed_c_vals, proof.1.clone()));
            Ok(())
        }
    }

    pub fn verify_share(&self, hasher: &mut Hasher, buf: &mut [u8; 64]) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((compressed_cvals, cvals, z)) => match &self.share {
                Some((f_i, g_i)) => {
                    let flat_vec: Vec<u8> =
                        compressed_cvals.iter().flat_map(|x| x.to_bytes()).collect();

                    hasher.update(flat_vec.as_slice());

                    hasher.finalize_xof().fill(buf);

                    let d = Scalar::from_bytes_mod_order_wide(buf);
                    hasher.reset();
                    buf.zeroize();

                    let expected_c = cvals[self.index - 1];

                    let c = self.g1 * f_i
                        + self.g2 * (z.evaluate(self.index) - d * f_i)
                        + self.g3 * g_i;

                    Ok(expected_c == c)
                }
                None => Err(UninitializedValue("party.share").into()),
            },
            None => Err(UninitializedValue("party.dealer_proof").into()),
        }
    }

    pub fn verify_shares(
        &mut self,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
    ) -> Result<bool, Error> {
        match &self.dealer_proof {
            Some((compressed_cvals, cvals, z)) => match &self.shares {
                Some(shares) => {
                    let flat_vec: Vec<u8> =
                        compressed_cvals.iter().flat_map(|x| x.to_bytes()).collect();

                    hasher.update(flat_vec.as_slice());

                    hasher.finalize_xof().fill(buf);

                    let d = Scalar::from_bytes_mod_order_wide(buf);
                    hasher.reset();
                    buf.zeroize();

                    self.validated_shares = shares
                        .par_iter()
                        .enumerate()
                        .map(|(i, (f_i, g_i))| {
                            if cvals[i]
                                == self.g1 * f_i
                                    + self.g2 * (z.evaluate(i + 1) - d * f_i)
                                    + self.g3 * g_i
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
                None => Err(UninitializedValue("party.share").into()),
            },
            None => Err(UninitializedValue("party.dealer_proof").into()),
        }
    }

    pub fn ingest_shares(&mut self, shares: &(Vec<Scalar>, Vec<Scalar>)) -> Result<(), Error> {
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
                            .map(|x| (x + 1, shares[x].0))
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
    pub fn reconstruct_secret(&self, lambdas: &Vec<Scalar>) -> Result<Scalar, Error> {
        match &self.qualified_set {
            Some(qualified_set) => Ok(qualified_set
                .par_iter()
                .zip(lambdas.par_iter())
                .map(|((_, decrypted_share), lambda)| lambda * decrypted_share)
                .sum()),
            None => Err(UninitializedValue("party.qualified_set").into()),
        }
    }
}

pub fn generate_parties<R>(
    G: &RistrettoPoint,
    g1: &RistrettoPoint,
    g2: &RistrettoPoint,
    g3: &RistrettoPoint,
    rng: &mut R,
    n: usize,
    t: usize,
) -> Vec<Party>
where
    R: CryptoRng + RngCore,
{
    (1..=n)
        .map(|i| Party::new(G, g1.clone(), g2.clone(), g3.clone(), rng, n, t, i).unwrap())
        .collect()
}
