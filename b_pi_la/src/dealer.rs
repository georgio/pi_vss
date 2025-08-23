use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::{batch_decompress_ristretto_points, compute_d_powers_from_commitments},
};
use rand::{CryptoRng, RngCore};

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use rayon::prelude::*;

pub struct Dealer {
    pub t: usize,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secrets: Option<Vec<Scalar>>,
}

impl Dealer {
    pub fn new(n: usize, t: usize, public_keys: &[CompressedRistretto]) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(pks) => Ok(Self {
                t,
                public_keys: pks,
                secrets: None,
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Vec<Scalar> {
        self.secrets.clone().unwrap()
    }

    // pub fn deal_secrets<R>(
    //     &mut self,
    //     rng: &mut R,
    //     hasher: &mut Hasher,
    //     buf: &mut [u8; 64],
    //     secrets: &Vec<Scalar>,
    // ) -> (Vec<Vec<Scalar>>, (Vec<Vec<u8>>, Polynomial))
    // where
    //     R: CryptoRng + RngCore,
    // {
    //     let k = secrets.len();

    //     // This contains k*f polynomials + 1*r polynomial
    //     let mut polynomials = Polynomial::sample_n_set_f0(k, self.t, secrets).unwrap();

    //     let r = Polynomial::sample(self.t, rng);

    //     polynomials.push(r);

    //     // evals is vec[vec[k+1]; n]
    //     let mut evals = Polynomial::evaluate_many_range(&polynomials, 1, self.public_keys.len());

    //     // number of secrets to share
    //     let k = secrets.len();

    //     let c_vals: Vec<Vec<u8>> = (0..self.public_keys.len())
    //         .into_par_iter()
    //         .map_init(
    //             || Hasher::new(),
    //             |l_hasher, i| {
    //                 let mut l_buf = vec![0u8; 64];
    //                 evals[i].iter().for_each(|poly_eval| {
    //                     // this includes hashing r_i
    //                     l_hasher.update(poly_eval.as_bytes());
    //                 });

    //                 // l_hasher.update(ri.as_bytes());
    //                 l_hasher.finalize_xof().fill(&mut l_buf);
    //                 l_hasher.reset();
    //                 l_buf
    //             },
    //         )
    //         .collect();

    //     let flat_vec: Vec<u8> = c_vals.clone().into_iter().flatten().collect();

    //     hasher.update(&flat_vec);
    //     hasher.finalize_xof().fill(buf);

    //     let d = Scalar::from_bytes_mod_order_wide(buf);
    //     buf.zeroize();
    //     hasher.reset();

    //     let mut d_vals = Vec::with_capacity(k);
    //     // [d^1,
    //     d_vals.push(d);
    //     // d^2, d^3, ... d^k]
    //     for i in 1..k {
    //         d_vals.push(d_vals[i - 1] * d);
    //     }

    //     let mut r = polynomials.pop().unwrap();

    //     // d_j * f_j
    //     polynomials
    //         .par_iter_mut()
    //         .zip(d_vals.par_iter())
    //         .for_each(|(poly, d_val)| {
    //             poly.coef_op_in_place(Scalar::mul, d_val);
    //         });

    //     // z = r + ( ∑ d_j * f_j )
    //     r.fold_op_into(Scalar::add, &polynomials);

    //     evals.par_iter_mut().for_each(|eval_i| {
    //         eval_i.pop().unwrap();
    //     });

    //     (evals, (c_vals, r))
    // }

    pub fn deal_secrets_v2<R>(
        &mut self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        secrets: &Vec<Scalar>,
    ) -> (Vec<Vec<Scalar>>, (Vec<[u8; 64]>, Polynomial))
    where
        R: CryptoRng + RngCore,
    {
        // number of secrets to share
        let k = secrets.len();

        let (mut f_polynomials, f_evals) = self.generate_shares(k, secrets);

        let mut c_buf = vec![[0u8; 64]; self.public_keys.len()];

        let z = self.generate_proof(
            rng,
            hasher,
            buf,
            &mut c_buf,
            k,
            &mut f_polynomials,
            &f_evals,
        );

        (f_evals, (c_buf, z))
    }

    pub fn generate_shares(
        &self,
        k: usize,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Polynomial>, Vec<Vec<Scalar>>) {
        // This contains k * f_polynomial
        let f_polynomials = Polynomial::sample_n_set_f0(k, self.t, secrets).unwrap();
        // evals is vec[vec[k]; n]
        let f_evals = Polynomial::evaluate_many_range(&f_polynomials, 1, self.public_keys.len());

        (f_polynomials, f_evals)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        hasher: &mut Hasher,
        buf: &mut [u8; 64],
        c_buf: &mut Vec<[u8; 64]>,
        k: usize,
        f_polynomials: &Vec<Polynomial>,
        f_evals: &Vec<Vec<Scalar>>,
    ) -> Polynomial
    where
        R: CryptoRng,
    {
        let mut r = Polynomial::sample(self.t, rng);

        let r_evals = Polynomial::evaluate_range(&r, 1, self.public_keys.len());

        c_buf
            .par_iter_mut()
            .zip(f_evals.par_iter().zip(r_evals.par_iter()))
            .for_each_init(
                || Hasher::new(),
                |l_hasher, (l_buf, (fi, ri))| {
                    fi.iter().for_each(|fi_k| {
                        l_hasher.update(fi_k.as_bytes());
                    });

                    l_hasher.update(ri.as_bytes());

                    l_hasher.finalize_xof().fill(l_buf);
                    l_hasher.reset();
                },
            );

        // [d, d^2, ..., d^k]
        let d_vals = compute_d_powers_from_commitments(hasher, buf, &c_buf, k);

        // z == r += ( ∑ d_j * f_j )
        r.compute_z(f_polynomials, &d_vals);

        r
    }
}

#[cfg(test)]
mod test {
    use common::{
        error::{Error, ErrorKind::CountMismatch},
        polynomial::Polynomial,
        random::random_scalars,
        utils::batch_decompress_ristretto_points,
    };
    use rand::{CryptoRng, RngCore};
    use rayon::prelude::*;

    use blake3::Hasher;
    use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

    use crate::{dealer::Dealer, party::generate_parties};
    use common::{random::random_point, utils::compute_lagrange_bases};

    use zeroize::Zeroize;
    #[test]
    fn test_proof() {
        const N: usize = 8;
        const T: usize = 3;
        const K: usize = 1;

        let mut rng = rand::rng();
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64];
        let mut c_buf = vec![[0u8; 64]; N];

        // begin deal secret
        let secrets = random_scalars(&mut rng, K);

        // This contains k*f polynomials
        let f_polynomials = Polynomial::sample_n_set_f0(K, T, &secrets).unwrap();

        let f_evals = Polynomial::evaluate_many_range(&f_polynomials, 1, N);

        // end deal_secret

        // begin proof

        let r = Polynomial::sample(T, &mut rng);

        println!("t: {}", T);
        println!("{}", r.coef_ref().len());
        println!("{}", f_polynomials[0].coef_ref().len());
        // let r_evals = Polynomial::evaluate_range(&r, 1, N);
        let r_evals = Polynomial::evaluate_range(&r, 1, N);

        println!("{}", r_evals.len());
        println!("{}", f_evals.len());
        for i in 0..N {
            assert_eq!(r_evals[i], r.evaluate(i + 1));
            assert_eq!(f_evals[i][0], f_polynomials[0].evaluate(i + 1));
        }

        println!("{:?}\n\n\n----------", r_evals);
        println!("{:?}\n\n\n----------", f_evals);

        let mut l_hasher = Hasher::new();

        c_buf
            .iter_mut()
            .zip(f_evals.iter().enumerate().zip(r_evals.iter()))
            .for_each(|(l_buf, ((i, fi), ri))| {
                fi.iter().enumerate().for_each(|(k, fi_k)| {
                    // if i == 17 {
                    println!("f_{}_{}: {:?}", i, k, fi_k);
                    // }
                    l_hasher.update(fi_k.as_bytes());
                });
                l_hasher.update(ri.as_bytes());

                println!("r_{}: {:?}", i, ri);

                l_hasher.finalize_xof().fill(l_buf);
                l_hasher.reset();
                // println!("l_buf{}: {:?} ", i, l_buf);
            });

        let flat_vec: Vec<u8> = c_buf.clone().into_iter().flatten().collect();

        hasher.update(&flat_vec);
        hasher.finalize_xof().fill(&mut buf);

        let d = Scalar::from_bytes_mod_order_wide(&mut buf);
        buf.zeroize();
        hasher.reset();

        let mut d_vals = Vec::with_capacity(K);
        // [d^1,
        d_vals.push(d);
        // d^2, d^3, ... d^k]
        for i in 1..K {
            d_vals.push(d_vals[i - 1] * d);
        }

        println!("dvals: {:?}", d_vals);

        // z = r + ( ∑ d_j * f_j )
        let mut z = r.clone();
        z.compute_z(&f_polynomials, &d_vals);

        println!("z: {:?}", z.coef_ref());
        println!("-----ok-----");

        // end generate proof

        // begin verification

        let z_evals = Polynomial::evaluate_range(&z, 1, N);
        let shares = f_evals.clone();
        let cvals = c_buf;

        let validated_shares: Vec<usize> = (0..N)
            .map(|i| {
                let mut l_buf = vec![0u8; 64];
                // maybe possible to collect all bytes and flatten

                // println!("z_evals[{}]: {:?}", i, &z_evals[i]);
                // println!("z({}): {:?}", i + 1, &z.evaluate(i + 1));
                // println!("shares[{}]: {:?}", i, &shares[i]);
                // println!("f({}): {:?}", i, &f_polynomials[0].evaluate(i + 1));

                let r_val = Polynomial::compute_r_eval(&z_evals[i], &shares[i], &d_vals);

                // let manual_r = z.evaluate(i + 1) - (&f_polynomials[0].evaluate(i + 1) * d);
                // println!("manual_r_{}: {:?}", i, manual_r);

                // for (k, fi_k) in shares[i].iter().enumerate() {
                //     println!("f_{}_{}: {:?}", i, k, fi_k);
                // }
                // println!("r_{}: {:?}", i, r_val);

                shares[i].iter().enumerate().for_each(|(k, fi_k)| {
                    l_hasher.update(fi_k.as_bytes());
                });

                l_hasher.update(r_val.as_bytes());

                l_hasher.finalize_xof().fill(&mut l_buf);
                l_hasher.reset();

                // println!("c_vals[{}]: {:?}", i, cvals[i]);
                // println!("lbuf[{}]: {:?}", i, l_buf);

                let check_bit = cvals[i] == *l_buf;
                l_buf.zeroize();
                if check_bit {
                    println!("pap");
                    Some(i)
                } else {
                    None
                }
            })
            .filter(Option::is_some)
            .map(|res| res.unwrap())
            .collect();
        assert!(validated_shares.len() > T);
    }
}
