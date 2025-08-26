use common::{
    error::{Error, ErrorKind::CountMismatch},
    polynomial::Polynomial,
    utils::batch_decompress_ristretto_points,
};
use rand::{CryptoRng, RngCore};

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

pub struct Dealer {
    pub t: usize,
    // [g1...gk]
    pub g: Vec<RistrettoPoint>,
    pub g0: RistrettoPoint,
    pub public_keys: Vec<RistrettoPoint>,
    pub(crate) secret: Option<Scalar>,
}

impl Dealer {
    pub fn new(
        g: Vec<RistrettoPoint>,
        g0: RistrettoPoint,
        n: usize,
        t: usize,
        public_keys: &[CompressedRistretto],
    ) -> Result<Self, Error> {
        if public_keys.len() != n {
            return Err(CountMismatch(n, "parties", public_keys.len(), "public keys").into());
        }
        match batch_decompress_ristretto_points(public_keys) {
            Ok(pks) => Ok(Self {
                t,
                public_keys: pks,
                secret: None,
                g: g.clone(),
                g0: g0.clone(),
            }),
            Err(x) => Err(x),
        }
    }

    pub fn t(&self) -> usize {
        self.t
    }

    pub fn deal_secret<R>(
        &mut self,
        rng: &mut R,
        x_pows: &Vec<Vec<Scalar>>,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Vec<Scalar>>, (Vec<Scalar>, Vec<CompressedRistretto>))
    where
        R: CryptoRng + RngCore,
    {
        let k = secrets.len();
        let (f_polynomials, f_evals) = self.generate_shares(x_pows, k, secrets);

        let mut c_buf: Vec<CompressedRistretto> = Vec::with_capacity(self.t + 1);

        let r_evals = self.generate_proof(rng, &mut c_buf, x_pows, &f_polynomials);
        (f_evals, (r_evals, c_buf))
    }

    pub fn generate_shares(
        &self,
        x_pows: &Vec<Vec<Scalar>>,
        k: usize,
        secrets: &Vec<Scalar>,
    ) -> (Vec<Polynomial>, Vec<Vec<Scalar>>) {
        let f_polynomials = Polynomial::sample_n_set_f0(k, self.t, secrets).unwrap();

        let f_evals = Polynomial::evaluate_many_range_precomp(
            x_pows,
            &f_polynomials,
            1,
            self.public_keys.len(),
        );
        (f_polynomials, f_evals)
    }

    pub fn generate_proof<R>(
        &self,
        rng: &mut R,
        c_buf: &mut Vec<CompressedRistretto>,
        x_pows: &Vec<Vec<Scalar>>,
        f_polynomials: &Vec<Polynomial>,
    ) -> Vec<Scalar>
    where
        R: CryptoRng,
    {
        let r = Polynomial::sample(self.t, rng);
        let r_evals = r.evaluate_range_precomp(x_pows, 1, self.public_keys.len());

        // r.coef_ref()
        //     .par_iter()
        //     .enumerate()
        //     // b0 .... bt (r coefficients)
        //     .map(|(i, r_coef)| {
        //         f_polynomials
        //             .par_iter()
        //             // g1...gk
        //             .zip(self.g.par_iter())
        //             // a10 .... a1t (f1 coefficients)
        //             // ak0 .... a1t (fk coefficients)
        //             .map(|(fk, gk)| gk * fk.coef_at_unchecked(i))
        //             // if i == 1
        //             // [g1 * a11, g0 * a21, ..., gk * at1]
        //             .reduce(|| self.g0 * r_coef, |acc, prod| acc + prod)
        //             .compress()
        //     })
        //     .collect_into_vec(c_buf);

        // DEBUG

        // let mut commitment_vector = vec![RistrettoPoint::identity(); r.coefficients.len()];

        for t in 0..r.coefficients.len() {
            let mut commitment = self.g0 * r.coef_at_unchecked(t);

            for k in 0..self.g.len() {
                let product = self.g[k] * f_polynomials[k].coef_at_unchecked(t);
                commitment += product;
            }

            // commitment_vector[t] = commitment;
            c_buf.push(commitment.compress());
        }

        // let mut addition_of_commitments = RistrettoPoint::identity();

        // for c in &commitment_vector {
        //     addition_of_commitments += c;
        // }
        // let mut addition_of_commitments2 = RistrettoPoint::identity();

        // for c in c_buf {
        //     addition_of_commitments2 += c.decompress().unwrap();
        // }

        // let f_evals = Polynomial::evaluate_many_range_precomp(
        //     x_pows,
        //     &f_polynomials,
        //     1,
        //     self.public_keys.len(),
        // );

        // let a = f_evals[0]
        //     .iter()
        //     .zip(self.g.iter())
        //     .map(|(fik, gk)| fik * gk)
        //     .fold(self.g0 * r_evals[0], |acc, prod| acc + prod);

        // let b = commitment_vector
        //     .iter()
        //     .enumerate()
        //     .skip(1)
        //     .map(|(t, c)| {
        //         println!("t: {}", t);
        //         c * Scalar::from(1u64.pow(t as u32) as u64)
        //     })
        //     // .reduce(|| commitment_vector[0], |acc, prod| acc + prod);
        //     .fold(commitment_vector[0], |acc, prod| acc + prod);

        // println!("{}", addition_of_commitments2 == b);
        // println!("{}", addition_of_commitments == b);
        // println!("{}", a == b);

        r_evals
    }

    pub fn get_pk0(&self) -> &RistrettoPoint {
        &self.public_keys[0]
    }

    pub fn publish_f0(&self) -> Scalar {
        self.secret.unwrap()
    }
}
