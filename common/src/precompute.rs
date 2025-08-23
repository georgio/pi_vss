use std::{
    fs::File,
    io::{Read, Write},
};

use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};

fn gen_powers(n: usize, t: usize) -> Vec<Vec<Scalar>> {
    (1..=n)
        .into_iter()
        .map(|i| {
            let mut x_powers: Vec<Scalar> = vec![Scalar::ONE, Scalar::from(i as u64)];
            for i in 2..t {
                x_powers.push(x_powers[1] * x_powers[i - 1]);
            }
            x_powers
        })
        .collect()
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct XPowTable {
    pub n16_t7: Vec<Vec<Scalar>>,
    pub n32_t15: Vec<Vec<Scalar>>,
    pub n64_t31: Vec<Vec<Scalar>>,
    pub n128_t63: Vec<Vec<Scalar>>,
    pub n256_t127: Vec<Vec<Scalar>>,
    pub n512_t255: Vec<Vec<Scalar>>,
    pub n1024_t511: Vec<Vec<Scalar>>,
    pub n2048_t1023: Vec<Vec<Scalar>>,
    pub n4096_t2047: Vec<Vec<Scalar>>,
}

impl XPowTable {
    pub fn new() -> Self {
        Self {
            n16_t7: gen_powers(16, 7),
            n32_t15: gen_powers(32, 15),
            n64_t31: gen_powers(64, 31),
            n128_t63: gen_powers(128, 63),
            n256_t127: gen_powers(256, 127),
            n512_t255: gen_powers(512, 255),
            n1024_t511: gen_powers(1024, 511),
            n2048_t1023: gen_powers(2048, 1023),
            n4096_t2047: gen_powers(4096, 2047),
        }
    }

    pub fn from_file(path: &str) -> Self {
        let mut read_handle = File::open(path).unwrap();

        let mut bytes: Vec<u8> = vec![];
        read_handle.read_to_end(&mut bytes).unwrap();

        serde_json::from_slice(&bytes).unwrap()
    }

    pub fn from_params(path: &str, n: usize, t: usize) -> Vec<Vec<Scalar>> {
        let table = Self::from_file(path);
        match (n, t) {
            (16, 7) => table.n16_t7,
            (32, 15) => table.n32_t15,
            (64, 31) => table.n64_t31,
            (128, 63) => table.n128_t63,
            (256, 127) => table.n256_t127,
            (512, 255) => table.n512_t255,
            (1024, 511) => table.n1024_t511,
            (2048, 1023) => table.n2048_t1023,
            (4096, 2047) => table.n4096_t2047,
            (_, _) => gen_powers(n, t),
        }
    }
}

fn main() {
    let table = XPowTable::new();

    let mut file = File::create("./table.json").unwrap();

    file.write_all(&(serde_json::to_vec(&table).unwrap()))
        .unwrap();

    let mut read_handle = File::open("./table.json").unwrap();

    let mut bytes: Vec<u8> = vec![];
    read_handle.read_to_end(&mut bytes).unwrap();

    let t2: XPowTable = serde_json::from_slice(&bytes).unwrap();
    assert!(table == t2);
    println!("Ok");
}
