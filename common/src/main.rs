use std::{
    fs::File,
    io::{Read, Write},
};

use common::precompute::XPowTable;

fn main() {
    let table = XPowTable::new();

    let mut file = File::create("../table.json").unwrap();

    file.write_all(&(serde_json::to_vec(&table).unwrap()))
        .unwrap();

    let mut read_handle = File::open("../table.json").unwrap();

    let mut bytes: Vec<u8> = vec![];
    read_handle.read_to_end(&mut bytes).unwrap();

    let t2: XPowTable = serde_json::from_slice(&bytes).unwrap();
    assert!(table == t2);
    println!("Ok");
}
