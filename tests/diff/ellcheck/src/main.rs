//! For each 64-byte ElligatorSwift encoding on stdin (hex, one per line), print 1 if it equals the
//! encoding secp256k1's `from_pubkey` makes with zero randomness, else 0.
use std::io::BufRead;

use secp256k1::ellswift::ElligatorSwift;
use secp256k1::PublicKey;

fn main() {
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let bytes: Vec<u8> = (0..line.len()).step_by(2).map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
        let first64: [u8; 64] = bytes.try_into().expect("64 bytes");
        let pk = PublicKey::from_ellswift(ElligatorSwift::from_array(first64));
        println!("{}", (ElligatorSwift::from_pubkey(pk).to_array() == first64) as u8);
    }
}
