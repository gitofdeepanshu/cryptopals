use std::{collections::HashMap, fs};
pub mod set2;
pub mod set3;

use set2::challenge12::random_aes_key;
use set3::utils::{aes_ctr_decrypt, aes_ctr_encrypt};

fn main() {
    let key = random_aes_key();
    dbg!(attack(&key));
}

fn oracle(msg: &str, key: &[u8]) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let msg = msg.replace(";", "\";\"").replace("=", "\"=\"");

    let pt = format!("{}{}{}", prefix, msg, suffix);
    aes_ctr_encrypt(pt.as_bytes(), key)
}

fn is_admin(ct: &[u8], key: &[u8]) -> bool {
    let decrypted = aes_ctr_decrypt(ct, key);
    let pt = String::from_utf8_lossy(&decrypted);
    dbg!(&pt);
    pt.contains(";admin=true;")
}

fn attack(key: &[u8]) -> bool {
    let msg = [0u8; 16].to_vec();
    let mut ct = oracle(
        &String::from_utf8(msg).expect("can't convert vec[0u8;16] to string"),
        key,
    );

    let planted_ct = ct.chunks(16).map(|x| x.to_vec()).collect::<Vec<Vec<u8>>>()[2].clone();
    let my_text = b";admin=true;FUCK";

    let hacked_block = planted_ct
        .iter()
        .zip(my_text.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    (0..16usize).for_each(|x| ct[32 + x] = hacked_block[x]);
    is_admin(&ct, key)
}
