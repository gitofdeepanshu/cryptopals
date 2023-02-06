pub mod set2;
use std::collections::HashMap;

use aes::cipher::Iv;
use rand::random;
use set2::challenge12::{aes_cbc_decrypt, aes_cbc_encrypt, random_aes_key};
fn run() {
    let key = random_aes_key();
    let iv = random_aes_key();
    let msg = "abcdefghijklmnop";
    let encrypted_aes = base64::decode(oracle(msg, &key, &iv)).unwrap();

    let mut encrypted_blocks = encrypted_aes
        .chunks(16)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let desired_value = ";admin=true;a=bc";
    let block_to_edit = encrypted_blocks[1].clone();
    let modified_block = xor_blocks(
        &block_to_edit,
        &xor_blocks(desired_value.as_bytes(), msg.as_bytes()),
    );
    encrypted_blocks[1] = modified_block;
    let modified_msg = base64::encode(
        encrypted_blocks
            .iter()
            .flat_map(|x| x.iter())
            .copied()
            .collect::<Vec<u8>>(),
    );

    dbg!(is_admin(modified_msg, &key, &iv));
}

fn oracle(msg: &str, key: &[u8], iv: &[u8]) -> String {
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let msg = msg.replace(";", "\";\"").replace("=", "\"=\"");

    let pt = format!("{}{}{}", prefix, msg, suffix);
    aes_cbc_encrypt(pt.as_bytes(), key, iv)
}

fn is_admin(ct: String, key: &[u8], iv: &[u8]) -> bool {
    let decrypted = aes_cbc_decrypt(&ct, key, iv);
    let mut decrypted_string = String::from_utf8_lossy(&decrypted);
    // match String::from_utf8(decrypted) {
    //     Ok(x) => decrypted_string = x,
    //     Err(e) => panic!("Not a valid String"),
    // };

    let mut map = decrypted_string
        .split(';')
        .map(|x| x.split_at(x.find("=").unwrap()))
        .map(|(key, val)| (key, &val[1..]))
        .collect::<HashMap<&str, &str>>();

    dbg!(&map);

    match map.get("admin") {
        Some(&x) => {
            if x == "true" {
                return true;
            } else {
                false
            }
        }
        None => false,
    }
}
fn check_pkcs7_valid(a: &str) -> bool {
    let padding_byte = a.chars().last().unwrap() as u8;
    a.chars()
        .rev()
        .take(padding_byte as usize)
        .all(|x| x == padding_byte as char)
}
fn xor_blocks(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut ans = Vec::new();
    for i in 0..a.len() {
        ans.push(a[i] ^ b[i]);
    }
    ans
}
