pub mod set2;
use aes::cipher::Iv;
use rand::{random, thread_rng, Rng};
use set2::challenge12::{aes_cbc_decrypt, aes_cbc_encrypt, random_aes_key};
use std::collections::HashMap;
use std::fs;
fn main() {
    let key = "YELLOW SUBMARINE";
    // let (encrypted, iv) = encrypter(&key);
    // let is_valid = padding_oracle(&iv, &key, &encrypted);
    let iv = [48u8; 16];
    let encrypted = aes_cbc_encrypt(
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".as_bytes(),
        key.as_bytes(),
        &iv,
    );

    // let (iv, encrypted) = encrypter(key.as_bytes());

    let blocks: Vec<Vec<u8>> = encrypted.chunks(16).map(|x| x.to_vec()).collect();
    // dbg!(break_block(&blocks[0], key.as_bytes()));

    let mut answer = Vec::new();
    for i in 0..blocks.len() {
        if i == 0 {
            answer.push(
                iv.iter()
                    .zip(break_block(&blocks[i], key.as_bytes()).iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>(),
            );
            dbg!(&answer);
        } else {
            answer.push(
                blocks[i - 1]
                    .clone()
                    .iter()
                    .zip(break_block(&blocks[i], key.as_bytes()).iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>(),
            );
            dbg!(&answer);
        }
    }

    println!(
        "{}",
        String::from_utf8_lossy(
            &answer
                .into_iter()
                .flat_map(|x| x.into_iter())
                .collect::<Vec<u8>>(),
        )
    );
}
fn encrypter(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let string_collection =
        fs::read_to_string("./text.txt").expect("Can't read the contents of the file");

    let list_of_random_string = string_collection.split_whitespace().collect::<Vec<&str>>();

    let random_string =
        list_of_random_string[thread_rng().gen_range(0..(list_of_random_string.len()))];
    let iv = random_aes_key();
    (aes_cbc_encrypt(random_string.as_bytes(), key, &iv), iv)
}

fn padding_oracle(iv: &[u8], key: &[u8], ct: &[u8]) -> bool {
    let result = aes_cbc_decrypt(ct, key, iv);
    dbg!(&result);
    check_pkcs7_valid(&result)
}
fn check_pkcs7_valid(a: &[u8]) -> bool {
    let padding_byte = *a.iter().last().unwrap() as u8;
    if (padding_byte == 0) {
        return false;
    }
    a.iter()
        .rev()
        .take(padding_byte as usize)
        .all(|&x| x == padding_byte)
}
fn xor_blocks(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut ans = Vec::new();
    for i in 0..a.len() {
        ans.push(a[i] ^ b[i]);
    }
    ans
}
fn break_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    dbg!(&block);
    let mut start_iv = [0u8; 16].to_vec();
    let mut zeroing_iv = [0u8; 16].to_vec();
    for x in 0..16usize {
        for i in 0..255u8 {
            dbg!(&i);
            start_iv[15 - x] = i;

            if padding_oracle(&start_iv, key, block) {
                if x == 0 {
                    start_iv[14] = start_iv[14] + 1;

                    if padding_oracle(&start_iv, key, block) {
                        println!("Key found for byte {} value {}", 16 - x, i);
                        zeroing_iv[15 - x] = i ^ (x as u8 + 1);
                        dbg!(&zeroing_iv);
                        start_iv = zeroing_iv
                            .clone()
                            .iter()
                            .map(|&v| (x as u8 + 2) ^ v)
                            .collect();
                        dbg!(&start_iv);
                        break;
                    } else {
                        continue;
                    }
                } else {
                    println!("Key found for byte {} value {}", 16 - x, i);
                    zeroing_iv[15 - x] = i ^ (x as u8 + 1);
                    dbg!(&zeroing_iv);
                    start_iv = zeroing_iv
                        .clone()
                        .iter()
                        .map(|&v| (x as u8 + 2) ^ v)
                        .collect();
                    dbg!(&start_iv);
                    break;
                }
            }
        }
        println!("Key not found");
    }
    dbg!(&zeroing_iv);
    zeroing_iv
}
