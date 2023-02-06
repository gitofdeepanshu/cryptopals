use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::{fs, vec};

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

fn main() {
    // println!("{:?}", random_aes_key());

    let buffer = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let buffer2 = "VHdvIHJvYWRzIGRpdmVyZ2VkIGluIGEgeWVsbG93IHdvb2QsCkFuZCBzb3JyeSBJIGNvdWxkIG5vdCB0cmF2ZWwgYm90aApBbmQgYmUgb25lIHRyYXZlbGVyLCBsb25nIEkgc3Rvb2QKQW5kIGxvb2tlZCBkb3duIG9uZSBhcyBmYXIgYXMgSSBjb3VsZApUbyB3aGVyZSBpdCBiZW50IGluIHRoZSB1bmRlcmdyb3d0aDsKClRoZW4gdG9vayB0aGUgb3RoZXIsIGFzIGp1c3QgYXMgZmFpciwKQW5kIGhhdmluZyBwZXJoYXBzIHRoZSBiZXR0ZXIgY2xhaW0sCkJlY2F1c2UgaXQgd2FzIGdyYXNzeSBhbmQgd2FudGVkIHdlYXI7ClRob3VnaCBhcyBmb3IgdGhhdCB0aGUgcGFzc2luZyB0aGVyZQpIYWQgd29ybiB0aGVtIHJlYWxseSBhYm91dCB0aGUgc2FtZSw=";
    let key = "YELLOW SUBMARINE";
    let block_size = find_block_size();

    break_aes(key);
}

pub fn random_aes_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}
fn encryption_oracle(input: &str) -> (String, EncryptionMode) {
    let mut input = input.as_bytes().to_vec();

    let mut rng = rand::thread_rng();
    let mut prefix = (0..rng.gen_range(5..11))
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>();

    let mut suffix = (0..rng.gen_range(5..11))
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>();

    let message: Vec<u8> = prefix
        .iter()
        .chain(input.iter())
        .chain(suffix.iter())
        .cloned()
        .collect();

    // Odd -> CBC
    // Even -> ECB
    let ebc_mode: bool = rand::random();

    if ebc_mode {
        return (
            aes_ecb_encrypt(&message, &random_aes_key()),
            EncryptionMode::ECB,
        );
    } else {
        return (
            String::from_utf8(aes_cbc_encrypt(
                &message,
                &random_aes_key(),
                &random_aes_key(),
            ))
            .unwrap(),
            EncryptionMode::CBC,
        );
    }
}
pub fn aes_cbc_decrypt(ct: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut blocks: Vec<GenericArray<u8, U16>> = ct
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    let cipher = Aes128::new(GenericArray::from_slice(key));

    let total_blocks = blocks.len() - 1;
    for i in 0..blocks.len() {
        cipher.decrypt_block(&mut blocks[total_blocks - i]);
        if i < total_blocks {
            blocks[total_blocks - i] =
                xor_block(blocks[total_blocks - i], blocks[total_blocks - i - 1]);
        }
    }

    //IV Implementation
    blocks[0] = xor_block(blocks[0], iv.to_vec());

    let result = blocks
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect::<Vec<u8>>();

    // println!("{}", String::from_utf8(result).unwrap());

    let total_padded_bytes = result[result.len() - 1];

    result[..result.len() - total_padded_bytes as usize].to_vec()
}
pub fn aes_cbc_encrypt(pt: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut pt = pt.to_vec();

    //padding
    let padding_size = 16 - pt.len() % 16;
    let padding_char = padding_size as u8;
    let mut padding: Vec<u8> = (0..padding_size).map(|_| (padding_char)).collect();

    pt.append(&mut padding);

    //IV Implemented
    for i in 0..16usize {
        pt[i] = pt[i] ^ iv[i];
    }

    // AES PreRequisite
    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut blocks: Vec<GenericArray<u8, U16>> = pt
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    //Encryption

    //encrpyt first block
    cipher.encrypt_block(&mut blocks[0]);

    for i in 1..blocks.len() {
        blocks[i] = xor_block(blocks[i], blocks[i - 1]);
        cipher.encrypt_block(&mut blocks[i]);
    }

    let result = blocks
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect::<Vec<u8>>();
    // dbg!(&result);

    result
}
pub fn aes_ecb_encrypt(pt: &[u8], key: &[u8]) -> String {
    let mut pt = pt.to_vec();

    //padding
    let padding_size = 16 - pt.len() % 16;
    let padding_char = padding_size as u8;
    let mut padding: Vec<u8> = (0..padding_size).map(|_| (padding_char)).collect();

    pt.append(&mut padding);

    // AES PreRequisite
    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut blocks: Vec<GenericArray<u8, U16>> = pt
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    //Encryption

    //encrpyt first block
    cipher.encrypt_blocks(&mut blocks);

    let result = blocks
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect::<Vec<u8>>();
    // dbg!(&result);

    base64::encode(result)
}
pub fn xor_block<T: IntoIterator<Item = u8>>(
    a: GenericArray<u8, U16>,
    b: T,
) -> GenericArray<u8, U16> {
    let mut a = a.into_iter().collect::<Vec<u8>>();
    let b = b.into_iter().collect::<Vec<u8>>();
    for i in 0..16usize {
        a[i] = a[i] ^ b[i];
    }
    *GenericArray::from_slice(&a)
}
fn detect_mode() {
    let message = "z".repeat(64);

    let (ct, actual_mode) = encryption_oracle(&message);
    let ct = ct.as_bytes().to_vec();

    let blocks: Vec<Vec<u8>> = ct.chunks(16).map(|x| x.to_vec()).collect();
    dbg!(&blocks);
    let unique_blocks: HashSet<_> = blocks.iter().cloned().collect();
    dbg!(&unique_blocks);

    if blocks.len() > unique_blocks.len() {
        println!(
            "Detected Mode {:?}, Actual Mode {:?}",
            EncryptionMode::ECB,
            actual_mode
        );
    } else {
        println!(
            "Detected Mode {:?}, Actual Mode {:?}",
            EncryptionMode::CBC,
            actual_mode
        );
    }
}
fn find_block_size() -> usize {
    let mut test_vec = ['a' as u8].to_vec();
    let init_size = unknown_encrypt(&test_vec);
    loop {
        //increase size by 1
        test_vec.push('a' as u8);
        let new_size = unknown_encrypt(&test_vec);
        if new_size.len() - init_size.len() > 0 {
            return new_size.len() - init_size.len();
        }
    }
}
fn unknown_encrypt(msg: &Vec<u8>) -> Vec<u8> {
    let buffer = "VHdvIHJvYWRzIGRpdmVyZ2VkIGluIGEgeWVsbG93IHdvb2QsCkFuZCBzb3JyeSBJIGNvdWxkIG5vdCB0cmF2ZWwgYm90aApBbmQgYmUgb25lIHRyYXZlbGVyLCBsb25nIEkgc3Rvb2QKQW5kIGxvb2tlZCBkb3duIG9uZSBhcyBmYXIgYXMgSSBjb3VsZApUbyB3aGVyZSBpdCBiZW50IGluIHRoZSB1bmRlcmdyb3d0aDsKClRoZW4gdG9vayB0aGUgb3RoZXIsIGFzIGp1c3QgYXMgZmFpciwKQW5kIGhhdmluZyBwZXJoYXBzIHRoZSBiZXR0ZXIgY2xhaW0sCkJlY2F1c2UgaXQgd2FzIGdyYXNzeSBhbmQgd2FudGVkIHdlYXI7ClRob3VnaCBhcyBmb3IgdGhhdCB0aGUgcGFzc2luZyB0aGVyZQpIYWQgd29ybiB0aGVtIHJlYWxseSBhYm91dCB0aGUgc2FtZSw=";
    let test_msg: Vec<u8> = msg
        .iter()
        .chain(buffer.as_bytes().iter())
        .copied()
        .collect();
    base64::decode(aes_ecb_encrypt(&test_msg, "YELLOW SUBMARINE".as_bytes())).unwrap()
}

fn break_aes(key: &str) {
    let mut final_string: Vec<u8> = Vec::new();
    let mut i = 0;

    loop {
        if find_block(&mut final_string, i) {
            i = i + 1;
        } else {
            break;
        }
    }

    println!(
        "{}",
        String::from_utf8_lossy(&base64::decode(final_string).unwrap())
    );
}

fn find_block(known_string: &mut Vec<u8>, block_number: usize) -> bool {
    let mut suffix_buffer = ['a' as u8; 15].to_vec();
    let mut unknown_string = Vec::new();
    for _ in 0..16 {
        let encrypted = unknown_encrypt(&suffix_buffer);

        if encrypted.len() < ((block_number + 1) * 16) {
            return false;
        }
        let comparator = encrypted[block_number * 16..((block_number + 1) * 16)].to_vec();
        let mut map: HashMap<Vec<u8>, u8> = HashMap::new();

        for i in 0..255u8 {
            let mut test_block: Vec<u8> = suffix_buffer
                .iter()
                .chain(known_string.iter())
                .chain(unknown_string.iter())
                .copied()
                .collect();
            test_block.push(i);

            let value: Vec<Vec<u8>> =
                base64::decode(aes_ecb_encrypt(&test_block, "YELLOW SUBMARINE".as_bytes()))
                    .unwrap()
                    .chunks(16)
                    .map(|x| x.to_vec())
                    .collect();
            map.insert(value[block_number].clone(), i);
            let _ = test_block.pop();
        }
        match map.get(&comparator) {
            Some(x) => unknown_string.push(*x),
            None => {
                let _ = unknown_string.pop();
                known_string.append(&mut unknown_string);
                dbg!(known_string);
                return false;
            }
        };
        let _ = suffix_buffer.pop();
    }
    known_string.append(&mut unknown_string);
    true
}
