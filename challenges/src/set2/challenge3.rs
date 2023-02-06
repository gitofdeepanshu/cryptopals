use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use rand::Rng;
use std::collections::HashSet;
use std::{fs, vec};

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
    ECB,
    CBC,
}

fn main() {
    // println!("{:?}", random_aes_key());
    for _ in 0..3 {
        detect_mode();
    }
}

fn random_aes_key() -> Vec<u8> {
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
            aes_cbc_encrypt(&message, &random_aes_key(), &random_aes_key()),
            EncryptionMode::CBC,
        );
    }
}
fn aes_cbc_decrypt(ct: &str, key: &str, iv: &[u8]) {
    let ct = base64::decode(ct).unwrap();

    let mut blocks: Vec<GenericArray<u8, U16>> = ct
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    let cipher = Aes128::new(GenericArray::from_slice(key.as_bytes()));

    let total_blocks = blocks.len() - 1;
    dbg!(total_blocks);
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

    println!("{}", String::from_utf8(result).unwrap());
}
fn aes_cbc_encrypt(pt: &[u8], key: &[u8], iv: &[u8]) -> String {
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

    base64::encode(result)
}
fn aes_ecb_encrypt(pt: &[u8], key: &[u8]) -> String {
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
fn xor_block<T: IntoIterator<Item = u8>>(a: GenericArray<u8, U16>, b: T) -> GenericArray<u8, U16> {
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
