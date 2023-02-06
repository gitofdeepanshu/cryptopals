use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use std::fs;
fn main() {
    let contents = fs::read_to_string("./text.txt")
        .expect("Can't read file")
        .replace("\n", "");

    let decoded = base64::decode(contents.as_bytes()).unwrap();

    let mut blocks: Vec<GenericArray<u8, _>> = decoded
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    let bytes_key = b"YELLOW SUBMARINE";

    let key = GenericArray::from(*bytes_key);

    let cipher = Aes128::new(&key);
    cipher.decrypt_blocks(&mut blocks);

    let decoded: Vec<u8> = blocks.into_iter().flat_map(|x| x.into_iter()).collect();

    println!("{}", String::from_utf8(decoded).unwrap());
}
