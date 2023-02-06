use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
use std::{collections::HashMap, fs, u8};
fn main() {
    let file_content = fs::read_to_string("./text.txt").expect("Can't read file");

    let modified_contents: Vec<&str> = file_content.split_whitespace().collect();

    for i in 0..modified_contents.len() {
        score(modified_contents[i].as_bytes(), i);
    }
}

fn score(values: &[u8], index: usize) {
    let mut hashmap: HashMap<Vec<u8>, u8> = HashMap::new();
    let r_bytes = hex::decode(values).expect("Can't convert hex to raw bytes");

    let blocks: Vec<Vec<u8>> = r_bytes.chunks(16).map(|x| x.to_vec()).collect();

    for v in blocks {
        hashmap.entry(v).and_modify(|v| *v = *v + 1).or_insert(0);
    }
    println!(
        "For index {} value {}",
        index,
        hashmap.iter().map(|(x, y)| y).sum::<u8>()
    );
}
