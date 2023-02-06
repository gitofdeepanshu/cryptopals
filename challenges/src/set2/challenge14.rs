pub mod set2;
use std::collections::HashMap;
use std::f64;

use set2::challenge12::aes_ecb_encrypt;

const UNKNOWN: &str = "VHdvIHJvYWRzIGRpdmVyZ2VkIGluIGEgeWVsbG93IHdvb2QsCkFuZCBzb3JyeSBJIGNvdWxkIG5vdCB0cmF2ZWwgYm90aApBbmQgYmUgb25lIHRyYXZlbGVyLCBsb25nIEkgc3Rvb2QKQW5kIGxvb2tlZCBkb3duIG9uZSBhcyBmYXIgYXMgSSBjb3VsZApUbyB3aGVyZSBpdCBiZW50IGluIHRoZSB1bmRlcmdyb3d0aDsKClRoZW4gdG9vayB0aGUgb3RoZXIsIGFzIGp1c3QgYXMgZmFpciwKQW5kIGhhdmluZyBwZXJoYXBzIHRoZSBiZXR0ZXIgY2xhaW0sCkJlY2F1c2UgaXQgd2FzIGdyYXNzeSBhbmQgd2FudGVkIHdlYXI7ClRob3VnaCBhcyBmb3IgdGhhdCB0aGUgcGFzc2luZyB0aGVyZQpIYWQgd29ybiB0aGVtIHJlYWxseSBhYm91dCB0aGUgc2FtZSw=";
const PREFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctd";
const KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let mut final_string: Vec<u8> = Vec::new();
    let mut i = 0;

    loop {
        if find_block(&mut final_string, i, len_of_prefix()) {
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
fn unknown_encrypt(msg: &Vec<u8>) -> Vec<u8> {
    let test_msg: Vec<u8> = PREFIX
        .as_bytes()
        .iter()
        .chain(msg.iter())
        .chain(UNKNOWN.as_bytes().iter())
        .copied()
        .collect();
    base64::decode(aes_ecb_encrypt(&test_msg, KEY.as_bytes())).unwrap()
}
fn len_of_prefix() -> usize {
    let mut msg = Vec::new();
    let empty_msg = unknown_encrypt(&msg)
        .chunks(16)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();

    msg.push(0);

    let test_msg = unknown_encrypt(&msg)
        .chunks(16)
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let mut target_block = 0usize;
    for i in 0..empty_msg.len() {
        if empty_msg[i] == test_msg[i] {
            target_block = target_block + 1;
        } else {
            break;
        }
    }

    let mut previous_block = test_msg[target_block].clone();
    let mut added_size_count = 1usize;

    for _ in 0..16 {
        msg.push(0);
        let new_block = unknown_encrypt(&msg)
            .chunks(16)
            .map(|x| x.to_vec())
            .collect::<Vec<Vec<u8>>>()[target_block]
            .to_vec();

        if new_block == previous_block {
            break;
        }
        added_size_count = added_size_count + 1;
        previous_block = new_block;
    }
    (16 * (target_block + 1)) - added_size_count
}
fn find_block(known_string: &mut Vec<u8>, block_number: usize, len_prefix: usize) -> bool {
    let prefix_dump = (0..(16 - (len_prefix % 16)))
        .map(|_| 0)
        .collect::<Vec<u8>>();
    let dump_blocks = (len_prefix / 16) + 1;
    let mut suffix_buffer = ['a' as u8; 15].to_vec();
    let mut unknown_string = Vec::new();
    for _ in 0..16 {
        let encrypted = unknown_encrypt(
            &(prefix_dump
                .iter()
                .chain(suffix_buffer.iter())
                .copied()
                .collect()),
        )[dump_blocks * 16..]
            .to_vec();

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

            let value: Vec<Vec<u8>> = base64::decode(aes_ecb_encrypt(&test_block, KEY.as_bytes()))
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
                return false;
            }
        };
        let _ = suffix_buffer.pop();
    }
    known_string.append(&mut unknown_string);
    true
}
