use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use std::io::prelude::*;

lazy_static! {
    static ref OCCURANCE_ENGLISH: HashMap<char, f64> = {
        let m = HashMap::from([
            ('a', 8.2389258),
            ('b', 1.5051398),
            ('c', 2.8065007),
            ('d', 4.2904556),
            ('e', 12.813865),
            ('f', 2.2476217),
            ('g', 2.0327458),
            ('h', 6.1476691),
            ('i', 6.1476691),
            ('j', 0.1543474),
            ('k', 0.7787989),
            ('l', 4.0604477),
            ('m', 2.4271893),
            ('n', 6.8084376),
            ('o', 7.5731132),
            ('p', 1.9459884),
            ('q', 0.0958366),
            ('r', 6.0397268),
            ('s', 6.3827211),
            ('t', 9.3827211),
            ('u', 2.7822893),
            ('v', 0.9866131),
            ('w', 2.3807842),
            ('x', 0.1513210),
            ('y', 1.9913847),
            ('z', 0.0746517),
        ]);
        m
    };
}

fn main() {
    let contents = fs::read_to_string("./text.txt")
        .expect("Should have been able to read the file")
        .replace("\n", "");
    // let modified_contents = contents
    //     .split_whitespace()
    //     .map(|x| x.to_string())
    //     .collect::<Vec<String>>()
    //     .concat();

    let decode_base64 = base64::decode(contents).unwrap();

    // let string_bytes = &decode_base64;
    // find_key(string_bytes);

    let key = 11;
    let blocks = transpose_block(&decode_base64, key);
    for i in 0..11 {
        single_bit_xor(&blocks[i]);
    }

    // single_bit_xor(&blocks[3]);
    // let new_key = b"Ter(inator X: Bring the noise";
    // decrypt(&decode_base64, new_key);
    // println!("{:?}", blocks);
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut count = 0;
    for i in 0..a.len() {
        for x in 0..8 {
            if (a[i] >> x) & 1 != (b[i] >> x) & 1 {
                count = count + 1;
            }
        }
    }
    count
}

fn transpose_block(a: &[u8], key: usize) -> Vec<Vec<u8>> {
    let mut transpose: Vec<Vec<u8>> = Vec::new();
    for _ in 0..key {
        transpose.push(Vec::new());
    }
    for i in 0..a.len() {
        transpose[i % key].push(a[i]);
    }
    transpose
}
fn find_key(string_bytes: &[u8]) {
    for key_size in 2..41 {
        let str1 = &string_bytes[0..key_size];
        let str2 = &string_bytes[key_size..key_size * 2];
        let str3 = &string_bytes[key_size * 2..key_size * 3];
        let str4 = &string_bytes[key_size * 3..key_size * 4];
        let str5 = &string_bytes[key_size * 4..key_size * 5];
        let str6 = &string_bytes[key_size * 5..key_size * 6];

        let hd: f32 = (hamming_distance(str1, str2) as f32
            + hamming_distance(str2, str3) as f32
            + hamming_distance(str3, str4) as f32
            + hamming_distance(str4, str5) as f32
            + hamming_distance(str5, str6) as f32)
            / 5 as f32;

        let hd_nomarlized = hd / key_size as f32;

        println!(
            "For the keySize {}, HD is {}, nomalized Hd is {}",
            key_size, hd, hd_nomarlized
        );
    }
}

// let key size be 29
fn single_bit_xor(a: &[u8]) {
    let mut final_scores = HashMap::new();
    for i in 32u8..123u8 {
        let mut dec = Vec::new();
        for x in 0..a.len() {
            dec.push(a[x] ^ i);
        }

        let mut score: f64 = 0f64;
        for b in 0..dec.len() {
            if (dec[b] >= 65 && dec[b] <= 90) || (dec[b] >= 97 && dec[b] <= 122) {
                let character: Vec<char> = (dec[b] as char).to_lowercase().collect();
                score = OCCURANCE_ENGLISH.get(&character[0]).unwrap() + score;
            } else if (dec[b] >= 0 && dec[b] <= 16) {
                score = score - 1f64;
            }
        }
        println!("Score for ASCII {} is {}", i as char, score);
        final_scores.insert(i as char, score);

        // match String::from_utf8(dec) {
        //     Ok(x) => println!(" for ASCII {} the string is {}", i as char, x),
        //     Err(e) => {}
        // }
    }
    let key_with_max_value = final_scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .unwrap();

    dbg!(key_with_max_value.0);
}
fn decrypt(ct: &[u8], key: &[u8]) {
    let mut new_vec = Vec::new();

    for i in 0..ct.len() {
        new_vec.push(ct[i] ^ key[i % 29]);
    }

    println!("{}", String::from_utf8(new_vec).unwrap());
}
