pub mod set2;
use rand::{random, Rng};
use set2::challenge12::{aes_cbc_decrypt, aes_cbc_encrypt, random_aes_key};
fn main() {
    // let mut rng = rand::thread_rng();
    // let pt = (0..32).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    // let key = random_aes_key();
    // dbg!(&key);

    // let ct = oracle(&pt, &key);
    // let mut i = 0;
    // loop {
    //     dbg!(&i);
    //     let planted_ct = find_appropriate_ct();
    //     let _ = decrypt(&planted_ct, &key);
    //     i += 1;
    // }
    dbg!(answer());
}

fn oracle(msg: &[u8], key: &[u8]) -> Vec<u8> {
    aes_cbc_encrypt(msg, key, key)
}
fn decrypt(ct: &[u8], key: &[u8]) -> Vec<u8> {
    let decrypted = aes_cbc_decrypt(ct, key, key);
    if !(0..decrypted.len()).all(|x| decrypted[x] <= 128) {
        panic!("High ASCII value found {:?}", decrypted);
    }
    dbg!(&decrypted);
    decrypted
}
fn find_appropriate_ct() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let start = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();

    let middle = [0u8; 16].to_vec();
    start
        .iter()
        .chain(middle.iter())
        .chain(start.iter())
        .copied()
        .collect::<Vec<u8>>()
}
fn answer() -> Vec<u8> {
    let p1_: [u8; 16] = [
        142, 102, 42, 32, 139, 84, 102, 149, 208, 119, 46, 25, 222, 226, 155, 41,
    ];
    let p3_: [u8; 16] = [
        228, 230, 233, 125, 68, 56, 200, 211, 11, 182, 2, 205, 100, 11, 129, 170,
    ];

    p1_.iter()
        .zip(p3_.iter())
        .map(|(&a, &b)| a ^ b)
        .collect::<Vec<u8>>()
}
