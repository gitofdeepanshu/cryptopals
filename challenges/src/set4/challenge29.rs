//Incomplete
use sha1::{Digest, Sha1};
pub mod set4;

use set4::utils::SHA1;
fn main() {
    attack();
}
fn attack() {
    let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let (a, b, c, d, e) = calculate_fixed_integers(msg.as_bytes());
    let added_msg = b";admin=true";
    let total_len = msg.len() + added_msg.len();

    let key_len = 16;
    let glue_padding = glue_padding(key_len + msg.len());
    dbg!(calculated_mac(
        a,
        b,
        c,
        d,
        e,
        added_msg,
        total_len + key_len + glue_padding.len(),
    ));
    dbg!(actual_mac(msg.as_bytes(), &glue_padding, added_msg));
    // {
    //     println!("Correct Key length is {} bytes", key_len);
    // }
}
fn mac_sha1(
    msg: &[u8],
    a: Option<u32>,
    b: Option<u32>,
    c: Option<u32>,
    d: Option<u32>,
    e: Option<u32>,
) -> (u32, u32, u32, u32, u32) {
    let key = "YELLOW SUMARINE";
    let mut hasher = SHA1::new(a, b, c, d, e);
    hasher.digest(
        &key.as_bytes()
            .iter()
            .chain(msg.iter())
            .copied()
            .collect::<Vec<u8>>(),
    )
}

fn calculate_fixed_integers(msg: &[u8]) -> (u32, u32, u32, u32, u32) {
    mac_sha1(msg, None, None, None, None, None)
}
fn actual_mac(a: &[u8], b: &[u8], c: &[u8]) -> (u32, u32, u32, u32, u32) {
    mac_sha1(
        &a.iter()
            .chain(b.iter())
            .chain(c.iter())
            .copied()
            .collect::<Vec<u8>>(),
        None,
        None,
        None,
        None,
        None,
    )
}
fn calculated_mac(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    msg: &[u8],
    keylen: usize,
) -> (u32, u32, u32, u32, u32) {
    let mut hasher = SHA1::new(Some(a), Some(b), Some(c), Some(d), Some(e));
    let final_msg = msg
        .iter()
        .chain(custom_padding(keylen).iter())
        .copied()
        .collect::<Vec<u8>>();

    let mut words = Vec::new();
    final_msg.chunks(4).for_each(|x| {
        words.push(u32::from_be_bytes(
            x.try_into().expect("slice with incorrect length"),
        ))
    });

    hasher.process_self(&words)
}

fn glue_padding(total_len: usize) -> Vec<u8> {
    let len = u64::try_from(total_len * 8)
        .expect("Can't convert length to u64")
        .to_be_bytes();

    let first_block = [128u8; 1];
    let mut zero_block = Vec::new();

    (0..(64 - (total_len + 9) % 64)).for_each(|_| zero_block.push(0u8));
    first_block
        .iter()
        .chain(zero_block.iter())
        .chain(len.iter())
        .copied()
        .collect::<Vec<u8>>()
}
fn custom_padding(len: usize) -> Vec<u8> {
    let len = u64::try_from(len * 8)
        .expect("Can't convert length to u64")
        .to_be_bytes();

    let first_block = [128u8; 1];
    let zero_block = [0u8; 44];

    first_block
        .iter()
        .chain(zero_block.iter())
        .chain(len.iter())
        .copied()
        .collect::<Vec<u8>>()
}
