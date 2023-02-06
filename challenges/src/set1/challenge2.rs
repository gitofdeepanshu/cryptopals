fn main() {
    let a = b"1c0111001f010100061a024b53535009181c";
    let b = b"686974207468652062756c6c277320657965";
    println!("{}", fixed_xor(a, b));
}

fn fixed_xor(a: &[u8], b: &[u8]) -> String {
    let a_hex = hex::decode(a).unwrap();
    let b_hex = hex::decode(b).unwrap();

    let mut xored = Vec::new();

    for i in 0..a_hex.len() {
        xored.push(a_hex[i] ^ b_hex[i]);
    }

    hex::encode(xored)
}
