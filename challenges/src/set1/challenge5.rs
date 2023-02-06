fn main() {
    let stanza = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";

    let key = b"ICE";

    repeated_key_xor(stanza, key);
}

fn repeated_key_xor(pt: &[u8], key: &[u8]) {
    let mut xored = Vec::new();
    for i in 0..pt.len() {
        xored.push(pt[i] ^ key[i % 3]);
    }
    println!("{}", hex::encode(xored));
}
