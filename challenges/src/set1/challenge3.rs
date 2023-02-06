fn main() {
    let a = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let a_hex = hex::decode(a).unwrap();

    for i in 65u8..123u8 {
        let mut xored_arr = Vec::new();
        for j in 0..a_hex.len() {
            xored_arr.push(a_hex[j] ^ i);
        }
        println!("{} - {}", i, String::from_utf8(xored_arr).unwrap());
    }
}

//key in "X","x"
