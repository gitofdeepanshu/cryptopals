pub fn run() -> Result<(), ()> {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("{}", hex_to_base64(hex_string));
    Ok(())
}

pub fn hex_to_base64(a: &str) -> String {
    base64::encode(hex::decode(a).unwrap())
}
