use std::fs;

fn main() {
    let contents =
        fs::read_to_string("./text.txt").expect("Should have been able to read the file");

    let values: Vec<String> = contents.split_whitespace().map(|x| x.to_string()).collect();
    println!(
        "{}",
        String::from_utf8(
            hex::decode("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f").unwrap()
        )
        .unwrap()
    );

    // for i in 0..values.len() {
    //     // println!("For the hex {} : {}", &values[i], i);
    //     decryter(&values[i]);
    // }
}

fn decryter(a: &String) {
    let a_hex = hex::decode(a).unwrap();

    for i in 0u8..127u8 {
        let mut xored_arr = Vec::new();
        for j in 0..a_hex.len() {
            xored_arr.push(a_hex[j] ^ i);
        }

        match String::from_utf8(xored_arr) {
            Ok(x) => {
                println!(
                    "For the hex: {}, and the key value {}, Final Text:{}",
                    a, i, x
                );
            }
            Err(_) => {}
        };
    }
}
