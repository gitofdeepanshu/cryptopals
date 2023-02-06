use rand::Rng;
use set2::challenge12::{aes_ecb_encrypt, random_aes_key};
use std::{
    collections::HashMap,
    fmt::{format, write, Display},
};
pub mod set2;

struct Info {
    email: String,
    uid: usize,
    role: String,
}

impl Display for Info {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "email={}&uid={}&role={}",
            self.email, self.uid, self.role
        )?;
        Ok(())
    }
}
fn run() {
    let input = "foo=bar&baz=qux&zap=zazzle";
    let key = "YELLOW SUBMARINE".as_bytes();

    let original_email_ecrypted =
        base64::decode(profile_for("hooda@ipu.com".to_string(), &key)).unwrap();

    let padding = String::from_utf8([11u8; 11].to_vec()).unwrap();
    let malicious_email = format!("{}{}", "hooda@ipu.admin", padding);

    let malicious_email_encrypted = base64::decode(profile_for(malicious_email, &key)).unwrap();

    let first_piece = original_email_ecrypted[0..(original_email_ecrypted.len() - 16)].to_vec();
    let second_piece = malicious_email_encrypted[16..32].to_vec();

    let malicious_string = base64::encode(
        first_piece
            .iter()
            .chain(second_piece.iter())
            .copied()
            .collect::<Vec<u8>>(),
    );
    println!("{malicious_string}");
}
fn parser(a: String) {
    let mut map: HashMap<&str, &str> = a
        .split('&')
        .map(|x| x.split_at(x.find('=').unwrap()))
        .map(|(key, value)| (key, &value[1..]))
        .collect();

    println!("{:?}", map);
}
fn profile_for(a: String, key: &[u8]) -> String {
    let info = Info {
        email: a.replace("=", "").replace("&", ""),
        uid: 10,
        role: "user".to_string(),
    };

    let encoded = format!("{}", info);

    aes_ecb_encrypt(encoded.as_bytes(), key)
}
