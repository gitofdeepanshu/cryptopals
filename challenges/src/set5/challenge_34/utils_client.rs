use crate::{set2, set4};
use std::{io, str::FromStr};

use set2::challenge12::{aes_cbc_decrypt, aes_cbc_encrypt, random_aes_key};
use set4::utils::SHA1;

use num_bigint::{BigInt, BigUint};

#[derive(Debug)]
pub struct Attacker {}
impl Attacker {
    pub fn decrypt_message(&self, ct: &[u8]) -> io::Result<String> {
        let key = BigUint::from(0u8).to_bytes_be();

        let mut sha1 = SHA1::new(None, None, None, None, None);
        let digest = sha1.digest(&key);

        let iv = &ct[ct.len() - 16..];

        let pt = aes_cbc_decrypt(&ct[0..ct.len() - 16], &digest[0..16], &iv);

        Ok(String::from_utf8(pt).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Can't convert to string {}", e),
            )
        })?)
    }
}

#[derive(Debug)]
pub struct Client {
    pub p: BigUint,
    pub g: BigUint,
    pub a: BigUint,
}

impl Client {
    pub fn new() -> io::Result<Self> {
        Ok(Client {
            p: BigUint::from_str("0").map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format! {"Can't convert from String to BigUint or {}",e},
                )
            })?,
            g: BigUint::from_str("0").map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format! {"Can't convert from String to BigUint or {}",e},
                )
            })?,
            a: BigUint::from_str("0").map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format! {"Can't convert from String to BigUint or {}",e},
                )
            })?,
        })
    }
    pub fn get_p(&self) -> io::Result<BigUint> {
        Ok(self.p.clone())
    }
    pub fn get_g(&self) -> io::Result<BigUint> {
        Ok(self.g.clone())
    }
    pub fn get_a(&self) -> io::Result<BigUint> {
        Ok(self.a.clone())
    }
    pub fn get_public_key(&self) -> io::Result<BigUint> {
        Ok(self.g.modpow(&self.a, &self.p))
    }
    pub fn send_encrypted_message(&self, msg: &[u8], public_key: BigUint) -> io::Result<Vec<u8>> {
        let key = self.get_secret(public_key).to_bytes_be();

        let mut sha1 = SHA1::new(None, None, None, None, None);
        let digest = sha1.digest(&key);

        let mut iv = random_aes_key();

        let mut ct = aes_cbc_encrypt(msg, &digest[0..16], &iv);

        ct.append(&mut iv);

        Ok(ct)
    }

    pub fn decrypt_message(&self, public_key: BigUint, ct: &[u8]) -> io::Result<String> {
        let key = self.get_secret(public_key).to_bytes_be();

        let mut sha1 = SHA1::new(None, None, None, None, None);
        let digest = sha1.digest(&key);

        let iv = &ct[ct.len() - 16..];

        let pt = aes_cbc_decrypt(&ct[0..ct.len() - 16], &digest[0..16], &iv);

        Ok(String::from_utf8(pt).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Can't convert to string {}", e),
            )
        })?)
    }
    pub fn get_secret(&self, public_key: BigUint) -> BigUint {
        public_key.modpow(&self.a, &self.p)
    }
}
mod test {
    use super::*;
    use std::{io::Cursor, str::FromStr};

    #[test]
    fn test_get_public_key() {
        let mut client = Client::new().unwrap();
        client.p = BigUint::from_str("23").unwrap();
        client.g = BigUint::from_str("5").unwrap();
        client.a = BigUint::from_str("6").unwrap();

        let pub_key = client.get_public_key().unwrap();

        assert_eq!(BigUint::from(8u8), pub_key);
    }
    #[test]
    fn test_get_secret() {
        let mut client_a = Client::new().unwrap();

        client_a.a = BigUint::from(6u8);
        client_a.g = BigUint::from(5u8);
        client_a.p = BigUint::from(23u8);

        let mut client_b = Client::new().unwrap();

        client_b.a = BigUint::from(15u8);
        client_b.g = BigUint::from(5u8);
        client_b.p = BigUint::from(23u8);

        let client_a_pub_key = client_a.get_public_key().unwrap();
        let client_b_pub_key = client_b.get_public_key().unwrap();

        let shared_secret = client_a.get_secret(client_b_pub_key);

        assert_eq!(shared_secret, client_b.get_secret(client_a_pub_key));
    }
}
