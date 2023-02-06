use lazy_static::__Deref;
use num_bigint::{BigUint, RandBigInt};
use once_cell;
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use sha256::{digest, try_digest};
pub const N: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

// pub const NIST_PRIME: BigUint = BigUint::parse_bytes(N.as_bytes(), 16).unwrap();
static NIST_PRIME: Lazy<BigUint> = Lazy::new(|| BigUint::parse_bytes(N.as_bytes(), 16).unwrap());
static G: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u8));
static K: Lazy<BigUint> = Lazy::new(|| BigUint::from(3u8));

pub const P_PASSWORD: &str = "password";

#[derive(Debug)]
pub struct Client {
    secret: BigUint,
}
impl Client {
    pub fn new() -> Client {
        Client {
            secret: random_salt(),
        }
    }
    pub fn get_pub_key(&self) -> BigUint {
        G.deref().modpow(&self.secret, NIST_PRIME.deref())
    }

    pub fn calculate_s(&self, salt: &BigUint, b: &BigUint) -> BigUint {
        let exponent = (&self.secret + calculate_uh(&self.get_pub_key(), b) * calculate_xh(salt))
            % NIST_PRIME.deref();

        let kv = &(K.deref() * (G.deref().modpow(&calculate_xh(salt), NIST_PRIME.deref()))
            % NIST_PRIME.deref());

        let base = (b - kv) % NIST_PRIME.deref();

        let s = base.modpow(&exponent, NIST_PRIME.deref()).to_bytes_be();

        let digest = digest(&*s);
        BigUint::parse_bytes(digest.as_bytes(), 16).unwrap()
    }
    pub fn gen_xh(&self, salt: &BigUint) -> BigUint {
        calculate_xh(salt)
    }
}
#[derive(Debug)]
pub struct Server {
    salt: BigUint,
    v: BigUint,
    secret: BigUint,
}

impl Server {
    pub fn new() -> Server {
        let secret_int = random_salt(); // this is b

        let salt = random_salt();
        let salted_pass = calculate_xh(&salt);

        Server {
            salt,
            v: gen_pub_key(&salted_pass),
            secret: secret_int,
        }
    }
    pub fn get_salt(&self) -> BigUint {
        self.salt.clone()
    }
    // pub fn get_pub_key(&self) -> BigUint {
    //     gen_pub_key(&self.secret)
    // }
    pub fn b(&self) -> BigUint {
        let kv = K.deref() * &self.v;

        let pub_key = G.deref().modpow(&self.secret, NIST_PRIME.deref());

        kv + pub_key
    }

    pub fn calculate_s(&self, pub_key_client: &BigUint) -> BigUint {
        let u = &calculate_uh(pub_key_client, &self.b());
        let s = (pub_key_client * self.v.modpow(u, NIST_PRIME.deref()))
            .modpow(&self.secret, NIST_PRIME.deref())
            .to_bytes_be();

        println!("s is {:?}", &s);
        let digest = digest(&*s);
        BigUint::parse_bytes(digest.as_bytes(), 16).unwrap()
    }
}

fn calculate_xh(salt: &BigUint) -> BigUint {
    let mut salt = salt.to_bytes_be();
    let mut pass = P_PASSWORD.as_bytes().to_vec();
    salt.append(&mut pass);

    let digest = digest(&*salt);

    BigUint::parse_bytes(digest.as_bytes(), 16).unwrap()
}
fn gen_pub_key(x: &BigUint) -> BigUint {
    G.deref().modpow(&x, &NIST_PRIME)
}
fn random_salt() -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint(100)
}
fn calculate_uh(pub_key_client: &BigUint, b: &BigUint) -> BigUint {
    let mut pub_client = pub_key_client.to_bytes_be();
    let mut pub_self = b.to_bytes_be();
    pub_client.append(&mut pub_self);

    let digest = digest(&*pub_client);

    BigUint::parse_bytes(digest.as_bytes(), 16).unwrap()
}

#[cfg(test)]

mod test {
    use super::*;
    use std::{io::Cursor, str::FromStr};

    #[test]
    fn test_s_equality() {
        let server = Server::new();
        let client = Client::new();

        let client_pub_key = client.get_pub_key();
        let server_send_b = server.b();

        let server_salt = server.get_salt();

        let client_s = client.calculate_s(&server_salt, &server_send_b);
        let server_s = server.calculate_s(&client_pub_key);

        assert_eq!(client_s, server_s);
    }
    #[test]
    fn test_with_zero_key_client() {
        let server = Server::new();

        let server_s = server.calculate_s(&BigUint::from(0u8));

        let digest = digest(&[0u8]);
        let malicious_s = BigUint::parse_bytes(digest.as_bytes(), 16).unwrap();
        // println!("{}", &server_s);

        assert_eq!(malicious_s, server_s);
    }
    #[test]
    fn test_with_n_factor_client() {
        let server = Server::new();

        let server_s = server.calculate_s(&NIST_PRIME.deref());

        let digest = digest(&[0u8]);
        let malicious_s = BigUint::parse_bytes(digest.as_bytes(), 16).unwrap();
        // println!("{}", &server_s);

        assert_eq!(malicious_s, server_s);
    }
}
