use super::utils_client::{Attacker, Client};
use super::utils_communication::{Protocol, Request, Response, Serialize};

use num_bigint::{BigInt, BigUint};
use std::io;
use std::{net::SocketAddr, net::TcpListener, thread};

pub fn main() -> io::Result<()> {
    let attacker = Attacker {};

    let mut protocol_a = Protocol::connect("127.0.0.1:3739".parse().unwrap())?;
    let mut protocol_b = Protocol::connect("127.0.0.1:3735".parse().unwrap())?;

    let intercepted_params = protocol_b.read_message::<Request>()?;
    println!(
        "Intercepted message from B with paramters {:?}",
        &intercepted_params
    );
    let (mut new_p, mut new_g) = (BigUint::from(0u8), BigUint::from(0u8));

    match intercepted_params {
        Request::Parameters { p, g, a } => {
            new_p = p;
            new_g = g;
        }
        _ => panic!("Data Corrupted!"),
    };

    let infected_paramaters = Request::Parameters {
        p: new_p.clone(),
        g: new_g,
        a: new_p.clone(),
    };

    println!(
        "Sending infected Paramters to A : {:?}",
        &infected_paramaters
    );
    protocol_a.send_message(&infected_paramaters);
    println!("Infected paramters sent to A");

    println!("Waiting for public key of A");

    //Discarding the public key of A because it's useless for us
    protocol_a.read_message::<Response>()?;

    let res = Response::PublicKey(new_p.clone());
    println!("Sending P back to B");

    protocol_b.send_message(&res)?;

    println!("Sent infected Public key to B, waiting for secret message of which key is 0");
    let req = protocol_b.read_message::<Request>()?;

    println!(
        "Received a secret message from B: {}",
        decrypt_secret_message_req(&req)
    );

    println!("Sending it back to A");
    protocol_a.send_message(&req);

    println!("A sending back the response of secret message");
    let res = protocol_a.read_message::<Response>()?;

    println!(
        "Received a secret message from A: {}",
        decrypt_secret_message_res(&res)
    );
    println!("Sending it back to B");

    protocol_b.send_message(&res);
    read_and_forward(&mut protocol_a, &mut protocol_b)?;

    Ok(())
}

fn decrypt_secret_message_req(req: &Request) -> String {
    let attacker = Attacker {};
    let ct_with_iv: &Vec<u8>;
    match req {
        Request::SecretKey(x) => {
            ct_with_iv = x;
        }
        _ => panic!("Data Corrupted!"),
    };
    attacker
        .decrypt_message(&ct_with_iv)
        .expect("Can't convert to String")
}
fn decrypt_secret_message_res(req: &Response) -> String {
    let attacker = Attacker {};
    let ct_with_iv: &Vec<u8>;
    match req {
        Response::SecretKey(x) => {
            ct_with_iv = x;
        }
        _ => panic!("Data Corrupted!"),
    };
    attacker
        .decrypt_message(&ct_with_iv)
        .expect("Can't convert to String")
}

fn read_and_forward(sender: &mut Protocol, receiver: &mut Protocol) -> io::Result<()> {
    let res = sender.read_message::<Response>()?;
    println!(
        "Received a secret message: {}",
        decrypt_secret_message_res(&res)
    );
    receiver.send_message(&res)
}
