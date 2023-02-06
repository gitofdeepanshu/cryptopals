use super::utils_client::Client;
use super::utils_communication::{Protocol, Request, Response};
use std::io::{self, Error};
use std::net::TcpStream;
use std::{net::TcpListener, thread};

use num_bigint::{BigInt, BigUint};

pub fn main() {
    let listener = TcpListener::bind("127.0.0.1:3739").expect("Can't bind!");
    println!("A started listeinng!");
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = thread::spawn(move || {
                handle_connection(stream);
            });
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut protocol = Protocol::with_stream(stream)?;
    println!("Thread received at A");
    let params = protocol.read_message::<Request>()?;
    println!("A received a req from B with paramters : {:?}", &params);
    let mut client_a = Client::new()?;
    let public_key_b: BigUint;
    match params {
        Request::Parameters { p, g, a } => {
            client_a.g = g;
            client_a.p = p;
            client_a.a = BigUint::from(6u8);
            public_key_b = a;
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid!"));
        }
    }
    println!("A initilaized with {:?}", &client_a);

    let res = Response::PublicKey(client_a.get_public_key()?);
    println!("Sending A's public key to B {:?}", &res);
    protocol.send_message(&res)?;

    let received_bytes: Vec<u8>;
    println!("Reading secret message from B and trying to extract text");
    match protocol.read_message::<Request>()? {
        Request::SecretKey(x) => {
            received_bytes = x;
            println!("Message successfully Read, now trying to decrypt it!");
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid!"));
        }
    }

    let receieved_message = client_a
        .decrypt_message(public_key_b.clone(), &received_bytes)
        .unwrap();
    println!("B sent a string {}", &receieved_message);
    let ct = client_a.send_encrypted_message(receieved_message.as_bytes(), public_key_b.clone())?;
    let res = Response::SecretKey(ct);
    println!("Sending B the same message encrypted with B's public key");
    protocol.send_message(&res)?;
    println!("Final message sent!");

    let res = send_message(
        "I am so smart!".to_string(),
        public_key_b.clone(),
        &client_a,
    )?;
    protocol.send_message(&res)?;
    println!(" message sent!");

    let res = send_message(
        "We are so very smart!!! HHAHAHAHAH".to_string(),
        public_key_b,
        &client_a,
    )?;
    protocol.send_message(&res)?;
    println!(" message sent!");
    Ok(())
}
fn send_message(msg: String, public_key_b: BigUint, client_a: &Client) -> io::Result<Response> {
    let ct = client_a.send_encrypted_message(msg.as_bytes(), public_key_b)?;
    let res = Response::SecretKey(ct);
    println!("Sending B new message encrypted with B's public key");
    Ok(res)
}
