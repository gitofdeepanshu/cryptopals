use super::utils_client::Client;
use super::utils_communication::{Protocol, Request, Response};

use num_bigint::{BigInt, BigUint};
use std::io;
use std::net::TcpStream;
use std::{net::SocketAddr, net::TcpListener, thread};

pub fn main() {
    let listener = TcpListener::bind("127.0.0.1:3735").expect("Can't bind!");
    println!("B started listeinng!");
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = thread::spawn(move || {
                handle_connection(stream);
            });
        }
    }
}
pub fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    println!("B started, sending message");
    let mut client_b = Client::new()?;
    client_b.g = BigUint::from(5u8);
    client_b.p = BigUint::from(23u8);
    client_b.a = BigUint::from(15u8);

    let req = Request::Parameters {
        g: client_b.get_g()?,
        p: client_b.get_p()?,
        a: client_b.get_public_key()?,
    };

    println!("B initialized with parameters {:?}", &client_b);

    let mut protocol = Protocol::with_stream(stream)?;
    println!("B trying to send a REQ to A, with Paramters : {:?}", &req);
    protocol.send_message(&req)?;
    println!("B succesfully sent the paramters to A");
    println!("B awaiting response, expecting public key of A");

    let res = protocol.read_message::<Response>()?;

    println!(
        "Response received from A: Expected a public Key of A{:?}",
        &res
    );
    let public_key_a: BigUint;
    match res {
        Response::PublicKey(x) => {
            public_key_a = x;
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid!"));
        }
    }

    let test_msg = b"Hello from B";
    println!("B sending message Hello from B ecrypted with public key of A");
    let ct = client_b.send_encrypted_message(test_msg, public_key_a.clone())?;

    let hand_shake_req = Request::SecretKey(ct);
    protocol.send_message(&hand_shake_req)?;
    println!("B sent a secret message, let's see if A can decrypt it!");

    if let Ok(res) = protocol.read_message::<Response>() {
        match res {
            Response::SecretKey(x) => {
                if test_msg
                    == client_b
                        .decrypt_message(public_key_a.clone(), &x)?
                        .as_bytes()
                {
                    println!("Connection Secured!!");
                } else {
                    println!(
                        "Something went wrong! msg received is :{:?} expected {:?}",
                        client_b
                            .decrypt_message(public_key_a.clone(), &x)?
                            .as_bytes(),
                        test_msg
                    );
                }
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid!"));
            }
        }
    }
    if let Ok(res) = protocol.read_message::<Response>() {
        match res {
            Response::SecretKey(x) => {
                println!(
                    "ne wmessage recieved {}",
                    client_b.decrypt_message(public_key_a.clone(), &x)?
                );
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid!"));
            }
        }
    }

    Ok(())
}
