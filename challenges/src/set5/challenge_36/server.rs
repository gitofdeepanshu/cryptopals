use crate::set5::challenge_36::{
    protocol::{Protocol, Request},
    utils::Server,
};
use std::{
    io,
    net::{TcpListener, TcpStream},
    thread,
};

pub fn main() {
    let listener = TcpListener::bind("127.0.0.1:3225").expect("Can't bind to the port");

    println!("Server started listenening!");
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            thread::spawn(move || handle_connection(stream));
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut protocol = Protocol::with_stream(stream).expect("Can't initialize a protocol instance");
    let server = Server::new();

    let (client_pub_key, email_address) = match protocol.read_message::<Request>().unwrap() {
        Request::ClientCredentials { pub_key, email } => (pub_key, email),
        _ => panic!("Couldn't get the pub key"),
    };

    let req_containing_b = Request::B {
        salt: server.get_salt(),
        b: server.b(),
    };

    protocol.send_message(&req_containing_b)?;

    let session_key_by_client = match protocol.read_message::<Request>()? {
        Request::SessionKey(a) => a,
        _ => panic!("couldn't get the session key"),
    };
    let session_key_self = server.calculate_s(&client_pub_key);

    if session_key_by_client == session_key_self {
        println!("Session Key matched!, Connection Established");
        protocol.send_message(&Request::OK("Connection Established!".to_string()))?;
    }

    Ok(())
}
