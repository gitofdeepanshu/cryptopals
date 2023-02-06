use super::{
    protocol::{Protocol, Request},
    utils::Client,
};

pub fn main() {
    let mut protocol = Protocol::connect("127.0.0.1:3225".parse().unwrap())
        .expect("Can't connect to the socket addr");
    let client = Client::new();

    protocol
        .send_message(&Request::ClientCredentials {
            pub_key: client.get_pub_key(),
            email: "email@email.com".to_string(),
        })
        .unwrap();

    let (salt, b) = match protocol.read_message::<Request>().unwrap() {
        Request::B { b, salt } => (salt, b),
        _ => panic!("Error Occured!"),
    };

    protocol
        .send_message(&Request::SessionKey(client.calculate_s(&salt, &b)))
        .expect("Can't send message!");

    match protocol.read_message::<Request>().unwrap() {
        Request::OK(s) => println!("{s}"),
        _ => panic!("Error Occured!"),
    };
}
