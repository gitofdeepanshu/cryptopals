use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
#[derive(Debug)]
pub enum Request {
    ClientCredentials { pub_key: BigUint, email: String },
    B { b: BigUint, salt: BigUint },
    SessionKey(BigUint),
    OK(String),
}
// #[derive(Debug)]
// pub enum Response {
//     PublicKey(BigUint),
//     SecretKey(Vec<u8>),
// }

pub trait Serialize {
    fn serialize(&self, buf: &mut impl Write) -> io::Result<usize>;
}
pub trait Deserialize {
    type Output;
    fn deserialize(buf: &mut impl Read) -> io::Result<Self::Output>;
}

impl From<&Request> for u8 {
    fn from(req: &Request) -> Self {
        match req {
            Request::ClientCredentials { .. } => 1,
            Request::B { .. } => 2,
            Request::SessionKey(_) => 3,
            Request::OK(_) => 4,
        }
    }
}

// impl From<&Response> for u8 {
//     fn from(res: &Response) -> Self {
//         match res {
//             Response::PublicKey(_) => 1,
//             Response::SecretKey(_) => 2,
//         }
//     }
// }

impl Serialize for Request {
    fn serialize(&self, buf: &mut impl Write) -> io::Result<usize> {
        let mut total_written = 0usize;
        buf.write_u8(self.into())?;
        total_written += 1;

        match self {
            Request::ClientCredentials { pub_key, email } => {
                total_written += serialize_bigunit(pub_key, buf)?;
                let email_len = email.len();

                buf.write_u16::<NetworkEndian>(email_len as u16)?;
                total_written += 2;
                buf.write(email.as_bytes())?;
                total_written += email_len;
            }
            Request::B { b, salt } => {
                total_written += serialize_bigunit(b, buf)?;
                total_written += serialize_bigunit(salt, buf)?;
            }
            Request::SessionKey(s) => {
                total_written += serialize_bigunit(s, buf)?;
            }
            Request::OK(s) => {
                let len = s.len();
                total_written += 2;
                buf.write_u16::<NetworkEndian>(len as u16)?;
                buf.write_all(s.as_bytes())?;
                total_written += len;
            }

            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Data")),
        }
        Ok(total_written)
    }
}

fn serialize_bigunit(a: &BigUint, buf: &mut impl Write) -> io::Result<usize> {
    let a_bytes = a.to_bytes_be();
    let a_len = a_bytes.len();
    buf.write_u16::<NetworkEndian>(a_len as u16)?;
    buf.write(&a_bytes)?;

    Ok(a_len + 2)
}

impl Deserialize for Request {
    type Output = Request;

    fn deserialize(buf: &mut impl Read) -> io::Result<Self::Output> {
        let res_type = buf.read_u8()?;

        match res_type {
            1 => {
                let pub_key = deserialize_bigunit(buf)?;

                let len = buf.read_u16::<NetworkEndian>()?;
                let mut new_buf = vec![0u8; len as usize];
                buf.read_exact(&mut new_buf)?;
                Ok(Request::ClientCredentials {
                    pub_key,
                    email: String::from_utf8(new_buf).unwrap(),
                })
            }
            2 => {
                let b = deserialize_bigunit(buf)?;
                let salt = deserialize_bigunit(buf)?;
                Ok(Request::B { b, salt })
            }
            3 => {
                let s = deserialize_bigunit(buf)?;

                Ok(Request::SessionKey(s))
            }
            4 => {
                let len = buf.read_u16::<NetworkEndian>()?;
                let mut new_buf = vec![0u8; len as usize];
                buf.read_exact(&mut new_buf)?;
                Ok(Request::OK(
                    String::from_utf8(new_buf).expect("Can't convert to string"),
                ))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Data Invalid")),
        }
    }
}

fn deserialize_bigunit(buf: &mut impl Read) -> io::Result<BigUint> {
    let len = buf.read_u16::<NetworkEndian>()?;
    let mut new_buffer = vec![0u8; len as usize];
    buf.read_exact(&mut new_buffer)?;
    Ok(BigUint::from_bytes_be(&new_buffer))
}

// impl Serialize for Response {
//     fn serialize(&self, buf: &mut impl Write) -> io::Result<usize> {
//         let mut total_bytes_written = 0;
//         buf.write_u8(self.into())?;
//         total_bytes_written += 1;
//         match self {
//             Response::PublicKey(a) => {
//                 total_bytes_written += serialize_bigunit(a, buf)?;
//             }
//             Response::SecretKey(a) => {
//                 let len = a.len();
//                 buf.write_u16::<NetworkEndian>(len as u16)?;
//                 buf.write_all(a)?;

//                 total_bytes_written += 2 + len;
//             }
//             _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Data Invalid")),
//         }
//         Ok(total_bytes_written)
//     }
// }

// impl Deserialize for Response {
//     type Output = Response;

//     fn deserialize(buf: &mut impl Read) -> io::Result<Self::Output> {
//         let res_type = buf.read_u8()?;

//         match res_type {
//             1 => {
//                 let public_key = deserialize_bigunit(buf)?;
//                 Ok(Response::PublicKey(public_key))
//             }
//             2 => {
//                 let len = buf.read_u16::<NetworkEndian>()?;
//                 let mut new_buffer = vec![0u8; len as usize];
//                 buf.read_exact(&mut new_buffer)?;
//                 Ok(Response::SecretKey(new_buffer))
//             }
//             _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Data Invalid")),
//         }
//     }
// }
#[derive(Debug)]
pub struct Protocol {
    reader: io::BufReader<TcpStream>,
    stream: TcpStream,
}

impl Protocol {
    pub fn with_stream(stream: TcpStream) -> io::Result<Self> {
        let reader = io::BufReader::new(stream.try_clone()?);
        Ok(Self { reader, stream })
    }

    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        eprintln!("Connecting to {}", addr);
        Self::with_stream(stream)
    }
    pub fn send_message(&mut self, message: &impl Serialize) -> io::Result<()> {
        message.serialize(&mut self.stream)?;
        self.stream.flush()
    }
    pub fn read_message<T: Deserialize>(&mut self) -> io::Result<T::Output> {
        T::deserialize(&mut self.reader)
    }
}
