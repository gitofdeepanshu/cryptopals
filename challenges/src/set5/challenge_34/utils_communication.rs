use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
#[derive(Debug)]
pub enum Request {
    Parameters { p: BigUint, g: BigUint, a: BigUint },
    SecretKey(Vec<u8>),
}
#[derive(Debug)]
pub enum Response {
    PublicKey(BigUint),
    SecretKey(Vec<u8>),
}

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
            Request::Parameters { p, g, a } => 1,
            Request::SecretKey(_) => 2,
        }
    }
}

impl From<&Response> for u8 {
    fn from(res: &Response) -> Self {
        match res {
            Response::PublicKey(_) => 1,
            Response::SecretKey(_) => 2,
        }
    }
}

impl Serialize for Request {
    fn serialize(&self, buf: &mut impl Write) -> io::Result<usize> {
        let mut total_written = 0usize;
        buf.write_u8(self.into())?;
        total_written += 1;

        match self {
            Request::Parameters { p, g, a } => {
                total_written += serialize_bigunit(p, buf)?;
                total_written += serialize_bigunit(g, buf)?;
                total_written += serialize_bigunit(a, buf)?;
            }
            Request::SecretKey(a) => {
                let len = a.len();
                buf.write_u16::<NetworkEndian>(len as u16)?;
                buf.write_all(a)?;

                total_written += 2 + len;
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
                let p = deserialize_bigunit(buf)?;
                let g = deserialize_bigunit(buf)?;
                let a = deserialize_bigunit(buf)?;
                Ok(Request::Parameters { p, g, a })
            }
            2 => {
                let len = buf.read_u16::<NetworkEndian>()?;
                let mut new_buffer = vec![0u8; len as usize];
                buf.read_exact(&mut new_buffer)?;
                Ok(Request::SecretKey(new_buffer))
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

impl Serialize for Response {
    fn serialize(&self, buf: &mut impl Write) -> io::Result<usize> {
        let mut total_bytes_written = 0;
        buf.write_u8(self.into())?;
        total_bytes_written += 1;
        match self {
            Response::PublicKey(a) => {
                total_bytes_written += serialize_bigunit(a, buf)?;
            }
            Response::SecretKey(a) => {
                let len = a.len();
                buf.write_u16::<NetworkEndian>(len as u16)?;
                buf.write_all(a)?;

                total_bytes_written += 2 + len;
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Data Invalid")),
        }
        Ok(total_bytes_written)
    }
}

impl Deserialize for Response {
    type Output = Response;

    fn deserialize(buf: &mut impl Read) -> io::Result<Self::Output> {
        let res_type = buf.read_u8()?;

        match res_type {
            1 => {
                let public_key = deserialize_bigunit(buf)?;
                Ok(Response::PublicKey(public_key))
            }
            2 => {
                let len = buf.read_u16::<NetworkEndian>()?;
                let mut new_buffer = vec![0u8; len as usize];
                buf.read_exact(&mut new_buffer)?;
                Ok(Response::SecretKey(new_buffer))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Data Invalid")),
        }
    }
}
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

#[cfg(test)]

mod test {
    use super::*;
    use std::{io::Cursor, str::FromStr};

    #[test]
    fn test_roundtrip_req_parameters() {
        let p = BigUint::from_str("5").expect("Can't convert to BigUint");
        let g = BigUint::from_str("6").expect("Can't convert to BigUint");
        let a = BigUint::from_str("7").expect("Can't convert to BigUint");
        let req = Request::Parameters { p, g, a };
        println!("{:?}", &req);

        let mut buf = Vec::new();
        req.serialize(&mut buf).unwrap();

        let mut reader = Cursor::new(buf);
        let roundtrip = Request::deserialize(&mut reader).unwrap();
        println!("{:?}", &roundtrip);
        assert!(matches!(roundtrip, Request::Parameters { .. }));
    }
    #[test]
    fn test_roundtrip_req_secret() {
        let req = Request::SecretKey(vec![0, 1, 2, 3]);
        println!("{:?}", &req);

        let mut buf = Vec::new();
        req.serialize(&mut buf).unwrap();

        let mut reader = Cursor::new(buf);
        let roundtrip = Request::deserialize(&mut reader).unwrap();
        println!("{:?}", &roundtrip);
        assert!(matches!(roundtrip, Request::SecretKey(_)));
    }
    #[test]
    fn test_roundtrip_res_public_key() {
        let a = BigUint::from_str("525646464").unwrap();
        let res = Response::PublicKey(a);
        println!("{:?}", &res);

        let mut buf = Vec::new();
        res.serialize(&mut buf);

        let mut reader = Cursor::new(buf);

        let roundtrip = Response::deserialize(&mut reader).unwrap();
        println!("{:?}", roundtrip);

        assert!(matches!(roundtrip, Response::PublicKey(_)));
    }
    #[test]

    fn test_roundtrip_res_secret() {
        let res = Response::SecretKey(vec![0, 1, 2, 3, 4, 5]);
        println!("{:?}", &res);

        let mut buf = Vec::new();
        res.serialize(&mut buf);

        let mut reader = Cursor::new(buf);

        let roundtrip = Response::deserialize(&mut reader).unwrap();
        println!("{:?}", roundtrip);

        assert!(matches!(roundtrip, Response::SecretKey(_)));
    }
}
