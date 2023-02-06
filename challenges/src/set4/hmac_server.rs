
use iron::prelude::*;
use iron::status;
use iron::status::Status::InternalServerError;
use iron::status::Status::Ok;
use std::{thread, time};
use params::{Params, Value};
use super::utils::{hmac_sha1};
fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let fifty_millis = time::Duration::from_millis(50);
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
        thread::sleep(fifty_millis);
    }
    true
}

pub fn start(key: Vec<u8>) -> Result<iron::Listening> {
    Iron::new(move |req: &mut Request| handle_request(req, &key))
        .http("localhost:3000")
        .map_err(|err| err.into())
}

fn handle_request(req:&mut Request, key : &[u8]) -> IronResult<Response> {
    if let Some(file , signature) == parse_body(req) {
        if verify_signature (file, signature, key)== true {
            return Ok(Response::with(status::Ok));
        }
    }
    Ok(Response::with(InternalServerError))
}
fn compute_hmac(key : &[u8], msg:&str) -> Vec<u8> {
    hmac_sha1(key, msg.as_bytes())
}
fn verify_signature(file:&str, key:&[u8] ,signature:&str) -> bool {
    let computed_hmac = compute_hmac(key, file);
    insecure_compare(
        &computed_hmac,
        signature.as_bytes())
}
fn parse_body<'a>(req: &'a mut Request) -> Option<(&'a str, &'a str)> {
    let params = req.get_ref::<Params>().ok()?;
    let file = match params.find(&["file"]) {
        Some(&Value::String(ref file)) => file,
        _ => return None,
    };

    let signature = match params.find(&["signature"]) {
        Some(&Value::String(ref signature)) => signature,
        _ => return None,
    };

    Some((file, signature))
}