pub mod set4;
use set4::hmac_client;
use set4::hmac_server;
use set4::utils::SHA1;

//
// INCOMPLETE
//
fn main() {
    run();
}
pub fn run() -> Result<()> {
    println!(
    "Challenge 32: Please be sure to run this challenge in release mode because it depends on the timing of the code.
            Takes about three minutes, please wait ...");
    let mut rng = rand::thread_rng();
    let key: Vec<u8> = rng.gen_iter().take(20).collect();

    let mut server = hmac_server::start(key)?;
    let result = hmac_client::run();
    server.close().map_err(|err| AnnotatedError {
        message: "failed to close connection".to_string(),
        error: err.into(),
    })?;

    result
}
