pub mod set3;
use set3::utils::MersenneTwister;
use std::{
    thread,
    time::{self, SystemTime, UNIX_EPOCH},
};
fn main() {
    let (random_value, seed) = random_twister();
    println!(
        "Expected Seed {}, Seed Found {}",
        seed,
        find_seed(random_value)
    );
}
fn random_twister() -> (u32, u32) {
    let ten_millis = time::Duration::from_millis(12546);

    let current_time: u32 = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    let mut twister = MersenneTwister::new(current_time);
    thread::sleep(ten_millis);
    (twister.extract_number(), current_time)
}

fn find_seed(random_value: u32) -> u32 {
    let current_time: u32 = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    let random = (0..1000u32)
        .find(|&x| {
            let mut twister = MersenneTwister::new(current_time - x);
            twister.extract_number() == random_value
        })
        .unwrap();
    return current_time - random;
}
//challenge 22
