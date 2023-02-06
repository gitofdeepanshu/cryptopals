pub mod set3;

use set3::utils::{untemper, MersenneTwister};
fn main() {
    let mut random_num_gen = MersenneTwister::new(123456789);
    let mut collection_of_624 = Vec::new();
    for _ in 0..624 {
        collection_of_624.push(random_num_gen.extract_number());
    }

    println!(
        "Actual next Random Number {}, Predicted next Random Number {}",
        random_num_gen.extract_number(),
        predict_next(collection_of_624)
    )
}
fn predict_next(collection: Vec<u32>) -> u32 {
    let mut untempered = collection.iter().map(|&x| untemper(x)).collect();

    generate_number(&mut untempered);
    extract_number(untempered)
}
fn generate_number(a: &mut Vec<u32>) {
    for i in 0..624 {
        let y = (a[i] & 0x80000000) + (a[(i + 1) % 624] & 0x7fffffff);
        a[i] = a[(i + 397) % 624] ^ y >> 1;

        if y % 2 != 0 {
            a[i] = a[i] ^ 0x9908b0df;
        }
    }
}
fn extract_number(a: Vec<u32>) -> u32 {
    let mut y = a[0];

    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c_5680;
    y ^= (y << 15) & 0xefc6_0000;
    y ^= y >> 18;
    y
}
