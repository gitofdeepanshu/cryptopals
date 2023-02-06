pub mod set3;
use rand::Rng;
use set3::utils::MersenneTwister;
fn main() {
    let pt = [15u8; 15].to_vec();

    let mut rng = rand::thread_rng();
    let seed: u32 = u32::try_from(rng.gen::<u16>()).expect("Can't convert Random u16 to u32");

    println!(
        "Actual seed {}, Calculated Seed {} ",
        seed,
        find_key(&random_encrypter(&pt, seed)).expect("Couldn't find the key")
    )
}

fn mt19937_stream_cipher_encrypt(seed: u32, pt: &[u8]) -> Vec<u8> {
    let mut twister = MersenneTwister::new(seed);

    (0..pt.len())
        .map(|x| pt[x] ^ generate_twister(&mut twister))
        .collect::<Vec<u8>>()
}

fn generate_twister(a: &mut MersenneTwister) -> u8 {
    (a.extract_number() & 255).try_into().unwrap()
}

fn mt19937_stream_cipher_decrypt(seed: u32, ct: &[u8]) -> Vec<u8> {
    mt19937_stream_cipher_encrypt(seed, ct)
}

fn random_encrypter(pt: &[u8], seed: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let random_message = (0u8..rng.gen())
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>()
        .iter()
        .chain(pt.iter())
        .copied()
        .collect::<Vec<u8>>();

    mt19937_stream_cipher_encrypt(seed, &random_message)
}
fn find_key(ct: &[u8]) -> Result<u32, ()> {
    for i in 0..65534u32 {
        if mt19937_stream_cipher_decrypt(i, ct)
            .iter()
            .rev()
            .take(15)
            .all(|&x| x == 15)
        {
            return Ok(i);
        }
    }
    return Err(());
}
