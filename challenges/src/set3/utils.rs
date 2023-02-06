use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit,
};
use aes::Aes128;
pub fn aes_ctr_encrypt(pt: &[u8], key: &[u8]) -> Vec<u8> {
    let nonce = [0u8; 8].to_vec();
    let mut counter = [0u8; 8].to_vec();

    let mut final_vec = Vec::new();

    // AES PreRequisite
    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut pt_blocks: Vec<Vec<u8>> = pt.chunks(16).map(|x| x.to_vec()).collect();

    for i in 0..pt_blocks.len() {
        let mut block: GenericArray<u8, U16> = *GenericArray::from_slice(
            &(nonce
                .iter()
                .chain(counter.iter())
                .copied()
                .collect::<Vec<u8>>()),
        );
        cipher.encrypt_block(&mut block);

        final_vec.push(
            block
                .iter()
                .zip(pt_blocks[i].iter())
                .map(|(a, b)| a ^ b)
                .collect::<Vec<u8>>(),
        );

        counter[0] = counter[0] + 1;
    }
    final_vec.iter().flat_map(|x| x.iter()).copied().collect()
}

pub fn aes_ctr_decrypt(ct: &[u8], key: &[u8]) -> Vec<u8> {
    aes_ctr_encrypt(ct, key)
}
pub struct MersenneTwister {
    index: usize,
    mt: [u32; 624],
}

impl MersenneTwister {
    // Initialize the Mersenne Twister with a seed value
    pub fn new(seed: u32) -> MersenneTwister {
        let mut mt = [0; 624];
        mt[0] = seed;

        for i in 1..624 {
            mt[i] = 0xffffffff
                & ((mt[i - 1] ^ mt[i - 1] >> 30)
                    .wrapping_mul(1812433253)
                    .wrapping_add(i as u32));
        }

        MersenneTwister { index: 624, mt }
    }

    // Generate a new set of 624 random numbers
    fn generate_numbers(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff);
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1;

            if y % 2 != 0 {
                self.mt[i] = self.mt[i] ^ 0x9908b0df;
            }
        }
    }

    // Extract a random number from the current set of 624 numbers
    pub fn extract_number(&mut self) -> u32 {
        if self.index >= 624 {
            self.generate_numbers();
            self.index = 0;
        }

        let mut y = self.mt[self.index];
        self.index += 1;

        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }
}

fn inv_rs(mut u: u32, k: u32) -> u32 {
    assert!(k >= 1);
    let mut v = u;
    //Would profit from std::u32::BITS
    for _ in 0..=32 / k {
        u >>= k;
        v ^= u;
    }
    v
}
fn inv_lsa(u: u32, k: u32, c: u32) -> u32 {
    assert!(k >= 1);
    let mut v = u;
    //Would profit from std::u32::BITS
    for _ in 0..32 / k {
        v = u ^ (v << k & c);
    }
    v
}
pub fn untemper(u: u32) -> u32 {
    inv_rs(
        inv_lsa(inv_lsa(inv_rs(u, 18), 15, 0xefc6_0000), 7, 0x9d2c_5680),
        11,
    )
}
