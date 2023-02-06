pub struct SHA1 {
    pub h: [u32; 5],
    pub m: Vec<u32>,
}

impl SHA1 {
    //initialize
    pub fn new(
        a: Option<u32>,
        b: Option<u32>,
        c: Option<u32>,
        d: Option<u32>,
        e: Option<u32>,
    ) -> SHA1 {
        let mut h = [0u32; 5];
        h[0] = a.unwrap_or(0x67452301);
        h[1] = b.unwrap_or(0xEFCDAB89);
        h[2] = c.unwrap_or(0x98BADCFE);
        h[3] = d.unwrap_or(0x10325476);
        h[4] = e.unwrap_or(0xC3D2E1F0);

        SHA1 { h, m: Vec::new() }
    }
    pub fn digest(&mut self, msg: &[u8]) -> Vec<u8> {
        self.preprocess(msg);
        for i in 0..self.m.len() / 16 {
            let words: [u32; 16] = self.m[(16 * i)..((16 * i) + 16)]
                .try_into()
                .expect("slice with incorrect length");

            self.process(&words);
        }
        // format!(
        //     "{}{}{}{}{}",
        //     self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]
        // )
        // self.m.chunks(16).for_each(|x| self.process(x))
        self.h[0]
            .to_be_bytes()
            .iter()
            .chain(self.h[1].to_be_bytes().iter())
            .chain(self.h[2].to_be_bytes().iter())
            .chain(self.h[3].to_be_bytes().iter())
            .chain(self.h[4].to_be_bytes().iter())
            .copied()
            .collect::<Vec<u8>>()
    }

    fn preprocess(&mut self, msg: &[u8]) {
        //message padding:

        let len = u64::try_from(msg.len() * 8)
            .expect("Can't convert length to u64")
            .to_be_bytes();

        let first_block = [128u8; 1];
        let mut zero_block = Vec::new();

        (0..(64 - (msg.len() + 9) % 64)).for_each(|_| zero_block.push(0u8));

        let final_msg = msg
            .iter()
            .chain(first_block.iter())
            .chain(zero_block.iter())
            .chain(len.iter())
            .copied()
            .collect::<Vec<u8>>();

        final_msg.chunks(4).for_each(|x| {
            self.m.push(u32::from_be_bytes(
                x.try_into().expect("slice with incorrect length"),
            ))
        })
    }

    fn process(&mut self, words: &[u32]) {
        let mut new_words = [0u32; 80].to_vec();
        (0..16usize).for_each(|i| new_words[i] = words[i]);

        for i in 16..80_usize {
            new_words[i] = SHA1::circular_left_shift(
                new_words[i - 3] ^ new_words[i - 8] ^ new_words[i - 14] ^ new_words[i - 16],
                1,
            );
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut temp: u32;

        for i in 0..80usize {
            temp = SHA1::circular_left_shift(a, 5)
                .wrapping_add(SHA1::magic(i, b, c, d))
                .wrapping_add(e)
                .wrapping_add(new_words[i])
                .wrapping_add(SHA1::return_k_value(i));

            e = d;
            d = c;
            c = SHA1::circular_left_shift(b, 30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    fn circular_left_shift(a: u32, value: u32) -> u32 {
        (a << value) | (a >> 32 - value)
    }

    fn magic(t: usize, b: u32, c: u32, d: u32) -> u32 {
        if t >= 0 && t <= 19 {
            return (b & c) | ((!b) & d);
        } else if t >= 40 && t <= 59 {
            return (b & c) | (b & d) | (c & d);
        } else {
            return b ^ c ^ d;
        }
    }
    fn return_k_value(value: usize) -> u32 {
        if value >= 0 && value <= 19 {
            return 0x5A827999;
        } else if value >= 20 && value <= 39 {
            return 0x6ED9EBA1;
        } else if value >= 40 && value <= 59 {
            return 0x8F1BBCDC;
        } else {
            return 0xCA62C1D6;
        }
    }

    pub fn process_self(&mut self, words: &[u32]) -> (u32, u32, u32, u32, u32) {
        let mut new_words = [0u32; 80].to_vec();
        (0..16usize).for_each(|i| new_words[i] = words[i]);

        for i in 16..80_usize {
            new_words[i] = SHA1::circular_left_shift(
                new_words[i - 3] ^ new_words[i - 8] ^ new_words[i - 14] ^ new_words[i - 16],
                1,
            );
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut temp: u32;

        for i in 0..80usize {
            temp = SHA1::circular_left_shift(a, 5)
                .wrapping_add(SHA1::magic(i, b, c, d))
                .wrapping_add(e)
                .wrapping_add(new_words[i])
                .wrapping_add(SHA1::return_k_value(i));

            e = d;
            d = c;
            c = SHA1::circular_left_shift(b, 30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);

        (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4])
    }
}
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let opad: [u8; 64] = [0x5c; 64];
    let ipad: [u8; 64] = [0x36; 64];
    let mut final_key = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = SHA1::new(None, None, None, None, None);
        let key = &hasher.digest(key);
        final_key[0..key.len()].copy_from_slice(key);
    } else {
        (0..key.len()).for_each(|x| final_key[x] = key[x]);
    }
    let prefix = final_key
        .iter()
        .zip(opad.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>();

    let mut suffix_hasher = SHA1::new(None, None, None, None, None);
    let suffix = suffix_hasher.digest(
        &final_key
            .iter()
            .zip(ipad.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>()
            .iter()
            .chain(msg.iter())
            .copied()
            .collect::<Vec<u8>>(),
    );
    let mut final_hasher = SHA1::new(None, None, None, None, None);
    final_hasher.digest(
        &prefix
            .iter()
            .chain(suffix.iter())
            .copied()
            .collect::<Vec<u8>>(),
    )
}
