fn aes_encrypt(pt: &str, key: &str, iv: &[u8]) -> String {
    let mut pt = pt.as_bytes().to_vec();

    //padding
    let padding_size = 16 - pt.len() % 16;
    let padding_char = padding_size as u8;
    let mut padding: Vec<u8> = (0..padding_size).map(|_| (padding_char)).collect();

    pt.append(&mut padding);

    //IV Implemented
    for i in 0..16usize {
        pt[i] = pt[i] ^ iv[i];
    }

    // AES PreRequisite
    let cipher = Aes128::new(GenericArray::from_slice(key.as_bytes()));

    let mut blocks: Vec<GenericArray<u8, U16>> = pt
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    //Encryption

    //encrpyt first block
    cipher.encrypt_block(&mut blocks[0]);

    for i in 1..blocks.len() {
        blocks[i] = xor_block(blocks[i], blocks[i - 1]);
        cipher.encrypt_block(&mut blocks[i]);
    }

    let result = blocks
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect::<Vec<u8>>();
    // dbg!(&result);

    base64::encode(result)
}

fn xor_block<T: IntoIterator<Item = u8>>(a: GenericArray<u8, U16>, b: T) -> GenericArray<u8, U16> {
    let mut a = a.into_iter().collect::<Vec<u8>>();
    let b = b.into_iter().collect::<Vec<u8>>();
    for i in 0..16usize {
        a[i] = a[i] ^ b[i];
    }
    *GenericArray::from_slice(&a)
}

fn aes_decrypt(ct: &str, key: &str, iv: &[u8]) {
    let ct = base64::decode(ct).unwrap();

    let mut blocks: Vec<GenericArray<u8, U16>> = ct
        .chunks(16)
        .map(|x| *GenericArray::from_slice(x))
        .collect();

    let cipher = Aes128::new(GenericArray::from_slice(key.as_bytes()));

    let total_blocks = blocks.len() - 1;
    dbg!(total_blocks);
    for i in 0..blocks.len() {
        cipher.decrypt_block(&mut blocks[total_blocks - i]);
        if i < total_blocks {
            blocks[total_blocks - i] =
                xor_block(blocks[total_blocks - i], blocks[total_blocks - i - 1]);
        }
    }

    //IV Implementation
    blocks[0] = xor_block(blocks[0], iv.to_vec());

    let result = blocks
        .into_iter()
        .flat_map(|x| x.into_iter())
        .collect::<Vec<u8>>();

    println!("{}", String::from_utf8(result).unwrap());
}
