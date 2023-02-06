pub fn pad_pkcs7(message: &str, block_size: usize) -> String {
    let padding_size = block_size - message.len() % block_size;
    let padding_char = padding_size as u8 as char;
    let padding: String = (0..padding_size).map(|_| padding_char).collect();
    format!("Message {} Padding{}.", message, padding)
}
