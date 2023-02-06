fn run() {
    let pt = base64::decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_bytes(),
    )
    .unwrap();
    let key = "YELLOW SUBMARINE";
    println!(
        "{}",
        String::from_utf8(aes_ctr_decrypt(&pt, key.as_bytes())).unwrap()
    );
}
