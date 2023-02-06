fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    if a[1] == "1".to_string() {
        main_a();
    } else if a[1] == "2".to_string() {
        main_b();
    } else {
        main_attacker().unwrap();
    }
}
