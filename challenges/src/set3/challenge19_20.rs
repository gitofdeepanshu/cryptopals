pub mod set3;
use std::fs;

use set3::utils::{aes_ctr_decrypt, aes_ctr_encrypt};
fn main() {
    let file = fs::read_to_string("./text.txt").expect("Unable to read file");
    let file_contents = file.split_whitespace().collect::<Vec<&str>>();

    let mut vec_of_encrypted = Vec::new();
    let key = "YELLOW SUBMARINE";

    (0..file_contents.len()).map(|i| vec_of_encrypted.push(aes_ctr_encrypt(file_contents[i].as_bytes(), key.as_bytes())));
   
    
    // for i in 0..file_contents.len() {
    //     let res = aes_ctr_encrypt(file_contents[i].as_bytes(), key.as_bytes());
    //     vec_of_encrypted.push(res.chunks(16).map(|x| x.to_vec()).collect::<Vec<Vec<u8>>>());
    // }

    // let abc = vec_of_encrypted.iter().map(|x| x[0]).collect::<Vec<Vec<u8>>>();
}

fn break_key(similar_key : Vec<Vec<u8>>){
    let mut 
}
