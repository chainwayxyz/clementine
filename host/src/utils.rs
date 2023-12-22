use std::{fs::File, io::BufReader};

use serde::de::DeserializeOwned;


pub fn json_to_obj<T: DeserializeOwned>(file_path: &str) -> T {
    let file = File::open(file_path).expect("error");
    let reader = BufReader::new(file);
    let a: T = serde_json::from_reader(reader).expect("error");
    return a;
}
