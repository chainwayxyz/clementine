use std::io::{Write, self};

use sha2::{Digest, Sha256};

pub fn take_stdin<T: std::str::FromStr>(prompt: &str) -> Result<T, T::Err> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut string = String::new();
    io::stdin()
        .read_line(&mut string)
        .expect("Failed to read line");

    string.trim().parse::<T>()
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().try_into().unwrap()
}
