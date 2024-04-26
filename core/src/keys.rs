//! # Private and Public Keys
//!
//! This module reads or creates private and public keys depending on what the
//! user is supplying.
//!
//! ## Specifying Files
//!
//! This module accepts a single file as input. It can be specified as
//! environment variable `KEYS`.
//!
//! ## File Format
//!
//! Input file is in JSON file format. It has 3 sections:
//!
//! 1. private: Single private key, as a string
//! 2. public: Multiple public keys, as a string array
//! 3. id: Single number (starts from 0) to select which public key is going to
//! be used, as a number
//!
//! Example:
//!
//! ```json
//! {
//!     "private_key": "987654321",
//!     "public_keys": ["123", "345", "565"],
//!     id: 1
//! }
//! ```
//!
//! In this example, we have a private key of "987654321" and public key of
//! "345".
//!
//! ## Random Key Generation
//!
//! If input file is not specified, key pairs will be generated randomly.

use crate::errors::BridgeError::{self, InvalidKeyPair};
use bitcoin::XOnlyPublicKey;
use crypto_bigint::rand_core::OsRng;
use secp256k1::{All, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::{env, fs, io::Error};

/// Key file's structure.
#[derive(Serialize, Deserialize)]
pub struct FileContents {
    pub private_key: SecretKey,
    pub public_keys: Vec<XOnlyPublicKey>,
    pub id: usize,
}

/// Environment variable that points to the file that has private key and public
/// keys.
const ENV_FILE: &str = "KEYS";

/// Reads private key, public keys and id from a file if `ENV_FILE` is
/// specified.
pub fn get_from_file() -> Result<(SecretKey, Vec<XOnlyPublicKey>), BridgeError> {
    let env_file = env::var(ENV_FILE);

    match env_file {
        Ok(file) => match read_file(file) {
            Ok(content) => Ok(content),
            Err(e) => Err(e),
        },
        Err(_) => Err(InvalidKeyPair(Error::last_os_error())),
    }
}

/// Internal function for reading contents of the key file. If file is readable
/// and in right format, returns target key pair.
pub fn read_file(name: String) -> Result<(SecretKey, Vec<XOnlyPublicKey>), BridgeError> {
    match fs::read_to_string(name) {
        Ok(content) => match serde_json::from_str::<FileContents>(&content) {
            Ok(deserialized) => Ok((deserialized.private_key, deserialized.public_keys)),
            Err(e) => Err(InvalidKeyPair(e.into())),
        },
        Err(e) => Err(InvalidKeyPair(e)),
    }
}

/// Creates public and private keys randomly.
pub fn create_key_pairs(
    secp: Secp256k1<All>,
    rng: &mut OsRng,
    num_verifiers: usize,
) -> (Vec<SecretKey>, Vec<XOnlyPublicKey>) {
    (0..num_verifiers + 1)
        .map(|_| {
            let (sk, pk) = secp.generate_keypair(rng);
            (sk, XOnlyPublicKey::from(pk))
        })
        .unzip()
}
