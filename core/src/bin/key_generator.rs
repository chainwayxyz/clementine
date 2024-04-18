//! This binary generates random private/public key pairs for testing. They will
//! be put in `DIRECTORY`/`PREFIX`(0..`crate::constants::NUM_VERIFIERS`).json. File format is described
//! in `core/src/keys.rs`.

use bitcoin::XOnlyPublicKey;
use clementine_core::keys;
use core::panic;
use std::{fs::{self, File}, io::Write};
use crypto_bigint::rand_core::OsRng;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

/// Directory to put generated key files.
const DIRECTORY: &str = "configs";

/// Key file prefix.
const PREFIX: &str = "keys";

/// Key file's structure.
#[derive(Serialize, Deserialize)]
struct FileContents {
	private_key: SecretKey,
	public_keys: Vec<XOnlyPublicKey>,
	id: usize
}

fn main() {
    let (all_sks, all_xonly_pks) = generate_keypair();
    println!("Generated private keys: {:#?}", all_sks.clone());
    println!("Generated public keys: {:#?}", all_xonly_pks.clone());

	// Create directory. If it exist, it will return an `Err`. Handle that with
	// a variable.
	let _ = fs::create_dir(DIRECTORY);

	for i in 0..all_sks.len() {
		create_file(i, all_sks.clone(), all_xonly_pks.clone());
	}
}

/// This function's contents are copied from clementine_core's `main.rs`.
/// Currently it is not in a dedicated function. If it is refactored to have a
/// dedicated function, it should also be used here and this should be deleted.
/// It is not ideal to have a possibly different key generator algorithms, in
/// case of a change.
fn generate_keypair() -> (Vec<SecretKey>, Vec<XOnlyPublicKey>) {
    let secp: secp256k1::Secp256k1<secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
    let rng = &mut OsRng;

    let (all_sks, all_xonly_pks): (Vec<_>, Vec<_>) = match keys::get_keys(secp.clone(), rng) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error while reading private/public key pair: {}", e);
            panic!();
        }
    };

    (all_sks, all_xonly_pks)
}

/// Creates nth file in `DIRECTORY`.
fn create_file(index: usize, all_sks: Vec<SecretKey>, all_xonly_sks: Vec<XOnlyPublicKey>) {
	let content = FileContents {
		private_key: all_sks[index],
		public_keys: all_xonly_sks,
		id: index,
	};

	let serialized = serde_json::to_string_pretty(&content).unwrap();
	let file = DIRECTORY.to_string() + "/" + PREFIX + index.to_string().as_str() + ".json";

	let mut file = File::create(file).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}
