//! # Private and Public Keys
//!
//! This module reads or creates private and public keys depending on what the
//! user is supplying.
//!
//! ## Specifying Files
//!
//! Input file names can be specified using environment variables:
//!
//! * PRIVATE_KEYS: for private keys
//! * PUBLIC_KEYS: for public keys
//!
//! Because public keys can be generated using private keys, user can only
//! specify private keys and public keys can be generated afterwards.
//!
//! ## File Format
//!
//! Input files are comma seperated and new lines are unimportant.

use crate::constants::NUM_VERIFIERS;
use bitcoin::XOnlyPublicKey;
use crypto_bigint::rand_core::OsRng;
use secp256k1::{All, Secp256k1, SecretKey};
use std::{env, fs};
use thiserror::Error;

/// Tells which sources specified by user and why they can't be used.
#[derive(Debug, Error)]
enum InvalidKeySource {
    /// No source is given as inputs. This is not exactly an error.
    #[error("None")]
    None,
    /// Only private keys file is given and but file is not readable.
    #[error("Private")]
    Private(std::io::Error),
    /// Only public keys file is given and but file is not readable.
    #[error("Public")]
    Public(std::io::Error),
}

/// Gets private and public keys, either from a user supplied source or creates
/// random pairs. User can supply keys as files using PUBLIC_KEYS and
/// PRIVATE_KEYS environment variables.
pub fn get_keys(
    secp: Secp256k1<All>,
    rng: &mut OsRng,
) -> Result<(Vec<SecretKey>, Vec<XOnlyPublicKey>), std::io::Error> {
    match get_from_file() {
        Ok(ret) => return Ok(ret),
        Err(InvalidKeySource::None) => {
            tracing::info!(
                "Neither private nor public keys are specified: They will be generated randomly..."
            );
            return Ok(create(secp, rng));
        }
        Err(InvalidKeySource::Private(e)) => {
            return Err(std::io::Error::other(format!("Private key: {}", e)))
        }
        Err(InvalidKeySource::Public(e)) => {
            return Err(std::io::Error::other(format!("Public key: {}", e)))
        }
    }
}

/// Reads private and public keys from files if they are specified as
/// environment variables. If only private keys are specified, we don't really
/// need public keys as they can be generated using private keys.
fn get_from_file() -> Result<(Vec<SecretKey>, Vec<XOnlyPublicKey>), InvalidKeySource> {
    let private = env::var("PRIVATE_KEYS");
    let public = env::var("PUBLIC_KEYS");
    let mut result: (Vec<SecretKey>, Vec<XOnlyPublicKey>) = (Vec::new(), Vec::new());

    // Unwrap private and public variables read files afterwards.
    match (private, public) {
        (Err(_), Err(_)) => return Err(InvalidKeySource::None),
        (Err(e), Ok(_)) => return Err(InvalidKeySource::Public(std::io::Error::other(e))),
        (Ok(private_file), Err(_)) => match read_private_file(private_file) {
            Ok(contents) => result.0 = contents,
            Err(e) => return Err(InvalidKeySource::Private(e)),
        },
        (Ok(private_file), Ok(public_file)) => {
            match read_private_file(private_file) {
                Ok(contents) => result.0 = contents,
                Err(e) => {
                    return Err(InvalidKeySource::Private(e));
                }
            }
            match read_public_file(public_file) {
                Ok(contents) => result.1 = contents,
                Err(e) => return Err(InvalidKeySource::Public(e)), // TODO: This doesn't need to be an error; Public keys can be generated afterwards.
            }
        }
    };

    Ok(result)
}

/// Internal function for actually reading private key files.
fn read_private_file(name: String) -> Result<Vec<SecretKey>, std::io::Error> {
    let mut result: Vec<SecretKey> = Vec::new();

    let contents = match fs::read_to_string(name) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    for i in contents.split(",") {
        // Remove new lines.
        let i = i.trim();

        // Check if item is empty.
        if i.len() == 0 {
            continue;
        }

        // String value must be converted to
        let mut k = Vec::new();
        for j in hex_to_bytes(i).unwrap() {
            k.push(j);
        }

        let key = match SecretKey::from_slice(&k) {
            Ok(key) => key,
            Err(e) => return Err(std::io::Error::other(e)),
        };
        tracing::debug!("Private key read from file: {:?}", (i, key));

        result.push(key);
    }

    Ok(result)
}

/// Internal function for actually reading private key files.
fn read_public_file(_name: String) -> Result<Vec<XOnlyPublicKey>, std::io::Error> {
    todo!()
}

/// Creates public and private keys randomly.
fn create(secp: Secp256k1<All>, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<XOnlyPublicKey>) {
    (0..NUM_VERIFIERS + 1)
        .map(|_| {
            let (sk, pk) = secp.generate_keypair(rng);
            (sk, XOnlyPublicKey::from(pk))
        })
        .unzip()
}

/// This function is found on the internet:
/// https://users.rust-lang.org/t/hex-string-to-vec-u8/51903/2
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(1)
        .map(|i| {
            s.get(i..i + 1)
                .and_then(|sub| u8::from_str_radix(sub, 16).ok())
        })
        .collect()
}
