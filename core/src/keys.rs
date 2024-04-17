//! This module reads or creates private and public keys depending on what the
//! user is supplying.

use crate::constants::NUM_VERIFIERS;
use bitcoin::XOnlyPublicKey;
use crypto_bigint::rand_core::OsRng;
use secp256k1::{All, Secp256k1, SecretKey};
use std::env;

/// Gets private and public keys, either from a user supplied source or creates
/// random pairs. User can supply keys as files using PUBLIC_KEYS and
/// PRIVATE_KEYS environment variables.
pub fn get_keys(secp: Secp256k1<All>, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<XOnlyPublicKey>) {
    match read_from_file() {
        Some(ret) => return ret,
        None => (),
    }

    create(secp, rng)
}

/// Reads private and public keys from files if they are specified as
/// environment variables.
fn read_from_file() -> Option<(Vec<SecretKey>, Vec<XOnlyPublicKey>)> {
    let _private = env::var("PRIVATE_KEYS");
    let _public = env::var("PUBLIC_KEYS");

    None
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
