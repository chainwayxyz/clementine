//! # Common Module
//! This module contains common constants and utility functions used across the Risc0 circuits in the Clementine protocol.
//! It includes definitions for constants related to the bridge amount, number of outputs, transaction assertions, and watchtowers.
//! It also provides hashing functions for cryptographic operations, such as double SHA256 and single SHA256 hashing,
//! as well as a utility function to hash two nodes together.
//! The `ZkvmGuest` and `ZkvmHost` traits define the interface for zkVM guest and host interactions,
//! allowing for reading from and writing to the host, committing data, and verifying proofs.

pub mod constants;
pub mod hashes;
pub mod zkvm;

pub const NETWORK_TYPE: &str = {
    #[cfg(test)]
    {
        "testnet4"
    }
    #[cfg(not(test))]
    {
        match option_env!("BITCOIN_NETWORK") {
            Some(network) if matches!(network.as_bytes(), b"mainnet") => "mainnet",
            Some(network) if matches!(network.as_bytes(), b"testnet4") => "testnet4",
            Some(network) if matches!(network.as_bytes(), b"signet") => "signet",
            Some(network) if matches!(network.as_bytes(), b"regtest") => "regtest",
            None => "testnet4",
            _ => panic!("Invalid network type"),
        }
    }
};

pub const fn get_network() -> &'static str {
    NETWORK_TYPE
}
