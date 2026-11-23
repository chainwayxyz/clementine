//! # Common Module
//! This module contains common constants and utility functions used across the SP1 circuits in the Clementine protocol.
//! It includes definitions for constants related to the bridge amount, number of outputs, transaction assertions, and watchtowers.
//! It also provides hashing functions for cryptographic operations, such as double SHA256 and single SHA256 hashing,
//! as well as a utility function to hash two nodes together.
//! The `ZkvmGuest` trait defines the guest interface for reading from the host, committing data
//! and verifying proofs.

pub mod constants;
pub mod hashes;
pub mod programs;
pub mod sp1;
pub mod sp1_programs;
pub mod verification_mode;
pub mod zkvm;

/// A Bitcoin network that the circuits can be compiled for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildNetwork {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

/// The network this crate is compiled for: `BITCOIN_NETWORK`, or mainnet if it is unset.
/// Any other value fails the build. The crate's own unit tests use testnet4.
pub const BUILD_NETWORK: BuildNetwork = if cfg!(test) {
    BuildNetwork::Testnet4
} else {
    parse_build_network(option_env!("BITCOIN_NETWORK"))
};

/// Parses a `BITCOIN_NETWORK` value. An unset value is mainnet; an unknown value panics.
const fn parse_build_network(value: Option<&str>) -> BuildNetwork {
    match value {
        None => BuildNetwork::Mainnet,
        Some(network) => match network.as_bytes() {
            b"mainnet" => BuildNetwork::Mainnet,
            b"testnet4" => BuildNetwork::Testnet4,
            b"signet" => BuildNetwork::Signet,
            b"regtest" => BuildNetwork::Regtest,
            _ => panic!("Unsupported BITCOIN_NETWORK"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_bitcoin_network_is_mainnet() {
        assert_eq!(parse_build_network(None), BuildNetwork::Mainnet);
        for (value, network) in [
            ("mainnet", BuildNetwork::Mainnet),
            ("testnet4", BuildNetwork::Testnet4),
            ("signet", BuildNetwork::Signet),
            ("regtest", BuildNetwork::Regtest),
        ] {
            assert_eq!(parse_build_network(Some(value)), network);
        }
        assert!(std::panic::catch_unwind(|| parse_build_network(Some("bitcoin"))).is_err());
    }
}
