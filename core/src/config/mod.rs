//! # Configuration Options
//!
//! This module defines configuration options.
//!
//! This module is base for `cli` module and not dependent on it. Therefore,
//! this module can be used independently.
//!
//! ## Configuration File
//!
//! Configuration options can be read from a TOML file. File contents are
//! described in `BridgeConfig` struct.

use crate::errors::BridgeError;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Amount, XOnlyPublicKey};
use protocol::{ProtocolParamset, ProtocolParamsetName};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fs::File, io::Read, path::PathBuf};

pub mod env;
pub mod protocol;

/// Configuration options for any Clementine target (tests, binaries etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeConfig {
    /// Protocol paramset name
    /// One of:
    /// - `Mainnet`
    /// - `Regtest`
    /// - `Testnet`
    /// - `Signet`
    pub protocol_paramset: ProtocolParamsetName,
    /// Host of the operator or the verifier
    pub host: String,
    /// Port of the operator or the verifier
    pub port: u16,
    /// Entity index.
    pub index: u32,
    /// Secret key for the operator or the verifier.
    pub secret_key: SecretKey,
    /// Additional secret key that will be used for creating Winternitz one time signature.
    pub winternitz_secret_key: Option<SecretKey>,
    /// Verifiers public keys.
    /// In the future, we won't get verifiers public keys from config files, rather in set_verifiers rpc call
    pub verifiers_public_keys: Vec<PublicKey>,
    /// Number of verifiers.
    pub num_verifiers: usize,
    /// Operators x-only public keys.
    pub operators_xonly_pks: Vec<XOnlyPublicKey>,
    /// Number of operators.
    pub num_operators: usize,
    /// Operator's fee for withdrawal, in satoshis.
    pub operator_withdrawal_fee_sats: Option<Amount>,
    /// Bitcoin remote procedure call URL.
    pub bitcoin_rpc_url: String,
    /// Bitcoin RPC user.
    pub bitcoin_rpc_user: String,
    /// Bitcoin RPC user password.
    pub bitcoin_rpc_password: String,
    /// PostgreSQL database host address.
    pub db_host: String,
    /// PostgreSQL database port.
    pub db_port: usize,
    /// PostgreSQL database user name.
    pub db_user: String,
    /// PostgreSQL database user password.
    pub db_password: String,
    /// PostgreSQL database name.
    pub db_name: String,
    /// Citrea RPC URL.
    pub citrea_rpc_url: String,
    /// Citrea light client prover RPC URL.
    pub citrea_light_client_prover_url: String,
    /// Bridge contract address.
    pub bridge_contract_address: String,
    // Initial header chain proof receipt's file path.
    pub header_chain_proof_path: Option<PathBuf>,

    // Trusted Watchtower endpoint
    pub trusted_watchtower_endpoint: Option<String>,

    /// Verifier endpoints. For the aggregator only
    pub verifier_endpoints: Option<Vec<String>>,
    /// Operator endpoint. For the aggregator only
    pub operator_endpoints: Option<Vec<String>>,
    /// Watchtower endpoint. For the aggregator only
    pub watchtower_endpoints: Option<Vec<String>>,

    // /// Directory containing unix sockets
    // pub socket_path: String,
    /// All Secret keys. Just for testing purposes.
    pub all_verifiers_secret_keys: Option<Vec<SecretKey>>,
    /// All Secret keys. Just for testing purposes.
    pub all_operators_secret_keys: Option<Vec<SecretKey>>,
    /// All Secret keys. Just for testing purposes.
    pub all_watchtowers_secret_keys: Option<Vec<SecretKey>>,
}

impl BridgeConfig {
    /// Create a new `BridgeConfig` with default values.
    pub fn new() -> Self {
        BridgeConfig {
            ..Default::default()
        }
    }

    /// Get the protocol paramset defined by the paramset name.
    pub fn protocol_paramset(&self) -> &'static ProtocolParamset {
        self.protocol_paramset.into()
    }

    /// Read contents of a TOML file and generate a `BridgeConfig`.
    pub fn try_parse_file(path: PathBuf) -> Result<Self, BridgeError> {
        let mut contents = String::new();

        let mut file = match File::open(path.clone()) {
            Ok(f) => f,
            Err(e) => return Err(BridgeError::ConfigError(e.to_string())),
        };

        if let Err(e) = file.read_to_string(&mut contents) {
            return Err(BridgeError::ConfigError(e.to_string()));
        }

        tracing::trace!("Using configuration file: {:?}", path);

        BridgeConfig::try_parse_from(contents)
    }

    /// Try to parse a `BridgeConfig` from given TOML formatted string and
    /// generate a `BridgeConfig`.
    pub fn try_parse_from(input: String) -> Result<Self, BridgeError> {
        match toml::from_str::<BridgeConfig>(&input) {
            Ok(c) => Ok(c),
            Err(e) => Err(BridgeError::ConfigError(e.to_string())),
        }
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            protocol_paramset: ProtocolParamsetName::Regtest,
            host: "127.0.0.1".to_string(),
            port: 17000,
            index: 0,

            secret_key: SecretKey::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("known valid input"),

            num_verifiers: 4,
            verifiers_public_keys: vec![
                PublicKey::from_str(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                )
                .expect("known valid input"),
                PublicKey::from_str(
                    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                )
                .expect("known valid input"),
                PublicKey::from_str(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                )
                .expect("known valid input"),
                PublicKey::from_str(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                )
                .expect("known valid input"),
            ],

            num_operators: 2,
            operators_xonly_pks: vec![
                XOnlyPublicKey::from_str(
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                )
                .expect("known valid input"),
                XOnlyPublicKey::from_str(
                    "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                )
                .expect("known valid input"),
            ],

            operator_withdrawal_fee_sats: Some(Amount::from_sat(100000)),

            bitcoin_rpc_url: "http://127.0.0.1:18443/wallet/admin".to_string(),
            bitcoin_rpc_user: "admin".to_string(),
            bitcoin_rpc_password: "admin".to_string(),

            db_host: "127.0.0.1".to_string(),
            db_port: 5432,
            db_user: "clementine".to_string(),
            db_password: "clementine".to_string(),
            db_name: "clementine".to_string(),

            citrea_rpc_url: "".to_string(),
            citrea_light_client_prover_url: "".to_string(),
            bridge_contract_address: "3100000000000000000000000000000000000002".to_string(),

            header_chain_proof_path: Some(
                PathBuf::from_str("../core/tests/data/first_1.bin").expect("known valid input"),
            ),

            trusted_watchtower_endpoint: None,

            all_verifiers_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                )
                .expect("known valid input"),
            ]),
            all_operators_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
            ]),
            all_watchtowers_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .expect("known valid input"),
            ]),

            winternitz_secret_key: Some(
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
            ),
            // socket_path: "/".to_string(),
            verifier_endpoints: None,
            operator_endpoints: None,
            watchtower_endpoints: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeConfig;
    use std::{
        fs::{self, File},
        io::Write,
    };

    #[test]
    fn parse_from_string() {
        // In case of a incorrect file content, we should receive an error.
        let content = "brokenfilecontent";
        assert!(BridgeConfig::try_parse_from(content.to_string()).is_err());

        let init = BridgeConfig::new();
        BridgeConfig::try_parse_from(toml::to_string(&init).unwrap()).unwrap();
    }

    #[test]
    fn parse_from_file() {
        let file_name = "parse_from_file";
        let content = "invalid file content";
        let mut file = File::create(file_name).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        assert!(BridgeConfig::try_parse_file(file_name.into()).is_err());

        // Read first example test file use for this test.
        let base_path = env!("CARGO_MANIFEST_DIR");
        let config_path = format!("{}/tests/data/test_config.toml", base_path);
        let content = fs::read_to_string(config_path).unwrap();
        let mut file = File::create(file_name).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        BridgeConfig::try_parse_file(file_name.into()).unwrap();

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn parse_from_file_with_invalid_headers() {
        let file_name = "parse_from_file_with_invalid_headers";
        let content = "[header1]
        num_verifiers = 4

        [header2]
        confirmation_threshold = 1
        network = \"regtest\"
        bitcoin_rpc_url = \"http://localhost:18443\"
        bitcoin_rpc_user = \"admin\"
        bitcoin_rpc_password = \"admin\"\n";
        let mut file = File::create(file_name).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        assert!(BridgeConfig::try_parse_file(file_name.into()).is_err());

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_test_config_parseable() {
        let content = include_str!("../../tests/data/test_config.toml");
        BridgeConfig::try_parse_from(content.to_string()).unwrap();
    }

    #[test]
    fn test_docker_config_parseable() {
        let content = include_str!("../../../scripts/docker/docker_config.toml");
        BridgeConfig::try_parse_from(content.to_string()).unwrap();
    }
}
