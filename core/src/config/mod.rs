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

use crate::bitvm_client::UNSPENDABLE_XONLY_PUBKEY;
use crate::builder::transaction::SecurityCouncil;
use crate::errors::BridgeError;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, OutPoint};
use protocol::ProtocolParamset;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fs::File, io::Read, path::PathBuf};

pub mod env;
pub mod protocol;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestParams {
    pub should_run_state_manager: bool,
    pub all_verifiers_secret_keys: Vec<SecretKey>,
    pub all_operators_secret_keys: Vec<SecretKey>,
    pub disrupt_latest_block_hash_commit: bool,
    pub disrupt_payout_tx_block_hash_commit: bool,
    pub disrupt_challenge_sending_watchtowers_commit: bool,
    pub operator_forgot_watchtower_challenge: bool,
}

impl Default for TestParams {
    fn default() -> Self {
        Self {
            should_run_state_manager: true,
            all_verifiers_secret_keys: vec![
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
            ],
            all_operators_secret_keys: vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
            ],
            disrupt_latest_block_hash_commit: false,
            disrupt_payout_tx_block_hash_commit: false,
            disrupt_challenge_sending_watchtowers_commit: false,
            operator_forgot_watchtower_challenge: false,
        }
    }
}

/// Configuration options for any Clementine target (tests, binaries etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeConfig {
    /// Protocol paramset
    ///
    /// Sourced from either a file or the environment, is set to REGTEST_PARAMSET in tests
    ///
    /// Skipped in deserialization and replaced by either file/environment source. See [`crate::cli::get_cli_config`]
    #[serde(skip)]
    pub protocol_paramset: &'static ProtocolParamset,
    /// Host of the operator or the verifier
    pub host: String,
    /// Port of the operator or the verifier
    pub port: u16,
    /// Secret key for the operator or the verifier.
    pub secret_key: SecretKey,
    /// Additional secret key that will be used for creating Winternitz one time signature.
    pub winternitz_secret_key: Option<SecretKey>,
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
    /// Citrea's EVM Chain ID.
    pub citrea_chain_id: u32,
    /// Bridge contract address.
    pub bridge_contract_address: String,
    // Initial header chain proof receipt's file path.
    pub header_chain_proof_path: Option<PathBuf>,

    /// Security council.
    pub security_council: SecurityCouncil,

    /// Verifier endpoints. For the aggregator only
    pub verifier_endpoints: Option<Vec<String>>,
    /// Operator endpoint. For the aggregator only
    pub operator_endpoints: Option<Vec<String>>,

    /// Own operator's reimbursement address.
    pub operator_reimbursement_address: Option<Address<NetworkUnchecked>>,

    /// Own operator's collateral funding outpoint.
    pub operator_collateral_funding_outpoint: Option<OutPoint>,

    // TLS certificates
    /// Path to the server certificate file.
    ///
    /// Required for all entities.
    pub server_cert_path: PathBuf,
    /// Path to the server key file.
    pub server_key_path: PathBuf,

    /// Path to the client certificate file. (used to communicate with other gRPC services)
    ///
    /// Required for all entities. This is used to authenticate requests.
    /// Aggregator's client certificate should match the expected aggregator
    /// certificate in other entities.
    ///
    /// Aggregator needs this to call other entities, other entities need this
    /// to call their own internal endpoints.
    pub client_cert_path: PathBuf,
    /// Path to the client key file.
    pub client_key_path: PathBuf,

    /// Path to the CA certificate file which is used to verify client
    /// certificates.
    pub ca_cert_path: PathBuf,

    /// Whether client certificates should be restricted to Aggregator and Self certificates.
    ///
    /// Client certificates are always validated against the CA certificate
    /// according to mTLS regardless of this setting.
    pub client_verification: bool,

    /// Path to the aggregator certificate file. (used to authenticate requests from aggregator)
    ///
    /// Aggregator's client cert should be equal to the this certificate.
    pub aggregator_cert_path: PathBuf,

    #[cfg(test)]
    #[serde(skip)]
    pub test_params: TestParams,
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
        self.protocol_paramset
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
            protocol_paramset: Default::default(),
            host: "127.0.0.1".to_string(),
            port: 17000,

            secret_key: SecretKey::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .expect("known valid input"),

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
            citrea_chain_id: 5655,
            bridge_contract_address: "3100000000000000000000000000000000000002".to_string(),

            header_chain_proof_path: None,

            operator_reimbursement_address: None,
            operator_collateral_funding_outpoint: None,

            security_council: SecurityCouncil {
                pks: vec![*UNSPENDABLE_XONLY_PUBKEY],
                threshold: 1,
            },

            winternitz_secret_key: Some(
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
            ),
            verifier_endpoints: None,
            operator_endpoints: None,

            server_cert_path: PathBuf::from("certs/server/server.pem"),
            server_key_path: PathBuf::from("certs/server/server.key"),
            client_cert_path: PathBuf::from("certs/client/client.pem"),
            client_key_path: PathBuf::from("certs/client/client.key"),
            ca_cert_path: PathBuf::from("certs/ca/ca.pem"),
            aggregator_cert_path: PathBuf::from("certs/aggregator/aggregator.pem"),
            client_verification: true,

            #[cfg(test)]
            test_params: TestParams::default(),
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
        let config_path = format!("{}/src/test/data/bridge_config.toml", base_path);
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
        let content = include_str!("../test/data/bridge_config.toml");
        BridgeConfig::try_parse_from(content.to_string()).unwrap();
    }

    #[test]
    fn test_docker_config_parseable() {
        let content = include_str!("../../../scripts/docker/docker_config.toml");
        BridgeConfig::try_parse_from(content.to_string()).unwrap();
    }
}
