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

use crate::cli;
use crate::config::env::{read_string_from_env, read_string_from_env_then_parse};
use crate::deposit::SecurityCouncil;
use crate::errors::BridgeError;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, Network, OutPoint, XOnlyPublicKey};
use bridge_circuit_host::utils::is_dev_mode;
use circuits_lib::bridge_circuit::constants::is_test_vk;
use protocol::ProtocolParamset;
use secrecy::SecretString;
use serde::Deserialize;
use std::str::FromStr;
use std::time::Duration;
use std::{fs::File, io::Read, path::PathBuf};

pub mod env;
pub mod protocol;

#[cfg(test)]
mod test;

#[cfg(test)]
pub use test::*;

/// Configuration options for any Clementine target (tests, binaries etc.).
#[derive(Debug, Clone, Deserialize)]
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
    pub bitcoin_rpc_user: SecretString,
    /// Bitcoin RPC user password.
    pub bitcoin_rpc_password: SecretString,
    /// mempool.space API host for retrieving the fee rate. If None, Bitcoin Core RPC will be used.
    pub mempool_api_host: Option<String>,
    /// mempool.space API endpoint for retrieving the fee rate. If None, Bitcoin Core RPC will be used.
    pub mempool_api_endpoint: Option<String>,

    /// PostgreSQL database host address.
    pub db_host: String,
    /// PostgreSQL database port.
    pub db_port: usize,
    /// PostgreSQL database user name.
    pub db_user: SecretString,
    /// PostgreSQL database user password.
    pub db_password: SecretString,
    /// PostgreSQL database name.
    pub db_name: String,
    /// Citrea RPC URL.
    pub citrea_rpc_url: String,
    /// Citrea light client prover RPC URL.
    pub citrea_light_client_prover_url: String,
    /// Citrea's EVM Chain ID.
    pub citrea_chain_id: u32,
    /// Timeout in seconds for Citrea RPC calls.
    pub citrea_request_timeout: Option<Duration>,
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

    /// Telemetry configuration
    pub telemetry: Option<TelemetryConfig>,

    /// The ECDSA address of the citrea/aggregator that will sign the withdrawal params
    /// after manual verification of the optimistic payout and operator's withdrawal.
    /// Used for both an extra verification of aggregator's identity and to force citrea
    /// to check withdrawal params manually during some time after launch.
    pub aggregator_verification_address: Option<alloy::primitives::Address>,

    /// The X25519 public key that will be used to encrypt the emergency stop message.
    pub emergency_stop_encryption_public_key: Option<[u8; 32]>,

    #[cfg(test)]
    #[serde(skip)]
    pub test_params: test::TestParams,

    /// gRPC client/server limits
    #[serde(default = "default_grpc_limits")]
    pub grpc: GrpcLimits,

    /// Hard cap on tx sender fee rate (sat/vB).
    #[serde(default = "default_tx_sender_limits")]
    pub tx_sender_limits: TxSenderLimits,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct GrpcLimits {
    pub max_message_size: usize,
    pub timeout_secs: u64,
    pub tcp_keepalive_secs: u64,
    pub req_concurrency_limit: usize,
    pub ratelimit_req_count: usize,
    pub ratelimit_req_interval_secs: u64,
}

fn default_grpc_limits() -> GrpcLimits {
    GrpcLimits {
        max_message_size: 4 * 1024 * 1024,
        timeout_secs: 12 * 60 * 60, // 12 hours
        tcp_keepalive_secs: 60,
        req_concurrency_limit: 300, // 100 deposits at the same time
        ratelimit_req_count: 1000,
        ratelimit_req_interval_secs: 60,
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TxSenderLimits {
    pub fee_rate_hard_cap: u64,
    pub mempool_fee_rate_multiplier: u64,
    pub mempool_fee_rate_offset_sat_kvb: u64,
    /// The time to wait before bumping the fee of a fee payer UTXO
    /// We wait a bit because after bumping the fee, the unconfirmed change utxo that is in the bumped tx will not be able to be spent (so won't be used to create new fee payer utxos) until that fee payer tx confirms
    pub cpfp_fee_payer_bump_wait_time_seconds: u64,
}

fn default_tx_sender_limits() -> TxSenderLimits {
    TxSenderLimits {
        fee_rate_hard_cap: 100,
        mempool_fee_rate_multiplier: 1,
        mempool_fee_rate_offset_sat_kvb: 0,
        cpfp_fee_payer_bump_wait_time_seconds: 60 * 60, // 1 hour in seconds
    }
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

    /// Checks various variables if they are correct for mainnet deployment.
    pub fn check_mainnet_requirements(&self, actor_type: cli::Actors) -> Result<(), BridgeError> {
        if self.protocol_paramset().network != Network::Bitcoin {
            return Ok(());
        }

        let mut misconfigs = Vec::new();

        if actor_type == cli::Actors::Operator {
            if !self.client_verification {
                misconfigs.push("client_verification=false".to_string());
            }
            if self.operator_collateral_funding_outpoint.is_none() {
                misconfigs.push("operator_collateral_funding_outpoint is not set".to_string());
            }
        }

        if actor_type == cli::Actors::Verifier && !self.client_verification {
            misconfigs.push("client_verification=false".to_string());
        }

        /// Checks if an env var is set to a non 0 value.
        fn check_env_var(env_var: &str, misconfigs: &mut Vec<String>) {
            if let Ok(var) = std::env::var(env_var) {
                if var == "0" || var.eq_ignore_ascii_case("false") {
                    return;
                }

                misconfigs.push(format!("{env_var}={var}"));
            }
        }

        check_env_var("DISABLE_NOFN_CHECK", &mut misconfigs);

        if is_dev_mode() {
            misconfigs.push("Risc0 dev mode is enabled".to_string());
        }

        if is_test_vk() {
            misconfigs.push("use-test-vk feature is enabled".to_string());
        }

        if !misconfigs.is_empty() {
            return Err(BridgeError::ConfigError(format!(
                "Following configs can't be used on Mainnet: {:?}",
                misconfigs
            )));
        }

        Ok(())
    }
}

// only needed for one test
#[cfg(test)]
impl PartialEq for BridgeConfig {
    fn eq(&self, other: &Self) -> bool {
        use secrecy::ExposeSecret;

        let all_eq = self.protocol_paramset == other.protocol_paramset
            && self.host == other.host
            && self.port == other.port
            && self.secret_key == other.secret_key
            && self.winternitz_secret_key == other.winternitz_secret_key
            && self.operator_withdrawal_fee_sats == other.operator_withdrawal_fee_sats
            && self.bitcoin_rpc_url == other.bitcoin_rpc_url
            && self.bitcoin_rpc_user.expose_secret() == other.bitcoin_rpc_user.expose_secret()
            && self.bitcoin_rpc_password.expose_secret()
                == other.bitcoin_rpc_password.expose_secret()
            && self.db_host == other.db_host
            && self.db_port == other.db_port
            && self.db_user.expose_secret() == other.db_user.expose_secret()
            && self.db_password.expose_secret() == other.db_password.expose_secret()
            && self.db_name == other.db_name
            && self.citrea_rpc_url == other.citrea_rpc_url
            && self.citrea_light_client_prover_url == other.citrea_light_client_prover_url
            && self.citrea_chain_id == other.citrea_chain_id
            && self.bridge_contract_address == other.bridge_contract_address
            && self.header_chain_proof_path == other.header_chain_proof_path
            && self.security_council == other.security_council
            && self.verifier_endpoints == other.verifier_endpoints
            && self.operator_endpoints == other.operator_endpoints
            && self.operator_reimbursement_address == other.operator_reimbursement_address
            && self.operator_collateral_funding_outpoint
                == other.operator_collateral_funding_outpoint
            && self.server_cert_path == other.server_cert_path
            && self.server_key_path == other.server_key_path
            && self.client_cert_path == other.client_cert_path
            && self.client_key_path == other.client_key_path
            && self.ca_cert_path == other.ca_cert_path
            && self.client_verification == other.client_verification
            && self.aggregator_cert_path == other.aggregator_cert_path
            && self.test_params == other.test_params
            && self.grpc == other.grpc;

        all_eq
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
            bitcoin_rpc_user: "admin".to_string().into(),
            bitcoin_rpc_password: "admin".to_string().into(),
            mempool_api_host: None,
            mempool_api_endpoint: None,

            db_host: "127.0.0.1".to_string(),
            db_port: 5432,
            db_user: "clementine".to_string().into(),
            db_password: "clementine".to_string().into(),
            db_name: "clementine".to_string(),

            citrea_rpc_url: "".to_string(),
            citrea_light_client_prover_url: "".to_string(),
            citrea_chain_id: 5655,
            bridge_contract_address: "3100000000000000000000000000000000000002".to_string(),
            citrea_request_timeout: None,

            header_chain_proof_path: None,

            operator_reimbursement_address: None,
            operator_collateral_funding_outpoint: None,

            security_council: SecurityCouncil {
                pks: vec![
                    XOnlyPublicKey::from_str(
                        "9ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b",
                    )
                    .expect("valid xonly"),
                    XOnlyPublicKey::from_str(
                        "5ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30",
                    )
                    .expect("valid xonly"),
                ],
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
            aggregator_verification_address: Some(
                alloy::primitives::Address::from_str("0x242fbec93465ce42b3d7c0e1901824a2697193fd")
                    .expect("valid address"),
            ),
            emergency_stop_encryption_public_key: Some(
                hex::decode("025d32d10ec7b899df4eeb4d80918b7f0a1f2a28f6af24f71aa2a59c69c0d531")
                    .expect("valid hex")
                    .try_into()
                    .expect("valid key"),
            ),

            telemetry: Some(TelemetryConfig::default()),

            #[cfg(test)]
            test_params: test::TestParams::default(),

            // New hardening parameters, optional so they don't break existing configs.
            grpc: default_grpc_limits(),
            tx_sender_limits: default_tx_sender_limits(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    pub host: String,
    pub port: u16,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8081,
        }
    }
}

impl TelemetryConfig {
    pub fn from_env() -> Result<Self, BridgeError> {
        let host = read_string_from_env("TELEMETRY_HOST")?;
        let port = read_string_from_env_then_parse::<u16>("TELEMETRY_PORT")?;
        Ok(Self { host, port })
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeConfig;
    use crate::{cli, config::protocol::REGTEST_PARAMSET};
    use bitcoin::{hashes::Hash, Network, OutPoint, Txid};
    use std::{
        fs::{self, File},
        io::Write,
    };

    #[test]
    fn parse_from_string() {
        // In case of a incorrect file content, we should receive an error.
        let content = "brokenfilecontent";
        assert!(BridgeConfig::try_parse_from(content.to_string()).is_err());
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

    pub const INVALID_PARAMSET: crate::config::ProtocolParamset = crate::config::ProtocolParamset {
        network: Network::Bitcoin,
        ..REGTEST_PARAMSET
    };
    #[ignore = "Fails if bridge-circuit-host has use-test-vk feature! Which it will, if --all-features is specified at Cargo invocation."]
    #[serial_test::serial]
    #[test]
    fn check_mainnet_reqs() {
        let env_vars = vec!["DISABLE_NOFN_CHECK", "RISC0_DEV_MODE"];

        // Nothing illegal is set.
        for var in env_vars.clone() {
            std::env::remove_var(var);
        }
        let mainnet_config = BridgeConfig {
            protocol_paramset: &INVALID_PARAMSET,
            client_verification: true,
            operator_collateral_funding_outpoint: Some(OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            }),
            ..Default::default()
        };
        let checks = mainnet_config.check_mainnet_requirements(cli::Actors::Operator);
        println!("checks: {checks:?}");
        assert!(checks.is_ok());

        // Nothing illegal is set while illegal env vars set to 0 specifically.
        for var in env_vars.clone() {
            std::env::set_var(var, "0");
        }
        let checks = mainnet_config.check_mainnet_requirements(cli::Actors::Operator);
        println!("checks: {checks:?}");
        assert!(checks.is_ok());

        // Illegal configs, no illegal env vars.
        let incorrect_mainnet_config = BridgeConfig {
            client_verification: false,
            operator_collateral_funding_outpoint: None,
            ..mainnet_config.clone()
        };
        let checks = incorrect_mainnet_config.check_mainnet_requirements(cli::Actors::Operator);
        println!("checks: {checks:?}");
        assert!(checks.is_err());

        // No illegal configs, illegal env vars.
        for var in env_vars.clone() {
            std::env::set_var(var, "1");
        }
        let checks = mainnet_config.check_mainnet_requirements(cli::Actors::Operator);
        println!("checks: {checks:?}");
        assert!(checks.is_err());

        // Illegal everything.
        for var in env_vars.clone() {
            std::env::set_var(var, "1");
        }
        let checks = incorrect_mainnet_config.check_mainnet_requirements(cli::Actors::Operator);
        println!("checks: {checks:?}");
        assert!(checks.is_err());
    }
}
