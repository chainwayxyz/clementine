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
use bitcoin::{address::NetworkUnchecked, Amount};
use bitcoin::{Address, Network, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fs::File, io::Read, path::PathBuf};

/// Configuration options for any Clementine target (tests, binaries etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Host of the operator or the verifier
    pub host: String,
    /// Port of the operator or the verifier
    pub port: u16,
    /// Entitiy index.
    pub index: u32,
    /// Bitcoin network to work on.
    pub network: Network,
    /// Secret key for the operator or the verifier.
    pub secret_key: SecretKey,
    /// Verifiers public keys.
    pub verifiers_public_keys: Vec<PublicKey>,
    /// Number of verifiers.
    pub num_verifiers: usize,
    /// Operators x-only public keys.
    pub operators_xonly_pks: Vec<XOnlyPublicKey>,
    /// Operators wallet addresses.
    pub operator_wallet_addresses: Vec<bitcoin::Address<NetworkUnchecked>>,
    /// Number of operators.
    pub num_operators: usize,
    /// Number of watchtowers.
    pub num_watchtowers: usize,
    /// Number of time txs
    pub num_time_txs: usize,
    /// number of kickoffs per time tx
    pub num_kickoffs_per_timetx: usize,
    /// Operator's fee for withdrawal, in satoshis.
    pub operator_withdrawal_fee_sats: Option<Amount>,
    /// Number of blocks after which user can take deposit back if deposit request fails.
    pub user_takes_after: u32,
    /// Number of blocks after which operator can take reimburse the bridge fund if they are honest.
    pub operator_takes_after: u32,
    /// Bridge amount in satoshis.
    pub bridge_amount_sats: Amount,
    /// Operator: number of kickoff UTXOs per funding transaction.
    pub operator_num_kickoff_utxos_per_tx: usize,
    /// Threshold for confirmation.
    pub confirmation_threshold: u32,
    /// Bitcoin remote procedure call URL.
    pub bitcoin_rpc_url: String,
    /// Bitcoin RPC user.
    pub bitcoin_rpc_user: String,
    /// Bitcoin RPC user password.
    pub bitcoin_rpc_password: String,
    /// All Secret keys. Just for testing purposes.
    pub all_verifiers_secret_keys: Option<Vec<SecretKey>>,
    /// All Secret keys. Just for testing purposes.
    pub all_operators_secret_keys: Option<Vec<SecretKey>>,
    /// All Secret keys. Just for testing purposes.
    pub all_watchtowers_secret_keys: Option<Vec<SecretKey>>,
    /// Verifier endpoints. For the aggregator only
    pub verifier_endpoints: Option<Vec<String>>,
    /// Operator endpoint. For the aggregator only
    pub operator_endpoints: Option<Vec<String>>,
    /// Watchtower endpoint. For the aggregator only
    pub watchtower_endpoints: Option<Vec<String>>,
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
    /// Bridge contract address.
    pub bridge_contract_address: String,
    // Initial header chain proof receipt's file path.
    pub header_chain_proof_path: Option<PathBuf>,
    /// Additional secret key that will be used for creating Winternitz one time signature.
    pub winternitz_secret_key: Option<SecretKey>,
}

impl BridgeConfig {
    /// Create a new `BridgeConfig` with default values.
    pub fn new() -> Self {
        BridgeConfig {
            ..Default::default()
        }
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
            host: "127.0.0.1".to_string(),
            port: 17000,
            index: 0,

            secret_key: SecretKey::from_str(
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap(),

            num_verifiers: 7,
            verifiers_public_keys: vec![
                PublicKey::from_str(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                )
                .unwrap(),
                PublicKey::from_str(
                    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                )
                .unwrap(),
                PublicKey::from_str(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                )
                .unwrap(),
                PublicKey::from_str(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                )
                .unwrap(),
                PublicKey::from_str(
                    "029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b",
                )
                .unwrap(),
                PublicKey::from_str(
                    "035ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30",
                )
                .unwrap(),
                PublicKey::from_str(
                    "037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da",
                )
                .unwrap(),
            ],

            num_operators: 3,
            num_watchtowers: 4,
            num_time_txs: 10,
            num_kickoffs_per_timetx: 2, // TODO: increase after implementing stream for watchtower params
            operators_xonly_pks: vec![
                XOnlyPublicKey::from_str(
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "3c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                )
                .unwrap(),
            ],

            operator_takes_after: 5,

            operator_wallet_addresses: vec![
                Address::from_str(
                    "bcrt1pvaua4gvvglk27al5trh337xz8l8zzhgzageky0xt0dgv64xee8tqwwvzmf",
                )
                .unwrap(),
                Address::from_str(
                    "bcrt1pvaua4gvvglk27al5trh337xz8l8zzhgzageky0xt0dgv64xee8tqwwvzmf",
                )
                .unwrap(),
                Address::from_str(
                    "bcrt1pvaua4gvvglk27al5trh337xz8l8zzhgzageky0xt0dgv64xee8tqwwvzmf",
                )
                .unwrap(),
            ],
            operator_withdrawal_fee_sats: Some(Amount::from_sat(100000)),

            operator_num_kickoff_utxos_per_tx: 10,

            user_takes_after: 200,

            network: Network::Regtest,
            bitcoin_rpc_url: "http://127.0.0.1:18443".to_string(),
            bitcoin_rpc_user: "admin".to_string(),
            bitcoin_rpc_password: "admin".to_string(),

            db_host: "127.0.0.1".to_string(),
            db_port: 5432,
            db_user: "clementine".to_string(),
            db_password: "clementine".to_string(),
            db_name: "clementine".to_string(),

            bridge_amount_sats: Amount::from_sat(100_000_000),

            confirmation_threshold: 1,

            citrea_rpc_url: "".to_string(),
            bridge_contract_address: "3100000000000000000000000000000000000002".to_string(),

            header_chain_proof_path: Some(
                PathBuf::from_str("../core/tests/data/first_1.bin").unwrap(),
            ),

            all_verifiers_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                SecretKey::from_str(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                )
                .unwrap(),
                SecretKey::from_str(
                    "5555555555555555555555555555555555555555555555555555555555555555",
                )
                .unwrap(),
                SecretKey::from_str(
                    "6666666666666666666666666666666666666666666666666666666666666666",
                )
                .unwrap(),
                SecretKey::from_str(
                    "7777777777777777777777777777777777777777777777777777777777777777",
                )
                .unwrap(),
            ]),
            all_operators_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
            ]),
            all_watchtowers_secret_keys: Some(vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                SecretKey::from_str(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                )
                .unwrap(),
            ]),

            winternitz_secret_key: Some(
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
            ),

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
}
