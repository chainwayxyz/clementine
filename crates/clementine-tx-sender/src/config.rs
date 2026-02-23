//! TxSender standalone configuration.

use crate::MempoolConfig;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;
use clementine_config::tx_sender::TxSenderLimits;
use clementine_errors::BridgeError;
use secrecy::SecretString;
use std::str::FromStr;

const DEFAULT_POLL_DELAY_MS: u64 = 30_000;

#[derive(Clone, Debug)]
pub struct TxSenderPostgresConfig {
    pub host: String,
    pub port: u16,
    pub user: SecretString,
    pub password: SecretString,
    pub dbname: String,
}

#[derive(Clone, Debug)]
pub struct TxSenderBitcoinRpcConfig {
    pub url: String,
    pub user: SecretString,
    pub password: SecretString,
}

#[derive(Clone, Debug)]
pub struct TxSenderJsonRpcConfig {
    /// Bind address for the JSON-RPC server. Restricted to 127.0.0.1 or 0.0.0.0.
    pub bind: String,
    /// TCP port for the JSON-RPC server.
    pub port: u16,
}

/// Configuration for running the tx-sender service standalone.
#[derive(Clone, Debug)]
pub struct TxSenderConfig {
    pub network: Network,
    /// Taproot signing key used by tx-sender.
    ///
    /// In clementine_core usage this is derived from `BridgeConfig.secret_key`.
    /// In standalone usage it is sourced from env `SECRET_KEY`.
    pub secret_key: SecretKey,
    /// Optional Citrea DA blob signing key.
    ///
    /// If not provided, tx-sender falls back to `secret_key` for Citrea blob signing.
    pub private_da_key: Option<SecretKey>,
    pub postgres: TxSenderPostgresConfig,
    pub bitcoin_rpc: TxSenderBitcoinRpcConfig,
    pub mempool: MempoolConfig,
    pub limits: TxSenderLimits,
    /// How many confirmations are required before tx-sender treats an observation as final.
    ///
    /// The chain tip has 1 confirmation. Minimum value should be 1.
    pub finality_depth: u32,

    /// Poll delay for the txsender loop if txsender is used as standalone, in milliseconds.
    ///
    /// If not provided, defaults to 30 seconds.
    pub poll_delay_ms: u64,

    /// Optional override for the maximum number of consecutive input-unspent
    /// check failures before timing out a tx.
    ///
    /// If `None`, txsender derives it from:
    /// `(finality_depth * 2 * 10 minutes) / poll_delay_ms`.
    pub input_unspent_max_retries: Option<u32>,

    /// Whether to use unsafe utxos for funding new txs. An utxo is unsafe it belongs to a tx with at least one non wallet input, if it belongs to a tx that was rbf replaced.
    pub include_unsafe: bool,

    /// Optional JSON-RPC configuration, will not be used if json-rpc feature is not .
    pub jsonrpc: Option<TxSenderJsonRpcConfig>,
}

fn env_required(name: &'static str) -> Result<String, BridgeError> {
    std::env::var(name).map_err(|e| BridgeError::EnvVarNotSet(e, name))
}

fn env_optional(name: &'static str) -> Option<String> {
    std::env::var(name).ok()
}

fn env_parse_required<T: std::str::FromStr>(name: &'static str) -> Result<T, BridgeError>
where
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    env_required(name)?
        .parse::<T>()
        .map_err(|e| BridgeError::EnvVarMalformed(name, format!("{e:?}")))
}

fn env_parse_optional<T: std::str::FromStr>(name: &'static str) -> Result<Option<T>, BridgeError>
where
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    let Some(v) = env_optional(name) else {
        return Ok(None);
    };
    v.parse::<T>()
        .map(Some)
        .map_err(|e| BridgeError::EnvVarMalformed(name, format!("{e:?}")))
}

pub(crate) fn validate_input_unspent_max_retries(
    input_unspent_max_retries: Option<u32>,
) -> std::result::Result<Option<u32>, String> {
    if let Some(retries) = input_unspent_max_retries {
        if retries == 0 {
            return Err("must be >= 1 when set".to_string());
        }
        if retries > i32::MAX as u32 {
            return Err(format!("must be <= {} when set", i32::MAX));
        }
    }
    Ok(input_unspent_max_retries)
}

impl TxSenderConfig {
    pub fn from_env() -> Result<Self, BridgeError> {
        let network_str = env_required("NETWORK")?;
        let network = Network::from_str(&network_str)
            .map_err(|e| BridgeError::EnvVarMalformed("NETWORK", format!("{e:?}")))?;

        let secret_key_str = env_required("SECRET_KEY")?;
        let secret_key = SecretKey::from_str(&secret_key_str)
            .map_err(|e| BridgeError::EnvVarMalformed("SECRET_KEY", format!("{e:?}")))?;

        let private_da_key =
            match env_optional("PRIVATE_DA_KEY") {
                Some(value) => Some(SecretKey::from_str(&value).map_err(|e| {
                    BridgeError::EnvVarMalformed("PRIVATE_DA_KEY", format!("{e:?}"))
                })?),
                None => None,
            };

        let postgres = TxSenderPostgresConfig {
            host: env_required("DB_HOST")?,
            port: env_parse_required::<u16>("DB_PORT")?,
            user: env_required("DB_USER")?.into(),
            password: env_required("DB_PASSWORD")?.into(),
            dbname: env_required("DB_NAME")?,
        };

        let bitcoin_rpc = TxSenderBitcoinRpcConfig {
            url: env_required("BITCOIN_RPC_URL")?,
            user: env_required("BITCOIN_RPC_USER")?.into(),
            password: env_required("BITCOIN_RPC_PASSWORD")?.into(),
        };

        let mempool = MempoolConfig {
            host: env_optional("MEMPOOL_API_HOST"),
            endpoint: env_optional("MEMPOOL_API_ENDPOINT"),
        };

        // Keep limits in sync with existing `TX_SENDER_*` env vars used by core.
        // This mirrors the logic currently in `core/src/config/env.rs`.
        let defaults = TxSenderLimits::default();
        let limits = TxSenderLimits {
            fee_rate_hard_cap: env_parse_required::<u64>("TX_SENDER_FEE_RATE_HARD_CAP")
                .unwrap_or(defaults.fee_rate_hard_cap),
            mempool_fee_rate_multiplier: env_parse_required::<u64>(
                "TX_SENDER_MEMPOOL_FEE_RATE_MULTIPLIER",
            )
            .unwrap_or(defaults.mempool_fee_rate_multiplier),
            mempool_fee_rate_offset_sat_kvb: env_parse_required::<u64>(
                "TX_SENDER_MEMPOOL_FEE_RATE_OFFSET_SAT_KVB",
            )
            .unwrap_or(defaults.mempool_fee_rate_offset_sat_kvb),
            cpfp_fee_payer_bump_wait_time_seconds: env_parse_required::<u64>(
                "TX_SENDER_CPFP_FEE_PAYER_BUMP_WAIT_TIME_SECONDS",
            )
            .unwrap_or(defaults.cpfp_fee_payer_bump_wait_time_seconds),
            fee_bump_after_blocks: env_parse_required::<u32>("TX_SENDER_FEE_BUMP_AFTER_BLOCKS")
                .unwrap_or(defaults.fee_bump_after_blocks),
            min_bump_kvb: env_parse_required::<u64>("TX_SENDER_MIN_BUMP_KVB")
                .unwrap_or(defaults.min_bump_kvb),
        };

        let finality_depth = env_parse_required::<u32>("TX_SENDER_FINALITY_DEPTH")?;

        let poll_delay_ms =
            env_parse_optional::<u64>("TX_SENDER_POLL_DELAY_MS")?.unwrap_or(DEFAULT_POLL_DELAY_MS);
        if poll_delay_ms == 0 {
            return Err(BridgeError::EnvVarMalformed(
                "TX_SENDER_POLL_DELAY_MS",
                "poll_delay_ms must be >= 1".to_string(),
            ));
        }

        let input_unspent_max_retries = validate_input_unspent_max_retries(env_parse_optional::<
            u32,
        >(
            "TX_SENDER_INPUT_UNSPENT_MAX_RETRIES",
        )?)
        .map_err(|msg| BridgeError::EnvVarMalformed("TX_SENDER_INPUT_UNSPENT_MAX_RETRIES", msg))?;

        let include_unsafe = env_parse_required::<bool>("TX_SENDER_INCLUDE_UNSAFE")?;

        if finality_depth < 1 {
            return Err(BridgeError::EnvVarMalformed(
                "TX_SENDER_FINALITY_DEPTH",
                "finality depth must be >= 1".to_string(),
            ));
        }

        #[cfg(feature = "json-rpc")]
        let jsonrpc = {
            let port = env_parse_optional::<u16>("TX_SENDER_JSONRPC_PORT")?;
            port.map(|port| {
                let bind = env_optional("TX_SENDER_JSONRPC_BIND")
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                if bind != "127.0.0.1" && bind != "0.0.0.0" {
                    return Err(BridgeError::EnvVarMalformed(
                        "TX_SENDER_JSONRPC_BIND",
                        "bind must be either 127.0.0.1 or 0.0.0.0".to_string(),
                    ));
                }
                Ok(TxSenderJsonRpcConfig { bind, port })
            })
            .transpose()?
        };

        #[cfg(not(feature = "json-rpc"))]
        let jsonrpc = None;

        Ok(Self {
            network,
            secret_key,
            private_da_key,
            postgres,
            bitcoin_rpc,
            mempool,
            limits,
            finality_depth,
            poll_delay_ms,
            input_unspent_max_retries,
            include_unsafe,
            jsonrpc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TxSenderConfig;
    use clementine_errors::BridgeError;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    const ENV_KEYS: &[&str] = &[
        "NETWORK",
        "SECRET_KEY",
        "PRIVATE_DA_KEY",
        "DB_HOST",
        "DB_PORT",
        "DB_USER",
        "DB_PASSWORD",
        "DB_NAME",
        "BITCOIN_RPC_URL",
        "BITCOIN_RPC_USER",
        "BITCOIN_RPC_PASSWORD",
        "TX_SENDER_FINALITY_DEPTH",
        "TX_SENDER_POLL_DELAY_MS",
        "TX_SENDER_INPUT_UNSPENT_MAX_RETRIES",
        "TX_SENDER_INCLUDE_UNSAFE",
        "MEMPOOL_API_HOST",
        "MEMPOOL_API_ENDPOINT",
    ];

    const VALID_SECRET_KEY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    struct EnvGuard {
        original: BTreeMap<&'static str, Option<String>>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let original = ENV_KEYS
                .iter()
                .map(|k| (*k, std::env::var(k).ok()))
                .collect::<BTreeMap<_, _>>();
            Self { original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.original {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    fn set_required_env() {
        std::env::set_var("NETWORK", "regtest");
        std::env::set_var("SECRET_KEY", VALID_SECRET_KEY);
        std::env::remove_var("PRIVATE_DA_KEY");
        std::env::set_var("DB_HOST", "127.0.0.1");
        std::env::set_var("DB_PORT", "5432");
        std::env::set_var("DB_USER", "clementine");
        std::env::set_var("DB_PASSWORD", "clementine");
        std::env::set_var("DB_NAME", "clementine_tx_sender_test");
        std::env::set_var("BITCOIN_RPC_URL", "http://127.0.0.1:18443");
        std::env::set_var("BITCOIN_RPC_USER", "admin");
        std::env::set_var("BITCOIN_RPC_PASSWORD", "admin");
        std::env::set_var("TX_SENDER_FINALITY_DEPTH", "3");
        std::env::set_var("TX_SENDER_INCLUDE_UNSAFE", "true");

        std::env::remove_var("TX_SENDER_POLL_DELAY_MS");
        std::env::remove_var("TX_SENDER_INPUT_UNSPENT_MAX_RETRIES");
        std::env::remove_var("MEMPOOL_API_HOST");
        std::env::remove_var("MEMPOOL_API_ENDPOINT");
    }

    #[test]
    fn from_env_parses_required_fields() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned");
        let _env_guard = EnvGuard::new();

        set_required_env();
        std::env::set_var("PRIVATE_DA_KEY", VALID_SECRET_KEY);
        std::env::set_var("MEMPOOL_API_HOST", "https://mempool.space");
        std::env::set_var("MEMPOOL_API_ENDPOINT", "/api");
        std::env::set_var("TX_SENDER_POLL_DELAY_MS", "1000");
        std::env::set_var("TX_SENDER_INPUT_UNSPENT_MAX_RETRIES", "9");

        let config = TxSenderConfig::from_env().expect("config should parse");

        assert_eq!(config.network, bitcoin::Network::Regtest);
        assert_eq!(config.postgres.host, "127.0.0.1");
        assert_eq!(config.postgres.port, 5432);
        assert_eq!(config.postgres.dbname, "clementine_tx_sender_test");
        assert_eq!(config.bitcoin_rpc.url, "http://127.0.0.1:18443");
        assert_eq!(config.finality_depth, 3);
        assert_eq!(config.poll_delay_ms, 1000);
        assert_eq!(config.input_unspent_max_retries, Some(9));
        assert!(config.include_unsafe);
        assert_eq!(
            config.mempool.host.as_deref(),
            Some("https://mempool.space")
        );
        assert_eq!(config.mempool.endpoint.as_deref(), Some("/api"));
    }

    #[test]
    fn from_env_errors_on_missing_required_var() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned");
        let _env_guard = EnvGuard::new();

        set_required_env();
        std::env::remove_var("DB_HOST");

        let err = TxSenderConfig::from_env().expect_err("missing DB_HOST should fail");
        assert!(matches!(err, BridgeError::EnvVarNotSet(_, "DB_HOST")));
    }

    #[test]
    fn from_env_errors_on_malformed_var() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned");
        let _env_guard = EnvGuard::new();

        set_required_env();
        std::env::set_var("TX_SENDER_INCLUDE_UNSAFE", "not-a-bool");

        let err = TxSenderConfig::from_env().expect_err("malformed bool should fail");
        assert!(matches!(
            err,
            BridgeError::EnvVarMalformed("TX_SENDER_INCLUDE_UNSAFE", _)
        ));
    }

    #[test]
    fn from_env_rejects_zero_poll_delay() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned");
        let _env_guard = EnvGuard::new();

        set_required_env();
        std::env::set_var("TX_SENDER_POLL_DELAY_MS", "0");

        let err = TxSenderConfig::from_env().expect_err("zero poll delay should fail");
        assert!(matches!(
            err,
            BridgeError::EnvVarMalformed("TX_SENDER_POLL_DELAY_MS", _)
        ));
    }

    #[test]
    fn from_env_rejects_zero_finality_depth() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned");
        let _env_guard = EnvGuard::new();

        set_required_env();
        std::env::set_var("TX_SENDER_FINALITY_DEPTH", "0");

        let err = TxSenderConfig::from_env().expect_err("zero finality depth should fail");
        assert!(matches!(
            err,
            BridgeError::EnvVarMalformed("TX_SENDER_FINALITY_DEPTH", _)
        ));
    }
}
