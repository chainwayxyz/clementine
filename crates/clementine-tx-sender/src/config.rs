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
            include_unsafe,
            jsonrpc,
        })
    }
}
