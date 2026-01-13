//! TxSender standalone configuration.

use crate::MempoolConfig;
use bitcoin::Network;
use clementine_config::tx_sender::TxSenderLimits;
use clementine_errors::BridgeError;
use secrecy::SecretString;
use std::str::FromStr;

const DEFAULT_FINALITY_DEPTH: u32 = 5;

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

/// Configuration for running the tx-sender service standalone.
#[derive(Clone, Debug)]
pub struct TxSenderConfig {
    pub network: Network,
    pub postgres: TxSenderPostgresConfig,
    pub bitcoin_rpc: TxSenderBitcoinRpcConfig,
    pub mempool: MempoolConfig,
    pub limits: TxSenderLimits,
    /// How many confirmations are required before tx-sender treats an observation as final.
    ///
    /// The chain tip has 1 confirmation. Minimum value should be 1.
    pub finality_depth: u32,
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
        };

        let finality_depth = env_parse_optional::<u32>("TX_SENDER_FINALITY_DEPTH")?
            .unwrap_or(DEFAULT_FINALITY_DEPTH);

        if finality_depth < 1 {
            return Err(BridgeError::EnvVarMalformed(
                "TX_SENDER_FINALITY_DEPTH",
                "finality depth must be >= 1".to_string(),
            ));
        }

        Ok(Self {
            network,
            postgres,
            bitcoin_rpc,
            mempool,
            limits,
            finality_depth,
        })
    }
}
