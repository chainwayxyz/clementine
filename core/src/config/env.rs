//! # Environment Variable Support For [`BridgeConfig`]

use super::BridgeConfig;
use crate::{builder::transaction::SecurityCouncil, errors::BridgeError};
use bitcoin::{secp256k1::SecretKey, Amount};
use std::{path::PathBuf, str::FromStr};

pub(crate) fn read_string_from_env(env_var: &'static str) -> Result<String, BridgeError> {
    std::env::var(env_var).map_err(|e| BridgeError::EnvVarNotSet(e, env_var))
}

pub(crate) fn read_string_from_env_then_parse<T: std::str::FromStr>(
    env_var: &'static str,
) -> Result<T, BridgeError>
where
    <T as FromStr>::Err: std::fmt::Debug,
{
    read_string_from_env(env_var)?
        .parse::<T>()
        .map_err(|e| BridgeError::EnvVarMalformed(env_var, format!("{:?}", e)))
}

impl BridgeConfig {
    pub fn from_env() -> Result<Self, BridgeError> {
        let verifier_endpoints =
            std::env::var("VERIFIER_ENDPOINTS")
                .ok()
                .map(|verifier_endpoints| {
                    verifier_endpoints
                        .split(",")
                        .collect::<Vec<&str>>()
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                });
        let operator_endpoints =
            std::env::var("OPERATOR_ENDPOINTS")
                .ok()
                .map(|operator_endpoints| {
                    operator_endpoints
                        .split(",")
                        .collect::<Vec<&str>>()
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                });

        let all_verifiers_secret_keys =
            if let Ok(all_verifiers_secret_keys) = std::env::var("ALL_VERIFIERS_SECRET_KEYS") {
                Some(
                    all_verifiers_secret_keys
                        .split(",")
                        .collect::<Vec<&str>>()
                        .iter()
                        .map(|x| SecretKey::from_str(x))
                        .collect::<Result<Vec<SecretKey>, _>>()
                        .map_err(|e| {
                            BridgeError::EnvVarMalformed("ALL_VERIFIERS_SECRET_KEYS", e.to_string())
                        })?,
                )
            } else {
                None
            };
        let all_operators_secret_keys =
            if let Ok(all_operators_secret_keys) = std::env::var("ALL_OPERATORS_SECRET_KEYS") {
                Some(
                    all_operators_secret_keys
                        .split(",")
                        .collect::<Vec<&str>>()
                        .iter()
                        .map(|x| SecretKey::from_str(x))
                        .collect::<Result<Vec<SecretKey>, _>>()
                        .map_err(|e| {
                            BridgeError::EnvVarMalformed("ALL_OPERATORS_SECRET_KEYS", e.to_string())
                        })?,
                )
            } else {
                None
            };

        let winternitz_secret_key = if let Ok(sk) = std::env::var("WINTERNITZ_SECRET_KEY") {
            Some(sk.parse::<SecretKey>().map_err(|e| {
                BridgeError::EnvVarMalformed("WINTERNITZ_SECRET_KEY", e.to_string())
            })?)
        } else {
            None
        };

        let operator_withdrawal_fee_sats = if let Ok(operator_withdrawal_fee_sats) =
            std::env::var("OPERATOR_WITHDRAWAL_FEE_SATS")
        {
            Some(Amount::from_sat(
                operator_withdrawal_fee_sats.parse::<u64>().map_err(|e| {
                    BridgeError::EnvVarMalformed("OPERATOR_WITHDRAWAL_FEE_SATS", e.to_string())
                })?,
            ))
        } else {
            None
        };

        let header_chain_proof_path =
            if let Ok(header_chain_proof_path) = std::env::var("HEADER_CHAIN_PROOF_PATH") {
                Some(PathBuf::from(header_chain_proof_path))
            } else {
                None
            };

        // TLS certificate and key paths
        let server_cert_path = std::env::var("SERVER_CERT_PATH").ok().map(PathBuf::from);
        let server_key_path = std::env::var("SERVER_KEY_PATH").ok().map(PathBuf::from);
        let ca_cert_path = std::env::var("CA_CERT_PATH").ok().map(PathBuf::from);
        let client_cert_path = std::env::var("CLIENT_CERT_PATH").ok().map(PathBuf::from);
        let client_key_path = std::env::var("CLIENT_KEY_PATH").ok().map(PathBuf::from);
        let aggregator_cert_path = std::env::var("AGGREGATOR_CERT_PATH")
            .ok()
            .map(PathBuf::from);

        let security_council_string = read_string_from_env("SECURITY_COUNCIL")?;

        let security_council = SecurityCouncil::from_str(&security_council_string)?;

        let config = BridgeConfig {
            // Protocol paramset's source is independently defined
            protocol_paramset: Default::default(),
            host: read_string_from_env("HOST")?,
            port: read_string_from_env_then_parse::<u16>("PORT")?,
            secret_key: read_string_from_env_then_parse::<SecretKey>("SECRET_KEY")?,
            winternitz_secret_key,
            operator_withdrawal_fee_sats,
            bitcoin_rpc_url: read_string_from_env("BITCOIN_RPC_URL")?,
            bitcoin_rpc_user: read_string_from_env("BITCOIN_RPC_USER")?,
            bitcoin_rpc_password: read_string_from_env("BITCOIN_RPC_PASSWORD")?,
            db_host: read_string_from_env("DB_HOST")?,
            db_port: read_string_from_env_then_parse::<usize>("DB_PORT")?,
            db_user: read_string_from_env("DB_USER")?,
            db_password: read_string_from_env("DB_PASSWORD")?,
            db_name: read_string_from_env("DB_NAME")?,
            citrea_rpc_url: read_string_from_env("CITREA_RPC_URL")?,
            citrea_light_client_prover_url: read_string_from_env("CITREA_LIGHT_CLIENT_PROVER_URL")?,
            bridge_contract_address: read_string_from_env("BRIDGE_CONTRACT_ADDRESS")?,
            header_chain_proof_path,
            verifier_endpoints,
            operator_endpoints,
            all_verifiers_secret_keys,
            all_operators_secret_keys,
            security_council,

            server_cert_path,
            server_key_path,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            aggregator_cert_path,

            #[cfg(test)]
            test_params: super::TestParams::default(),
        };

        tracing::debug!("BridgeConfig from env: {:?}", config);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{
        protocol::{ProtocolParamset, REGTEST_PARAMSET},
        BridgeConfig,
    };

    #[test]
    #[serial_test::serial]
    fn get_config_from_env_vars() {
        let default_config = BridgeConfig::default();

        std::env::set_var("HOST", &default_config.host);
        std::env::set_var("PORT", default_config.port.to_string());
        std::env::set_var(
            "SECRET_KEY",
            default_config.secret_key.display_secret().to_string(),
        );
        if let Some(ref winternitz_secret_key) = default_config.winternitz_secret_key {
            std::env::set_var(
                "WINTERNITZ_SECRET_KEY",
                winternitz_secret_key.display_secret().to_string(),
            );
        }
        if let Some(ref operator_withdrawal_fee_sats) = default_config.operator_withdrawal_fee_sats
        {
            std::env::set_var(
                "OPERATOR_WITHDRAWAL_FEE_SATS",
                operator_withdrawal_fee_sats.to_sat().to_string(),
            );
        }
        std::env::set_var("BITCOIN_RPC_URL", &default_config.bitcoin_rpc_url);
        std::env::set_var("BITCOIN_RPC_USER", &default_config.bitcoin_rpc_user);
        std::env::set_var("BITCOIN_RPC_PASSWORD", &default_config.bitcoin_rpc_password);
        std::env::set_var("DB_HOST", default_config.db_host.clone());
        std::env::set_var("DB_PORT", default_config.db_port.to_string());
        std::env::set_var("DB_USER", default_config.db_user.clone());
        std::env::set_var("DB_PASSWORD", &default_config.db_password);
        std::env::set_var("DB_NAME", &default_config.db_name);
        std::env::set_var("CITREA_RPC_URL", &default_config.citrea_rpc_url);
        std::env::set_var(
            "CITREA_LIGHT_CLIENT_PROVER_URL",
            &default_config.citrea_light_client_prover_url,
        );
        std::env::set_var(
            "BRIDGE_CONTRACT_ADDRESS",
            &default_config.bridge_contract_address,
        );
        std::env::set_var(
            "AGGREGATOR_CERT_PATH",
            default_config
                .aggregator_cert_path
                .clone()
                .unwrap_or_default(),
        );
        std::env::set_var(
            "CLIENT_CERT_PATH",
            default_config.client_cert_path.clone().unwrap_or_default(),
        );
        std::env::set_var(
            "CLIENT_KEY_PATH",
            default_config.client_key_path.clone().unwrap_or_default(),
        );
        std::env::set_var(
            "SERVER_CERT_PATH",
            default_config.server_cert_path.clone().unwrap_or_default(),
        );
        std::env::set_var(
            "SERVER_KEY_PATH",
            default_config.server_key_path.clone().unwrap_or_default(),
        );
        std::env::set_var(
            "CA_CERT_PATH",
            default_config.ca_cert_path.clone().unwrap_or_default(),
        );

        std::env::set_var(
            "SECURITY_COUNCIL",
            default_config.security_council.to_string(),
        );

        if let Some(ref header_chain_proof_path) = default_config.header_chain_proof_path {
            std::env::set_var("HEADER_CHAIN_PROOF_PATH", header_chain_proof_path);
        }
        if let Some(ref verifier_endpoints) = default_config.verifier_endpoints {
            std::env::set_var("VERIFIER_ENDPOINTS", verifier_endpoints.join(","));
        }
        if let Some(ref operator_endpoints) = default_config.operator_endpoints {
            std::env::set_var("OPERATOR_ENDPOINTS", operator_endpoints.join(","));
        }
        if let Some(ref all_verifiers_secret_keys) = default_config.all_verifiers_secret_keys {
            std::env::set_var(
                "ALL_VERIFIERS_SECRET_KEYS",
                all_verifiers_secret_keys
                    .iter()
                    .map(|sk| sk.display_secret().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            );
        }
        if let Some(ref all_operators_secret_keys) = default_config.all_operators_secret_keys {
            std::env::set_var(
                "ALL_OPERATORS_SECRET_KEYS",
                all_operators_secret_keys
                    .iter()
                    .map(|sk| sk.display_secret().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            );
        }

        assert_eq!(super::BridgeConfig::from_env().unwrap(), default_config);
    }

    #[test]
    #[serial_test::serial]
    fn get_protocol_paramset_from_env_vars() {
        let default_config = REGTEST_PARAMSET;

        std::env::set_var("NETWORK", default_config.network.to_string());
        std::env::set_var("NUM_ROUND_TXS", default_config.num_round_txs.to_string());
        std::env::set_var(
            "NUM_KICKOFFS_PER_ROUND",
            default_config.num_kickoffs_per_round.to_string(),
        );
        std::env::set_var(
            "NUM_SIGNED_KICKOFFS",
            default_config.num_signed_kickoffs.to_string(),
        );
        std::env::set_var(
            "BRIDGE_AMOUNT",
            default_config.bridge_amount.to_sat().to_string(),
        );
        std::env::set_var(
            "KICKOFF_AMOUNT",
            default_config.kickoff_amount.to_sat().to_string(),
        );
        std::env::set_var(
            "OPERATOR_CHALLENGE_AMOUNT",
            default_config
                .operator_challenge_amount
                .to_sat()
                .to_string(),
        );
        std::env::set_var(
            "COLLATERAL_FUNDING_AMOUNT",
            default_config
                .collateral_funding_amount
                .to_sat()
                .to_string(),
        );
        std::env::set_var(
            "KICKOFF_BLOCKHASH_COMMIT_LENGTH",
            default_config.kickoff_blockhash_commit_length.to_string(),
        );
        std::env::set_var(
            "WATCHTOWER_CHALLENGE_BYTES",
            default_config.watchtower_challenge_bytes.to_string(),
        );
        std::env::set_var(
            "WINTERNITZ_LOG_D",
            default_config.winternitz_log_d.to_string(),
        );
        std::env::set_var(
            "USER_TAKES_AFTER",
            default_config.user_takes_after.to_string(),
        );
        std::env::set_var(
            "OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK",
            default_config
                .operator_challenge_timeout_timelock
                .to_string(),
        );
        std::env::set_var(
            "OPERATOR_CHALLENGE_NACK_TIMELOCK",
            default_config.operator_challenge_nack_timelock.to_string(),
        );
        std::env::set_var(
            "DISPROVE_TIMEOUT_TIMELOCK",
            default_config.disprove_timeout_timelock.to_string(),
        );
        std::env::set_var(
            "ASSERT_TIMEOUT_TIMELOCK",
            default_config.assert_timeout_timelock.to_string(),
        );
        std::env::set_var(
            "OPERATOR_REIMBURSE_TIMELOCK",
            default_config.operator_reimburse_timelock.to_string(),
        );
        std::env::set_var(
            "WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK",
            default_config
                .watchtower_challenge_timeout_timelock
                .to_string(),
        );
        std::env::set_var(
            "TIME_TO_SEND_WATCHTOWER_CHALLENGE",
            default_config.time_to_send_watchtower_challenge.to_string(),
        );
        std::env::set_var(
            "TIME_TO_DISPROVE",
            default_config.time_to_disprove.to_string(),
        );
        std::env::set_var("FINALITY_DEPTH", default_config.finality_depth.to_string());
        std::env::set_var("START_HEIGHT", default_config.start_height.to_string());
        std::env::set_var(
            "LATEST_BLOCKHASH_TIMEOUT_TIMELOCK",
            default_config.latest_blockhash_timeout_timelock.to_string(),
        );
        std::env::set_var(
            "HEADER_CHAIN_PROOF_BATCH_SIZE",
            default_config.header_chain_proof_batch_size.to_string(),
        );

        assert_eq!(ProtocolParamset::from_env().unwrap(), default_config);
    }
}
