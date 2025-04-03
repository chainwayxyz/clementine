//! # Environment Variable Support For [`BridgeConfig`]

use super::{protocol::ProtocolParamset, BridgeConfig};
use crate::errors::BridgeError;
use bitcoin::{
    secp256k1::{PublicKey, SecretKey},
    Amount, Network, XOnlyPublicKey,
};
use std::{path::PathBuf, str::FromStr};

fn read_string_from_env(env_var: &'static str) -> Result<String, BridgeError> {
    std::env::var(env_var).map_err(|e| BridgeError::EnvVarNotSet(e, env_var))
}

fn read_string_from_env_then_parse<T: std::str::FromStr>(
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
        let verifiers_public_keys = read_string_from_env("VERIFIERS_PUBLIC_KEYS")?;
        let verifiers_public_keys = verifiers_public_keys.split(",").collect::<Vec<&str>>();
        let verifiers_public_keys = verifiers_public_keys
            .iter()
            .map(|x| PublicKey::from_str(x))
            .collect::<Result<Vec<PublicKey>, _>>()
            .map_err(|e| BridgeError::EnvVarMalformed("VERIFIERS_PUBLIC_KEYS", e.to_string()))?;

        let operators_xonly_pks = read_string_from_env("OPERATOR_XONLY_PKS")?;
        let operators_xonly_pks = operators_xonly_pks.split(",").collect::<Vec<&str>>();
        let operators_xonly_pks = operators_xonly_pks
            .iter()
            .map(|x| XOnlyPublicKey::from_str(x))
            .collect::<Result<Vec<XOnlyPublicKey>, _>>()
            .map_err(|e| BridgeError::EnvVarMalformed("OPERATOR_XONLY_PKS", e.to_string()))?;

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

        let config = BridgeConfig {
            protocol_paramset: read_string_from_env("PROTOCOL_PARAMSET")?.parse()?,
            host: read_string_from_env("HOST")?,
            port: read_string_from_env_then_parse::<u16>("PORT")?,
            index: read_string_from_env_then_parse::<u32>("INDEX")?,
            secret_key: read_string_from_env_then_parse::<SecretKey>("SECRET_KEY")?,
            winternitz_secret_key,
            verifiers_public_keys,
            num_verifiers: read_string_from_env_then_parse::<usize>("NUM_VERIFIERS")?,
            operators_xonly_pks,
            num_operators: read_string_from_env_then_parse::<usize>("NUM_OPERATORS")?,
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

            #[cfg(test)]
            test_params: super::TestParams::default(),
        };

        tracing::debug!("BridgeConfig from env: {:?}", config);
        Ok(config)
    }
}

impl ProtocolParamset {
    pub fn from_env() -> Result<Self, BridgeError> {
        let config = ProtocolParamset {
            network: read_string_from_env_then_parse::<Network>("NETWORK")?,
            num_round_txs: read_string_from_env_then_parse::<usize>("NUM_ROUND_TXS")?,
            num_kickoffs_per_round: read_string_from_env_then_parse::<usize>(
                "NUM_KICKOFFS_PER_ROUND",
            )?,
            num_signed_kickoffs: read_string_from_env_then_parse::<usize>("NUM_SIGNED_KICKOFFS")?,
            bridge_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "BRIDGE_AMOUNT",
            )?),
            kickoff_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "KICKOFF_AMOUNT",
            )?),
            operator_challenge_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "OPERATOR_CHALLENGE_AMOUNT",
            )?),
            collateral_funding_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "COLLATERAL_FUNDING_AMOUNT",
            )?),
            kickoff_blockhash_commit_length: read_string_from_env_then_parse::<u32>(
                "KICKOFF_BLOCKHASH_COMMIT_LENGTH",
            )?,
            watchtower_challenge_bytes: read_string_from_env_then_parse::<usize>(
                "WATCHTOWER_CHALLENGE_BYTES",
            )?,
            winternitz_log_d: read_string_from_env_then_parse::<u32>("WINTERNITZ_LOG_D")?,
            user_takes_after: read_string_from_env_then_parse::<u16>("USER_TAKES_AFTER")?,
            operator_challenge_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK",
            )?,
            operator_challenge_nack_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_CHALLENGE_NACK_TIMELOCK",
            )?,
            disprove_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "DISPROVE_TIMEOUT_TIMELOCK",
            )?,
            assert_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "ASSERT_TIMEOUT_TIMELOCK",
            )?,
            operator_reimburse_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_REIMBURSE_TIMELOCK",
            )?,
            watchtower_challenge_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK",
            )?,
            time_to_send_watchtower_challenge: read_string_from_env_then_parse::<u16>(
                "TIME_TO_SEND_WATCHTOWER_CHALLENGE",
            )?,
            time_to_disprove: read_string_from_env_then_parse::<u16>("TIME_TO_DISPROVE")?,
            finality_depth: read_string_from_env_then_parse::<u32>("FINALITY_DEPTH")?,
            start_height: read_string_from_env_then_parse::<u32>("START_HEIGHT")?,
            header_chain_proof_batch_size: read_string_from_env_then_parse::<u32>(
                "HEADER_CHAIN_PROOF_BATCH_SIZE",
            )?,
        };

        tracing::debug!("ProtocolParamset from env: {:?}", config);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{protocol::REGTEST_PARAMSET, BridgeConfig};

    #[test]
    #[ignore = "If other tests are run before, this test will fail"]
    fn fail_if_not_all_env_vars_are_set() {
        std::env::set_var("PROTOCOL_PARAMSET", "regtest");
        assert!(super::BridgeConfig::from_env().is_err());
    }

    #[test]
    fn get_config_from_env_vars() {
        let default_config = BridgeConfig::default();

        std::env::set_var(
            "PROTOCOL_PARAMSET",
            default_config.protocol_paramset.to_string(),
        );
        std::env::set_var("HOST", &default_config.host);
        std::env::set_var("PORT", default_config.port.to_string());
        std::env::set_var("INDEX", default_config.index.to_string());
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
        std::env::set_var(
            "VERIFIERS_PUBLIC_KEYS",
            default_config
                .verifiers_public_keys
                .iter()
                .map(|pk| pk.to_string())
                .collect::<Vec<String>>()
                .join(","),
        );
        std::env::set_var("NUM_VERIFIERS", default_config.num_verifiers.to_string());
        std::env::set_var(
            "OPERATOR_XONLY_PKS",
            default_config
                .operators_xonly_pks
                .iter()
                .map(|pk| pk.to_string())
                .collect::<Vec<String>>()
                .join(","),
        );
        std::env::set_var("NUM_OPERATORS", default_config.num_operators.to_string());
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
            "HEADER_CHAIN_PROOF_BATCH_SIZE",
            default_config.header_chain_proof_batch_size.to_string(),
        );

        assert_eq!(super::ProtocolParamset::from_env().unwrap(), default_config);
    }
}
