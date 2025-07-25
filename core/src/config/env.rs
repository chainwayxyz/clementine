//! # Environment Variable Support For [`BridgeConfig`]

use super::BridgeConfig;
use crate::{config::GrpcLimits, deposit::SecurityCouncil, errors::BridgeError};
use bitcoin::{address::NetworkUnchecked, secp256k1::SecretKey, Amount};
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

impl GrpcLimits {
    pub fn from_env() -> Result<Self, BridgeError> {
        Ok(GrpcLimits {
            max_message_size: read_string_from_env_then_parse::<usize>("GRPC_MAX_MESSAGE_SIZE")?,
            timeout_secs: read_string_from_env_then_parse::<u64>("GRPC_TIMEOUT_SECS")?,
            tpc_keepalive_secs: read_string_from_env_then_parse::<u64>("GRPC_KEEPALIVE_SECS")?,
            req_concurrency_limit: read_string_from_env_then_parse::<usize>(
                "GRPC_CONCURRENCY_LIMIT",
            )?,
        })
    }
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

        let operator_reimbursement_address = if let Ok(operator_reimbursement_address) =
            std::env::var("OPERATOR_REIMBURSEMENT_ADDRESS")
        {
            Some(
                operator_reimbursement_address
                    .parse::<bitcoin::Address<NetworkUnchecked>>()
                    .map_err(|e| {
                        BridgeError::EnvVarMalformed(
                            "OPERATOR_REIMBURSEMENT_ADDRESS",
                            e.to_string(),
                        )
                    })?,
            )
        } else {
            None
        };

        let operator_collateral_funding_outpoint = if let Ok(operator_collateral_funding_outpoint) =
            std::env::var("OPERATOR_COLLATERAL_FUNDING_OUTPOINT")
        {
            Some(
                operator_collateral_funding_outpoint
                    .parse::<bitcoin::OutPoint>()
                    .map_err(|e| {
                        BridgeError::EnvVarMalformed(
                            "OPERATOR_COLLATERAL_FUNDING_OUTPOINT",
                            e.to_string(),
                        )
                    })?,
            )
        } else {
            None
        };

        // TLS certificate and key paths
        let server_cert_path = read_string_from_env("SERVER_CERT_PATH").map(PathBuf::from)?;
        let server_key_path = read_string_from_env("SERVER_KEY_PATH").map(PathBuf::from)?;
        let client_cert_path = read_string_from_env("CLIENT_CERT_PATH").map(PathBuf::from)?;
        let ca_cert_path = read_string_from_env("CA_CERT_PATH").map(PathBuf::from)?;
        let client_key_path = read_string_from_env("CLIENT_KEY_PATH").map(PathBuf::from)?;
        let aggregator_cert_path =
            read_string_from_env("AGGREGATOR_CERT_PATH").map(PathBuf::from)?;
        let client_verification =
            read_string_from_env("CLIENT_VERIFICATION").is_ok_and(|s| s == "true" || s == "1");

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
            operator_reimbursement_address,
            operator_collateral_funding_outpoint,
            bitcoin_rpc_url: read_string_from_env("BITCOIN_RPC_URL")?,
            bitcoin_rpc_user: read_string_from_env("BITCOIN_RPC_USER")?.into(),
            bitcoin_rpc_password: read_string_from_env("BITCOIN_RPC_PASSWORD")?.into(),
            db_host: read_string_from_env("DB_HOST")?,
            db_port: read_string_from_env_then_parse::<usize>("DB_PORT")?,
            db_user: read_string_from_env("DB_USER")?.into(),
            db_password: read_string_from_env("DB_PASSWORD")?.into(),
            db_name: read_string_from_env("DB_NAME")?,
            citrea_rpc_url: read_string_from_env("CITREA_RPC_URL")?,
            citrea_light_client_prover_url: read_string_from_env("CITREA_LIGHT_CLIENT_PROVER_URL")?,
            citrea_chain_id: read_string_from_env_then_parse::<u32>("CITREA_CHAIN_ID")?,
            bridge_contract_address: read_string_from_env("BRIDGE_CONTRACT_ADDRESS")?,
            header_chain_proof_path,
            verifier_endpoints,
            operator_endpoints,
            security_council,

            client_verification,
            server_cert_path,
            server_key_path,
            ca_cert_path,
            client_cert_path,
            client_key_path,
            aggregator_cert_path,

            grpc: GrpcLimits::from_env()?,

            #[cfg(test)]
            test_params: super::TestParams::default(),
        };

        tracing::debug!("BridgeConfig from env: {:?}", config);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

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
        std::env::set_var(
            "BITCOIN_RPC_USER",
            &default_config.bitcoin_rpc_user.expose_secret(),
        );
        std::env::set_var(
            "BITCOIN_RPC_PASSWORD",
            &default_config.bitcoin_rpc_password.expose_secret(),
        );
        std::env::set_var("DB_HOST", default_config.db_host.clone());
        std::env::set_var("DB_PORT", default_config.db_port.to_string());
        std::env::set_var("DB_USER", &default_config.db_user.expose_secret());
        std::env::set_var("DB_PASSWORD", &default_config.db_password.expose_secret());
        std::env::set_var("DB_NAME", &default_config.db_name);
        std::env::set_var("CITREA_RPC_URL", &default_config.citrea_rpc_url);
        std::env::set_var(
            "CITREA_LIGHT_CLIENT_PROVER_URL",
            &default_config.citrea_light_client_prover_url,
        );
        std::env::set_var(
            "CITREA_CHAIN_ID",
            default_config.citrea_chain_id.to_string(),
        );
        std::env::set_var(
            "BRIDGE_CONTRACT_ADDRESS",
            &default_config.bridge_contract_address,
        );
        std::env::set_var(
            "AGGREGATOR_CERT_PATH",
            default_config.aggregator_cert_path.clone(),
        );
        std::env::set_var("CLIENT_CERT_PATH", default_config.client_cert_path.clone());
        std::env::set_var("CLIENT_KEY_PATH", default_config.client_key_path.clone());
        std::env::set_var("SERVER_CERT_PATH", default_config.server_cert_path.clone());
        std::env::set_var("SERVER_KEY_PATH", default_config.server_key_path.clone());
        std::env::set_var("CA_CERT_PATH", default_config.ca_cert_path.clone());
        std::env::set_var(
            "CLIENT_VERIFICATION",
            default_config.client_verification.to_string(),
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

        if let Some(ref operator_reimbursement_address) =
            default_config.operator_reimbursement_address
        {
            std::env::set_var(
                "OPERATOR_REIMBURSEMENT_ADDRESS",
                operator_reimbursement_address
                    .to_owned()
                    .assume_checked()
                    .to_string(),
            );
        }

        if let Some(ref operator_collateral_funding_outpoint) =
            default_config.operator_collateral_funding_outpoint
        {
            std::env::set_var(
                "OPERATOR_COLLATERAL_FUNDING_OUTPOINT",
                operator_collateral_funding_outpoint.to_string(),
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
        std::env::set_var("GENESIS_HEIGHT", default_config.genesis_height.to_string());
        std::env::set_var(
            "GENESIS_CHAIN_STATE_HASH",
            hex::encode(default_config.genesis_chain_state_hash),
        );
        std::env::set_var(
            "LATEST_BLOCKHASH_TIMEOUT_TIMELOCK",
            default_config.latest_blockhash_timeout_timelock.to_string(),
        );
        std::env::set_var(
            "HEADER_CHAIN_PROOF_BATCH_SIZE",
            default_config.header_chain_proof_batch_size.to_string(),
        );

        std::env::set_var(
            "BRIDGE_CIRCUIT_METHOD_ID_CONSTANT",
            hex::encode(default_config.bridge_circuit_method_id_constant),
        );
        std::env::set_var(
            "BRIDGE_NONSTANDARD",
            default_config.bridge_nonstandard.to_string(),
        );

        assert_eq!(ProtocolParamset::from_env().unwrap(), default_config);
    }
}
