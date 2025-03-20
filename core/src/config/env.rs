//! # Environment Variable Support For [`BridgeConfig`]

use super::BridgeConfig;
use crate::errors::BridgeError;
use bitcoin::{
    secp256k1::{PublicKey, SecretKey},
    Amount, XOnlyPublicKey,
};
use std::{path::PathBuf, str::FromStr};

impl BridgeConfig {
    pub fn from_env() -> Result<Self, BridgeError> {
        let verifiers_public_keys = std::env::var("VERIFIERS_PUBLIC_KEYS")
            .map_err(|e| BridgeError::EnvVarNotSet(e, "VERIFIERS_PUBLIC_KEYS"))?;
        let verifiers_public_keys = verifiers_public_keys.split(",").collect::<Vec<&str>>();
        let verifiers_public_keys = verifiers_public_keys
            .iter()
            .map(|x| PublicKey::from_str(x))
            .collect::<Result<Vec<PublicKey>, _>>()
            .map_err(|e| BridgeError::EnvVarMalformed("VERIFIERS_PUBLIC_KEYS", e.to_string()))?;

        let operators_xonly_pks = std::env::var("OPERATOR_XONLY_PKS")
            .map_err(|e| BridgeError::EnvVarNotSet(e, "OPERATOR_XONLY_PKS"))?;
        let operators_xonly_pks = operators_xonly_pks.split(",").collect::<Vec<&str>>();
        let operators_xonly_pks = operators_xonly_pks
            .iter()
            .map(|x| XOnlyPublicKey::from_str(x))
            .collect::<Result<Vec<XOnlyPublicKey>, _>>()
            .map_err(|e| BridgeError::EnvVarMalformed("OPERATOR_XONLY_PKS", e.to_string()))?;

        let verifier_endpoints = if let Ok(verifier_endpoints) = std::env::var("VERIFIER_ENDPOINTS")
        {
            Some(
                verifier_endpoints
                    .split(",")
                    .collect::<Vec<&str>>()
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>(),
            )
        } else {
            None
        };
        let operator_endpoints = if let Ok(operator_endpoints) = std::env::var("OPERATOR_ENDPOINTS")
        {
            Some(
                operator_endpoints
                    .split(",")
                    .collect::<Vec<&str>>()
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>(),
            )
        } else {
            None
        };
        let watchtower_endpoints =
            if let Ok(watchtower_endpoints) = std::env::var("WATCHTOWER_ENDPOINTS") {
                Some(
                    watchtower_endpoints
                        .split(",")
                        .collect::<Vec<&str>>()
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>(),
                )
            } else {
                None
            };

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
        let all_watchtowers_secret_keys = if let Ok(all_watchtowers_secret_keys) =
            std::env::var("ALL_WATCHTOWERS_SECRET_KEYS")
        {
            Some(
                all_watchtowers_secret_keys
                    .split(",")
                    .collect::<Vec<&str>>()
                    .iter()
                    .map(|x| SecretKey::from_str(x))
                    .collect::<Result<Vec<SecretKey>, _>>()
                    .map_err(|e| {
                        BridgeError::EnvVarMalformed("ALL_WATCHTOWERS_SECRET_KEYS", e.to_string())
                    })?,
            )
        } else {
            None
        };

        let winternitz_secret_key = if let Ok(sk) = std::env::var("WINTERNITZ_SECRET_KEY") {
            let wsk = sk.parse::<SecretKey>().map_err(|e| {
                BridgeError::EnvVarMalformed("WINTERNITZ_SECRET_KEY", e.to_string())
            })?;

            Some(wsk)
        } else {
            None
        };

        let operator_withdrawal_fee_sats = if let Ok(operator_withdrawal_fee_sats) =
            std::env::var("OPERATOR_WITHDRAWAL_FEE_SATS")
        {
            let operator_withdrawal_fee_sats = operator_withdrawal_fee_sats
                .parse::<Amount>()
                .map_err(|e| {
                    BridgeError::EnvVarMalformed("OPERATOR_WITHDRAWAL_FEE_SATS", e.to_string())
                })?;

            Some(operator_withdrawal_fee_sats)
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
            protocol_paramset: std::env::var("PROTOCOL_PARAMSET")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "PROTOCOL_PARAMSET"))?
                .parse()?,
            host: std::env::var("HOST").map_err(|e| BridgeError::EnvVarNotSet(e, "HOST"))?,
            port: std::env::var("PORT")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "PORT"))?
                .parse::<u16>()
                .map_err(|e| BridgeError::EnvVarMalformed("PORT", e.to_string()))?,
            index: std::env::var("INDEX")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "INDEX"))?
                .parse::<u32>()
                .map_err(|e| BridgeError::EnvVarMalformed("INDEX", e.to_string()))?,
            secret_key: std::env::var("SECRET_KEY")
                .map_err(|e| BridgeError::EnvVarMalformed("SECRET_KEY", e.to_string()))?
                .parse::<SecretKey>()
                .map_err(|e| {
                    BridgeError::EnvVarMalformed("ALL_WATCHTOWERS_SECRET_KEYS", e.to_string())
                })?,
            winternitz_secret_key,
            verifiers_public_keys,
            num_verifiers: std::env::var("NUM_VERIFIERS")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "NUM_VERIFIERS"))?
                .parse::<usize>()
                .map_err(|e| BridgeError::EnvVarMalformed("NUM_VERIFIERS", e.to_string()))?,
            operators_xonly_pks,
            num_operators: std::env::var("NUM_OPERATORS")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "NUM_OPERATORS"))?
                .parse::<usize>()
                .map_err(|e| BridgeError::EnvVarMalformed("NUM_OPERATORS", e.to_string()))?,
            operator_withdrawal_fee_sats,
            bitcoin_rpc_url: std::env::var("BITCOIN_RPC_URL")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "BITCOIN_RPC_URL"))?,
            bitcoin_rpc_user: std::env::var("BITCOIN_RPC_USER")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "BITCOIN_RPC_USER"))?,
            bitcoin_rpc_password: std::env::var("BITCOIN_RPC_PASSWORD")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "BITCOIN_RPC_PASSWORD"))?,
            db_host: std::env::var("DB_HOST")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "DB_HOST"))?,
            db_port: std::env::var("DB_PORT")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "DB_PORT"))?
                .parse::<usize>()
                .map_err(|e| BridgeError::EnvVarMalformed("DB_PORT", e.to_string()))?,
            db_user: std::env::var("DB_USER")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "DB_USER"))?,
            db_password: std::env::var("DB_PASSWORD")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "DB_PASSWORD"))?,
            db_name: std::env::var("DB_NAME")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "DB_NAME"))?,
            citrea_rpc_url: std::env::var("CITREA_RPC_URL")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "CITREA_RPC_URL"))?,
            citrea_light_client_prover_url: std::env::var("CITREA_LIGHT_CLIENT_PROVER_URL")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "CITREA_LIGHT_CLIENT_PROVER_URL"))?,
            bridge_contract_address: std::env::var("BRIDGE_CONTRACT_ADDRESS")
                .map_err(|e| BridgeError::EnvVarNotSet(e, "BRIDGE_CONTRACT_ADDRESS"))?,
            header_chain_proof_path,
            trusted_watchtower_endpoint: std::env::var("TRUSTED_WATCHTOWER_ENDPOINT").ok(),
            verifier_endpoints,
            operator_endpoints,
            watchtower_endpoints,
            all_verifiers_secret_keys,
            all_operators_secret_keys,
            all_watchtowers_secret_keys,

            #[cfg(test)]
            test_params: super::TestParams::default(),
        };

        tracing::debug!("BridgeConfig from env: {:?}", config);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::BridgeConfig;

    #[test]
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
                operator_withdrawal_fee_sats.to_string(),
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
        if let Some(ref trusted_watchtower_endpoint) = default_config.trusted_watchtower_endpoint {
            std::env::set_var("TRUSTED_WATCHTOWER_ENDPOINT", trusted_watchtower_endpoint);
        }
        if let Some(ref verifier_endpoints) = default_config.verifier_endpoints {
            std::env::set_var("VERIFIER_ENDPOINTS", verifier_endpoints.join(","));
        }
        if let Some(ref operator_endpoints) = default_config.operator_endpoints {
            std::env::set_var("OPERATOR_ENDPOINTS", operator_endpoints.join(","));
        }
        if let Some(ref watchtower_endpoints) = default_config.watchtower_endpoints {
            std::env::set_var("WATCHTOWER_ENDPOINTS", watchtower_endpoints.join(","));
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
        if let Some(ref all_watchtowers_secret_keys) = default_config.all_watchtowers_secret_keys {
            std::env::set_var(
                "ALL_WATCHTOWERS_SECRET_KEYS",
                all_watchtowers_secret_keys
                    .iter()
                    .map(|sk| sk.display_secret().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            );
        }

        assert_eq!(super::BridgeConfig::from_env().unwrap(), default_config);
    }
}
