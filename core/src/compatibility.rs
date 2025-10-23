//! # Compatibility Module
//! This module contains the logic for checking compatibility between actors in the system.

use eyre::Context;
use semver::VersionReq;

use crate::aggregator::Aggregator;
use crate::bitvm_client::{load_or_generate_bitvm_cache, BITVM_CACHE};
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::deposit::SecurityCouncil;
use crate::errors::BridgeError;
use crate::operator::Operator;
use crate::rpc::clementine::CompatibilityParamsRpc;
use crate::verifier::Verifier;

/// Parameters related to protocol configuration that can affect contract transactions, Citrea syncing, and version compatibility. This must not include sensitive information.
#[derive(Clone, Debug)]
pub struct CompatibilityParams {
    pub protocol_paramset: ProtocolParamset,
    pub security_council: SecurityCouncil,
    pub citrea_chain_id: u32,
    pub clementine_version: String,
    pub bridge_circuit_constant: [u8; 32],
    pub sha256_bitvm_cache: [u8; 32],
}

impl CompatibilityParams {
    /// Returns an error with reason if not compatible, otherwise returns Ok(())
    /// For Protocol paramset, security council and citrea chain ID, we only check if they are different.
    /// For Clementine version, we allow different patch versions, but not different major or minor versions.
    pub fn is_compatible(&self, other: &CompatibilityParams) -> Result<(), BridgeError> {
        let mut reasons = Vec::new();
        if self.protocol_paramset != other.protocol_paramset {
            reasons.push(format!(
                "Protocol paramset mismatch: self={:?}, other={:?}",
                self.protocol_paramset, other.protocol_paramset
            ));
        }
        if self.security_council != other.security_council {
            reasons.push(format!(
                "Security council mismatch: self={:?}, other={:?}",
                self.security_council, other.security_council
            ));
        }
        if self.citrea_chain_id != other.citrea_chain_id {
            reasons.push(format!(
                "Citrea chain ID mismatch: self={}, other={}",
                self.citrea_chain_id, other.citrea_chain_id
            ));
        }
        if self.bridge_circuit_constant != other.bridge_circuit_constant {
            reasons.push(format!(
                "Bridge circuit constant mismatch: self={:?}, other={:?}",
                self.bridge_circuit_constant, other.bridge_circuit_constant
            ));
        }
        if self.sha256_bitvm_cache != other.sha256_bitvm_cache {
            reasons.push(format!(
                "BitVM cache SHA256 mismatch: self={:?}, other={:?}",
                self.sha256_bitvm_cache, other.sha256_bitvm_cache
            ));
        }
        let own_version = semver::Version::parse(&self.clementine_version).wrap_err(format!(
            "Failed to parse own Clementine version {}",
            self.clementine_version
        ))?;
        let other_version = semver::Version::parse(&other.clementine_version).wrap_err(format!(
            "Failed to parse other Clementine version {}",
            other.clementine_version
        ))?;
        let min_version = std::cmp::min(&own_version, &other_version);
        let max_version = std::cmp::max(&own_version, &other_version);
        let version_req =
            VersionReq::parse(&format!("^{min_version}")).wrap_err(format!(
                "Failed to parse version requirement for Clementine version mismatch: self={own_version:?}, other={other_version:?}",
            ))?;
        if !version_req.matches(max_version) {
            reasons.push(format!(
                "Clementine version mismatch: self={own_version:?}, other={other_version:?}",
            ));
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(BridgeError::ClementineNotCompatible(reasons.join(", ")))
        }
    }
}

impl TryFrom<CompatibilityParams> for CompatibilityParamsRpc {
    type Error = eyre::Report;

    fn try_from(params: CompatibilityParams) -> Result<Self, Self::Error> {
        Ok(CompatibilityParamsRpc {
            protocol_paramset: serde_json::to_string(&params.protocol_paramset)
                .wrap_err("Failed to serialize protocol paramset")?,
            security_council: params.security_council.to_string(),
            citrea_chain_id: params.citrea_chain_id,
            clementine_version: params.clementine_version,
            bridge_circuit_constant: params.bridge_circuit_constant.to_vec(),
            sha256_bitvm_cache: params.sha256_bitvm_cache.to_vec(),
        })
    }
}

impl TryFrom<CompatibilityParamsRpc> for CompatibilityParams {
    type Error = eyre::Report;

    fn try_from(params: CompatibilityParamsRpc) -> Result<Self, Self::Error> {
        Ok(CompatibilityParams {
            protocol_paramset: serde_json::from_str(&params.protocol_paramset)
                .wrap_err("Failed to deserialize protocol paramset")?,
            security_council: params
                .security_council
                .parse()
                .wrap_err("Failed to deserialize security council")?,
            citrea_chain_id: params.citrea_chain_id,
            clementine_version: params.clementine_version,
            bridge_circuit_constant: params.bridge_circuit_constant.try_into().map_err(|_| {
                eyre::eyre!("Failed to convert bridge circuit constant to [u8; 32]")
            })?,
            sha256_bitvm_cache: params
                .sha256_bitvm_cache
                .try_into()
                .map_err(|_| eyre::eyre!("Failed to convert sha256 bitvm cache to [u8; 32]"))?,
        })
    }
}

pub trait ActorWithConfig {
    fn get_config(&self) -> &BridgeConfig;

    fn get_compatibility_params(&self) -> Result<CompatibilityParams, BridgeError> {
        let config = self.get_config();
        Ok(CompatibilityParams {
            protocol_paramset: config.protocol_paramset.clone(),
            security_council: config.security_council.clone(),
            citrea_chain_id: config.citrea_chain_id,
            clementine_version: env!("CARGO_PKG_VERSION").to_string(),
            bridge_circuit_constant: *config.protocol_paramset.bridge_circuit_constant()?,
            sha256_bitvm_cache: BITVM_CACHE
                .get_or_try_init(load_or_generate_bitvm_cache)?
                .sha256_bitvm_cache,
        })
    }

    /// Returns an error with reason if not compatible, otherwise returns Ok(())
    fn is_compatible(&self, others: Vec<(String, CompatibilityParams)>) -> Result<(), BridgeError> {
        let own_params = self.get_compatibility_params()?;
        let mut reasons = Vec::new();
        for (id, params) in others {
            if let Err(e) = own_params.is_compatible(&params) {
                reasons.push(format!("{id}: {e}"));
            }
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(BridgeError::ClementineNotCompatible(reasons.join(", ")))
        }
    }
}

impl<C> ActorWithConfig for Operator<C>
where
    C: CitreaClientT,
{
    fn get_config(&self) -> &BridgeConfig {
        &self.config
    }
}

impl<C> ActorWithConfig for Verifier<C>
where
    C: CitreaClientT,
{
    fn get_config(&self) -> &BridgeConfig {
        &self.config
    }
}

impl ActorWithConfig for Aggregator {
    fn get_config(&self) -> &BridgeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::protocol::{REGTEST_PARAMSET, TESTNET4_TEST_PARAMSET},
        rpc::clementine::{entity_data_with_id::DataResult, Empty},
        test::common::{
            citrea::MockCitreaClient, create_actors, create_regtest_rpc,
            create_test_config_with_thread_name,
        },
    };
    use bitcoin::XOnlyPublicKey;
    use std::str::FromStr;

    #[allow(dead_code)]
    struct MockActorWithConfig {
        config: BridgeConfig,
    }

    impl ActorWithConfig for MockActorWithConfig {
        fn get_config(&self) -> &BridgeConfig {
            &self.config
        }
    }

    #[test]
    fn test_mock_actor_get_compatibility_params() {
        let config = BridgeConfig::default();
        let actor = MockActorWithConfig { config };

        let params = actor.get_compatibility_params().unwrap();

        assert_eq!(
            params.protocol_paramset,
            actor.config.protocol_paramset.clone()
        );
        assert_eq!(params.security_council, actor.config.security_council);
        assert_eq!(params.citrea_chain_id, actor.config.citrea_chain_id);
        assert_eq!(
            params.bridge_circuit_constant,
            *actor
                .config
                .protocol_paramset
                .bridge_circuit_constant()
                .unwrap()
        );
        assert_eq!(
            params.sha256_bitvm_cache,
            BITVM_CACHE
                .get_or_try_init(load_or_generate_bitvm_cache)
                .unwrap()
                .sha256_bitvm_cache
        );
        assert_eq!(
            params.clementine_version,
            env!("CARGO_PKG_VERSION").to_string()
        );
    }

    #[test]
    fn test_mock_actor_is_compatible_success() {
        let config = BridgeConfig::default();
        let actor = MockActorWithConfig { config };

        let own = actor.get_compatibility_params().unwrap();
        let others = vec![
            ("aggregator".to_string(), own.clone()),
            ("verifier".to_string(), own),
        ];
        assert!(actor.is_compatible(others).is_ok());
    }

    #[test]
    fn test_mock_actor_is_compatible_failure() {
        let config = BridgeConfig::default();
        let actor = MockActorWithConfig { config };

        let mut other = actor.get_compatibility_params().unwrap();
        // introduce mismatches
        other.citrea_chain_id += 1;
        other.security_council = create_test_security_council_different();

        let result = actor.is_compatible(vec![("verifier-1".to_string(), other)]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("verifier-1:"));
        assert!(msg.contains("Citrea chain ID mismatch"));
        assert!(msg.contains("Security council mismatch"));
    }

    // serial test because it calculates sha256 of the bitvm cache for all actors
    #[tokio::test]
    async fn test_get_compatibility_data_from_entities() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;
        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();
        // load cache here to calculate sha256 of the bitvm cache for all actors before get_compatibility call to avoid timeout in debug mode
        BITVM_CACHE
            .get_or_try_init(load_or_generate_bitvm_cache)
            .unwrap();
        let entity_comp_data = aggregator
            .get_compatibility_data_from_entities(Empty {})
            .await
            .unwrap()
            .into_inner();

        tracing::info!("Entity compatibility data: {:?}", entity_comp_data);

        let mut errors = Vec::new();
        for entity in entity_comp_data.entities_compatibility_data {
            let data = entity.data_result.unwrap();
            match data {
                DataResult::Data(_) => {}
                DataResult::Error(err) => {
                    errors.push(format!(
                        "Entity {:?} returned an error: {:?}",
                        entity.entity_id.unwrap(),
                        err
                    ));
                }
            }
        }
        if !errors.is_empty() {
            panic!("Errors: {}", errors.join(", "));
        }
    }

    fn create_test_protocol_paramset() -> ProtocolParamset {
        REGTEST_PARAMSET
    }

    fn create_test_protocol_paramset_different() -> ProtocolParamset {
        TESTNET4_TEST_PARAMSET
    }

    fn create_test_security_council() -> SecurityCouncil {
        SecurityCouncil {
            pks: vec![
                XOnlyPublicKey::from_str(
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap(),
            ],
            threshold: 1,
        }
    }

    fn create_test_security_council_different() -> SecurityCouncil {
        SecurityCouncil {
            pks: vec![
                XOnlyPublicKey::from_str(
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap(),
            ],
            threshold: 2,
        }
    }

    fn create_test_compatibility_params(version: &str) -> CompatibilityParams {
        let protocol_paramset = create_test_protocol_paramset();
        CompatibilityParams {
            bridge_circuit_constant: *protocol_paramset.bridge_circuit_constant().unwrap(),
            sha256_bitvm_cache: [0u8; 32],
            protocol_paramset,
            security_council: create_test_security_council(),
            citrea_chain_id: 1234,
            clementine_version: version.to_string(),
        }
    }

    #[test]
    fn test_compatible_identical_params() {
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("1.2.3");

        assert!(params1.is_compatible(&params2).is_ok());
    }

    #[test]
    fn test_compatible_different_patch_versions() {
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("1.2.5");

        assert!(params1.is_compatible(&params2).is_ok());
    }

    #[test]
    fn test_incompatible_different_security_council() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("1.2.3");
        params2.security_council = create_test_security_council_different();

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Security council mismatch"));
    }

    #[test]
    fn test_incompatible_different_citrea_chain_id() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("1.2.3");
        params2.citrea_chain_id = 5678;

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Citrea chain ID mismatch"));
    }

    #[test]
    fn test_incompatible_different_protocol_paramset() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("1.2.3");
        // Change a field in the protocol paramset
        params2.protocol_paramset = create_test_protocol_paramset_different();

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Protocol paramset mismatch"));
    }

    #[test]
    fn test_incompatible_different_bridge_circuit_constant() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("1.2.3");
        params2.bridge_circuit_constant = [1u8; 32];

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Bridge circuit constant mismatch"));
    }

    #[test]
    fn test_incompatible_different_sha256_bitvm_cache() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("1.2.3");
        params2.sha256_bitvm_cache = [2u8; 32];

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("BitVM cache SHA256 mismatch"));
    }

    #[test]
    fn test_incompatible_multiple_reasons() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("2.0.0");
        params2.citrea_chain_id = 5678;
        params2.security_council = create_test_security_council_different();

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Security council mismatch"));
        assert!(err_msg.contains("Citrea chain ID mismatch"));
        assert!(err_msg.contains("Clementine version mismatch"));
    }

    #[test]
    fn test_invalid_version_format_self() {
        let params1 = create_test_compatibility_params("invalid-version");
        let params2 = create_test_compatibility_params("1.2.3");

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version_format_other() {
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("not-a-version");

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_with_build_metadata() {
        let params1 = create_test_compatibility_params("1.2.3+build123");
        let params2 = create_test_compatibility_params("1.2.5+build456");

        // Build metadata should be ignored, and patch versions can differ
        assert!(params1.is_compatible(&params2).is_ok());
    }

    #[test]
    fn test_compatibility_params_to_rpc_conversion() {
        let params = create_test_compatibility_params("1.2.3");

        let rpc_params: CompatibilityParamsRpc = params.clone().try_into().unwrap();

        assert_eq!(rpc_params.citrea_chain_id, 1234);
        assert_eq!(rpc_params.clementine_version, params.clementine_version);
        assert!(!rpc_params.protocol_paramset.is_empty());
        assert!(!rpc_params.security_council.is_empty());
        assert_eq!(
            rpc_params.bridge_circuit_constant,
            params.bridge_circuit_constant.to_vec()
        );
        assert_eq!(
            rpc_params.sha256_bitvm_cache,
            params.sha256_bitvm_cache.to_vec()
        );
    }

    #[test]
    fn test_compatibility_params_rpc_parsing() {
        let params = create_test_compatibility_params("1.2.3");

        let rpc_params: CompatibilityParamsRpc = params.clone().try_into().unwrap();
        let params_back: CompatibilityParams = rpc_params.try_into().unwrap();

        assert_eq!(params.protocol_paramset, params_back.protocol_paramset);
        assert_eq!(params.security_council, params_back.security_council);
        assert_eq!(params.citrea_chain_id, params_back.citrea_chain_id);
        assert_eq!(
            params.bridge_circuit_constant,
            params_back.bridge_circuit_constant
        );
        assert_eq!(params.sha256_bitvm_cache, params_back.sha256_bitvm_cache);
        assert_eq!(params.clementine_version, params_back.clementine_version);
    }

    #[test]
    fn test_security_council_string_parsing() {
        let council = create_test_security_council();
        let council_str = council.to_string();
        let council_back: SecurityCouncil = council_str.parse().unwrap();

        assert_eq!(council, council_back);
    }

    #[test]
    fn test_security_council_multiple_keys() {
        let council = SecurityCouncil {
            pks: vec![
                XOnlyPublicKey::from_str(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                )
                .unwrap(),
                XOnlyPublicKey::from_str(
                    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                )
                .unwrap(),
            ],
            threshold: 2,
        };

        let council_str = council.to_string();
        let council_back: SecurityCouncil = council_str.parse().unwrap();

        assert_eq!(council, council_back);
        assert_eq!(council_back.threshold, 2);
        assert_eq!(council_back.pks.len(), 3);
    }

    #[test]
    fn test_actor_with_config_compatibility_success() {
        // Create two sets of compatible params
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("1.2.5");
        let params3 = create_test_compatibility_params("1.3.7");
        let params4 = create_test_compatibility_params("2.0.1");

        // Test the is_compatible method on the params
        let result = params1.is_compatible(&params2);
        assert!(result.is_ok());
        let result = params1.is_compatible(&params3);
        assert!(result.is_ok());
        let result = params1.is_compatible(&params4);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Clementine version mismatch"));

        let params5 = create_test_compatibility_params("0.6.8");
        let params6 = create_test_compatibility_params("0.6.7");
        let params7 = create_test_compatibility_params("0.7.0");

        let result = params5.is_compatible(&params6);
        assert!(result.is_ok());
        let result = params5.is_compatible(&params7);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Clementine version mismatch"));
    }

    #[test]
    fn test_actor_with_config_compatibility_failure() {
        let params1 = create_test_compatibility_params("1.2.3");
        let mut params2 = create_test_compatibility_params("2.0.0");
        params2.citrea_chain_id = 9999;

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Citrea chain ID mismatch"));
        assert!(err_msg.contains("Clementine version mismatch"));
    }
}
