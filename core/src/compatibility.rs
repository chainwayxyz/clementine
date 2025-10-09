//! # Compatibility Module
//! This module contains the logic for checking compatibility between actors in the system.

use eyre::Context;

use crate::aggregator::Aggregator;
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::deposit::SecurityCouncil;
use crate::errors::BridgeError;
use crate::operator::Operator;
use crate::rpc::clementine::CompatibilityParamsRpc;
use crate::verifier::Verifier;

// Everthing related to protocol params that can affect the transactions in the contract, syncing with citrea and version number
// for checking compatibility. This must not include any sensitive information.
#[derive(Clone, Debug)]
pub struct CompatibilityParams {
    pub protocol_paramset: ProtocolParamset,
    pub security_council: SecurityCouncil,
    pub citrea_chain_id: u32,
    pub clementine_version: String,
}

impl CompatibilityParams {
    // Returns an error with reason if not compatible, otherwise returns Ok(())
    // For Protocol paramset, security council and citrea chain ID, we only check if they are different.
    // For Clementine version, we allow different patch versions, but not different major or minor versions.
    pub fn is_compatible(&self, other: &CompatibilityParams) -> Result<(), BridgeError> {
        let mut reasons = Vec::new();
        if self.protocol_paramset != other.protocol_paramset {
            reasons.push("Protocol paramset mismatch");
        }
        if self.security_council != other.security_council {
            reasons.push("Security council mismatch");
        }
        if self.citrea_chain_id != other.citrea_chain_id {
            reasons.push("Citrea chain ID mismatch");
        }
        let own_version = semver::Version::parse(&self.clementine_version)
            .wrap_err("Failed to parse own Clementine version {self.clementine_version}")?;
        let other_version = semver::Version::parse(&other.clementine_version)
            .wrap_err("Failed to parse other Clementine version {other.clementine_version}")?;
        // allow different patch versions, but not different major or minor versions
        if own_version.major != other_version.major || own_version.minor != other_version.minor {
            reasons.push("Clementine version mismatch");
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
            clementine_version: env!("CARGO_PKG_VERSION").to_string(),
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
        })
    }
}

pub trait ActorWithConfig {
    fn get_config(&self) -> &BridgeConfig;

    fn get_compatibility_params(&self) -> CompatibilityParams {
        let config = self.get_config();
        CompatibilityParams {
            protocol_paramset: config.protocol_paramset.clone(),
            security_council: config.security_council.clone(),
            citrea_chain_id: config.citrea_chain_id,
            clementine_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Returns an error with reason if not compatible, otherwise returns Ok(())
    fn is_compatible(&self, others: Vec<(String, CompatibilityParams)>) -> Result<(), BridgeError> {
        let own_params = self.get_compatibility_params();
        let mut reasons = Vec::new();
        for (id, params) in others {
            if let Err(e) = own_params.is_compatible(&params) {
                reasons.push(format!("{}: {}", id, e));
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
    use crate::config::protocol::{REGTEST_PARAMSET, TESTNET4_TEST_PARAMSET};
    use bitcoin::XOnlyPublicKey;
    use std::str::FromStr;

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
        CompatibilityParams {
            protocol_paramset: create_test_protocol_paramset(),
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
    fn test_incompatible_different_major_versions() {
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("2.2.3");

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Clementine version mismatch"));
    }

    #[test]
    fn test_incompatible_different_minor_versions() {
        let params1 = create_test_compatibility_params("1.2.3");
        let params2 = create_test_compatibility_params("1.3.3");

        let result = params1.is_compatible(&params2);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Clementine version mismatch"));
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
    fn test_version_with_prerelease() {
        let params1 = create_test_compatibility_params("1.2.3-alpha");
        let params2 = create_test_compatibility_params("1.2.4-beta");

        // Prerelease versions should still be compatible if major.minor match
        assert!(params1.is_compatible(&params2).is_ok());
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
        assert_eq!(rpc_params.clementine_version, env!("CARGO_PKG_VERSION"));
        assert!(!rpc_params.protocol_paramset.is_empty());
        assert!(!rpc_params.security_council.is_empty());
    }

    #[test]
    fn test_compatibility_params_rpc_roundtrip() {
        let params = create_test_compatibility_params("1.2.3");

        let rpc_params: CompatibilityParamsRpc = params.clone().try_into().unwrap();
        let params_back: CompatibilityParams = rpc_params.try_into().unwrap();

        assert_eq!(params.protocol_paramset, params_back.protocol_paramset);
        assert_eq!(params.security_council, params_back.security_council);
        assert_eq!(params.citrea_chain_id, params_back.citrea_chain_id);
        // Note: clementine_version will be different due to env!("CARGO_PKG_VERSION") in TryFrom
    }

    #[test]
    fn test_security_council_string_roundtrip() {
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
        let params3 = create_test_compatibility_params("1.2.7");

        let others = vec![
            ("actor1".to_string(), params2),
            ("actor2".to_string(), params3),
        ];

        // Test the is_compatible method on the params
        let result = params1.is_compatible(&others[0].1);
        assert!(result.is_ok());
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
