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
